use crate::authorized_keys::apply_managed_block_to_file;
use crate::config::AppConfig;
use crate::discovery::{DiscoveryEngine, DiscoveryEvent};
use crate::ssh_keys::read_local_public_key;
use crate::transport::{HttpKeyExchangeService, PATH_GET_PUBLIC_KEY, PATH_PUBLISH_PARTICIPANT};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TIMESTAMP_SKEW_SECS: u64 = 60;
const NONCE_TTL_SECS: u64 = 120;
const LOOP_SLEEP_MILLIS: u64 = 200;
const IO_TIMEOUT_SECS: u64 = 3;
const STOP_WAIT_MILLIS: u64 = 3_000;
const STOP_POLL_MILLIS: u64 = 50;

#[derive(Debug)]
pub enum RuntimeError {
    ReadLocalPublicKey(String),
    BindHttp(String),
    BindUdp(String),
    ParseListenAddress(String),
    BuildAnnouncement,
    ParseEnvelope,
    HttpRequest,
    VerifyOrParseResponse,
    WriteAuthorizedKeys(String),
    ControlFile(String),
    KillProcess(u32),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::ReadLocalPublicKey(path) => {
                write!(f, "Failed to read local public key from {path}")
            }
            RuntimeError::BindHttp(addr) => write!(f, "Failed to bind HTTP listener at {addr}"),
            RuntimeError::BindUdp(addr) => write!(f, "Failed to bind UDP socket at {addr}"),
            RuntimeError::ParseListenAddress(addr) => write!(f, "Invalid listen address: {addr}"),
            RuntimeError::BuildAnnouncement => write!(f, "Failed to build startup announcement"),
            RuntimeError::ParseEnvelope => write!(f, "Failed to parse signed envelope"),
            RuntimeError::HttpRequest => write!(f, "Failed to perform HTTP key request"),
            RuntimeError::VerifyOrParseResponse => write!(f, "Failed to verify or parse response"),
            RuntimeError::WriteAuthorizedKeys(path) => {
                write!(f, "Failed to write authorized_keys at {path}")
            }
            RuntimeError::ControlFile(path) => write!(f, "Failed to access control file at {path}"),
            RuntimeError::KillProcess(pid) => {
                write!(f, "Failed to terminate process with pid {pid}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Debug, Clone)]
struct PeerEndpoint {
    participant_id: String,
    address: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStatus {
    Running { pid: u32 },
    Stopped,
    StalePidFile { pid: u32 },
}

pub fn run_daemon(config: &AppConfig) -> Result<(), RuntimeError> {
    let public_key_path = expand_home_path(&config.public_key_path);
    let authorized_keys_path = expand_home_path(&config.authorized_keys_path);
    let local_public_key = read_local_public_key(&public_key_path)
        .map_err(|_| RuntimeError::ReadLocalPublicKey(public_key_path.clone()))?;
    let service = HttpKeyExchangeService::new(
        config.sid.clone(),
        config.sid_token.clone(),
        config.participant_id.clone(),
        local_public_key.clone(),
    )
    .map_err(|_| RuntimeError::ReadLocalPublicKey(public_key_path.clone()))?;

    let http_listener = TcpListener::bind(&config.http_listen_addr)
        .map_err(|_| RuntimeError::BindHttp(config.http_listen_addr.clone()))?;
    http_listener
        .set_nonblocking(true)
        .map_err(|_| RuntimeError::BindHttp(config.http_listen_addr.clone()))?;

    let udp_socket = UdpSocket::bind(&config.udp_announce_addr)
        .map_err(|_| RuntimeError::BindUdp(config.udp_announce_addr.clone()))?;
    udp_socket
        .set_nonblocking(true)
        .map_err(|_| RuntimeError::BindUdp(config.udp_announce_addr.clone()))?;
    udp_socket
        .set_broadcast(true)
        .map_err(|_| RuntimeError::BindUdp(config.udp_announce_addr.clone()))?;

    let http_port = parse_port(&config.http_listen_addr)?;
    let udp_port = parse_port(&config.udp_announce_addr)?;
    let advertised_address = advertised_address(&config.http_listen_addr, &config.participant_id);

    let mut discovery = DiscoveryEngine::new(
        config.sid.clone(),
        config.sid_token.clone(),
        TIMESTAMP_SKEW_SECS,
        NONCE_TTL_SECS,
    );
    discovery.add_bootstrap_peers(&config.bootstrap_peers);

    let mut managed_keys: HashMap<String, String> = HashMap::new();
    let mut next_sync_at = now_secs();
    let pid_path = pid_file_path(&config.sid);
    let stop_path = stop_file_path(&config.sid);

    if Path::new(&stop_path).exists() {
        fs::remove_file(&stop_path).map_err(|_| RuntimeError::ControlFile(stop_path.clone()))?;
    }
    fs::write(&pid_path, std::process::id().to_string())
        .map_err(|_| RuntimeError::ControlFile(pid_path.clone()))?;

    println!(
        "Daemon is running. HTTP: {}, UDP: {}, participant: {}",
        config.http_listen_addr, config.udp_announce_addr, config.participant_id
    );

    send_announcement(
        &udp_socket,
        &discovery,
        &config.participant_id,
        &advertised_address,
        http_port,
        &local_public_key,
        udp_port,
    )?;

    loop {
        handle_http_connections(&http_listener, &service);
        handle_udp_announcements(&udp_socket, &mut discovery);

        let now = now_secs();
        let sync_due = now >= next_sync_at;
        let discovery_trigger = discovery.take_sync_trigger();
        if sync_due || discovery_trigger {
            if run_sync_cycle(config, &service, &discovery, &mut managed_keys).is_ok() {
                if !config.dry_run {
                    let keys: Vec<String> = managed_keys.values().cloned().collect();
                    apply_managed_block_to_file(&authorized_keys_path, &keys).map_err(|_| {
                        RuntimeError::WriteAuthorizedKeys(authorized_keys_path.clone())
                    })?;
                }
                println!("Sync completed: {} remote key(s)", managed_keys.len());
            }
            send_announcement(
                &udp_socket,
                &discovery,
                &config.participant_id,
                &advertised_address,
                http_port,
                &local_public_key,
                udp_port,
            )?;
            next_sync_at = now + config.sync_interval_secs.max(1);
        }

        if Path::new(&stop_path).exists() {
            println!("Stop requested, shutting down daemon");
            break;
        }
        thread::sleep(Duration::from_millis(LOOP_SLEEP_MILLIS));
    }

    if Path::new(&pid_path).exists() {
        let _ = fs::remove_file(&pid_path);
    }
    if Path::new(&stop_path).exists() {
        let _ = fs::remove_file(&stop_path);
    }
    Ok(())
}

pub fn run_single_sync(config: &AppConfig) -> Result<(), RuntimeError> {
    let public_key_path = expand_home_path(&config.public_key_path);
    let authorized_keys_path = expand_home_path(&config.authorized_keys_path);
    let local_public_key = read_local_public_key(&public_key_path)
        .map_err(|_| RuntimeError::ReadLocalPublicKey(public_key_path.clone()))?;
    let service = HttpKeyExchangeService::new(
        config.sid.clone(),
        config.sid_token.clone(),
        config.participant_id.clone(),
        local_public_key,
    )
    .map_err(|_| RuntimeError::ReadLocalPublicKey(public_key_path.clone()))?;
    let mut discovery = DiscoveryEngine::new(
        config.sid.clone(),
        config.sid_token.clone(),
        TIMESTAMP_SKEW_SECS,
        NONCE_TTL_SECS,
    );
    discovery.add_bootstrap_peers(&config.bootstrap_peers);
    let mut managed_keys: HashMap<String, String> = HashMap::new();

    run_sync_cycle(config, &service, &discovery, &mut managed_keys)?;
    if !config.dry_run {
        let keys: Vec<String> = managed_keys.values().cloned().collect();
        apply_managed_block_to_file(&authorized_keys_path, &keys)
            .map_err(|_| RuntimeError::WriteAuthorizedKeys(authorized_keys_path.clone()))?;
    }

    println!("Sync completed: {} remote key(s)", managed_keys.len());
    Ok(())
}

pub fn stop_daemon(sid: &str) -> Result<bool, RuntimeError> {
    match status_daemon(sid) {
        DaemonStatus::Running { pid } => {
            let path = stop_file_path(sid);
            fs::write(&path, "stop").map_err(|_| RuntimeError::ControlFile(path.clone()))?;

            let mut waited = 0_u64;
            while process_exists(pid) && waited < STOP_WAIT_MILLIS {
                thread::sleep(Duration::from_millis(STOP_POLL_MILLIS));
                waited += STOP_POLL_MILLIS;
            }

            if process_exists(pid) {
                let status = Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .status()
                    .map_err(|_| RuntimeError::KillProcess(pid))?;
                if !status.success() {
                    return Err(RuntimeError::KillProcess(pid));
                }
            }
            Ok(true)
        }
        DaemonStatus::StalePidFile { .. } => {
            let pid_path = pid_file_path(sid);
            if Path::new(&pid_path).exists() {
                fs::remove_file(&pid_path).map_err(|_| RuntimeError::ControlFile(pid_path))?;
            }
            let stop_path = stop_file_path(sid);
            if Path::new(&stop_path).exists() {
                fs::remove_file(&stop_path).map_err(|_| RuntimeError::ControlFile(stop_path))?;
            }
            Ok(false)
        }
        DaemonStatus::Stopped => Ok(false),
    }
}

pub fn status_daemon(sid: &str) -> DaemonStatus {
    let pid_path = pid_file_path(sid);
    let path = Path::new(&pid_path);
    if !path.exists() {
        return DaemonStatus::Stopped;
    }
    let content = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return DaemonStatus::Stopped,
    };
    let pid = match content.trim().parse::<u32>() {
        Ok(value) => value,
        Err(_) => return DaemonStatus::Stopped,
    };
    if process_exists(pid) {
        DaemonStatus::Running { pid }
    } else {
        DaemonStatus::StalePidFile { pid }
    }
}

fn run_sync_cycle(
    config: &AppConfig,
    service: &HttpKeyExchangeService,
    discovery: &DiscoveryEngine,
    managed_keys: &mut HashMap<String, String>,
) -> Result<(), RuntimeError> {
    let mut endpoints: HashMap<String, PeerEndpoint> = HashMap::new();
    for peer in &config.bootstrap_peers {
        if let Some(endpoint) = parse_bootstrap_peer(peer) {
            endpoints.insert(endpoint.participant_id.clone(), endpoint);
        }
    }
    for peer in discovery.peers().values() {
        endpoints.insert(
            peer.participant_id.clone(),
            PeerEndpoint {
                participant_id: peer.participant_id.clone(),
                address: peer.address.clone(),
                port: peer.port,
            },
        );
    }

    for endpoint in endpoints.values() {
        if endpoint.participant_id == config.participant_id {
            continue;
        }
        if let Ok(key) = request_public_key(service, endpoint) {
            managed_keys.insert(endpoint.participant_id.clone(), key);
        }
    }

    Ok(())
}

fn request_public_key(
    service: &HttpKeyExchangeService,
    endpoint: &PeerEndpoint,
) -> Result<String, RuntimeError> {
    let request_envelope =
        service.build_get_public_key_request(&endpoint.participant_id, now_secs(), &next_nonce());
    let request_body = serialize_envelope(&request_envelope);
    let response_body = send_http_post(
        &endpoint.address,
        endpoint.port,
        PATH_GET_PUBLIC_KEY,
        &request_body,
    )
    .map_err(|_| RuntimeError::HttpRequest)?;
    let response_envelope =
        parse_envelope(&response_body).map_err(|_| RuntimeError::ParseEnvelope)?;
    let payload = service
        .verify_and_parse_public_key_response(&response_envelope)
        .map_err(|_| RuntimeError::VerifyOrParseResponse)?;
    Ok(payload.public_key)
}

fn handle_http_connections(listener: &TcpListener, service: &HttpKeyExchangeService) {
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)));
                let _ = handle_http_connection(&mut stream, service);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn handle_http_connection(
    stream: &mut TcpStream,
    service: &HttpKeyExchangeService,
) -> Result<(), std::io::Error> {
    let (path, body) = read_http_request(stream)?;
    let envelope = match parse_envelope(&body) {
        Ok(value) => value,
        Err(_) => {
            write_http_response(stream, 400, b"invalid envelope")?;
            return Ok(());
        }
    };

    let response = if path == PATH_GET_PUBLIC_KEY {
        service.handle_get_public_key_request(&envelope, now_secs(), &next_nonce())
    } else if path == PATH_PUBLISH_PARTICIPANT {
        service.handle_publish_request(&envelope, now_secs(), &next_nonce())
    } else {
        write_http_response(stream, 404, b"not found")?;
        return Ok(());
    };

    match response {
        Ok(envelope) => {
            let body = serialize_envelope(&envelope);
            write_http_response(stream, 200, body.as_bytes())?;
        }
        Err(_) => {
            write_http_response(stream, 401, b"verification failed")?;
        }
    }

    Ok(())
}

fn handle_udp_announcements(socket: &UdpSocket, discovery: &mut DiscoveryEngine) {
    let mut buffer = [0_u8; 8192];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, _)) => {
                if let Ok(text) = std::str::from_utf8(&buffer[..size])
                    && let Ok(envelope) = parse_envelope(text)
                    && let Ok(event) = discovery.process_announcement(&envelope, now_secs())
                {
                    match event {
                        DiscoveryEvent::PeerAdded(participant) => {
                            println!("Discovered new peer: {participant}");
                        }
                        DiscoveryEvent::PeerUpdated(participant) => {
                            println!("Updated peer record: {participant}");
                        }
                        DiscoveryEvent::Ignored => {}
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn send_announcement(
    udp_socket: &UdpSocket,
    discovery: &DiscoveryEngine,
    participant_id: &str,
    address: &str,
    port: u16,
    public_key: &str,
    udp_port: u16,
) -> Result<(), RuntimeError> {
    let envelope = discovery
        .build_startup_announcement(
            participant_id,
            address,
            port,
            public_key,
            now_secs(),
            &next_nonce(),
        )
        .map_err(|_| RuntimeError::BuildAnnouncement)?;
    let payload = serialize_envelope(&envelope);
    let target = format!("255.255.255.255:{udp_port}");
    let _ = udp_socket.send_to(payload.as_bytes(), target);
    Ok(())
}

fn parse_bootstrap_peer(value: &str) -> Option<PeerEndpoint> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (participant_id, host_port) =
        if let Some((participant, host_port)) = trimmed.split_once('@') {
            (participant.trim().to_owned(), host_port.trim())
        } else {
            (trimmed.to_owned(), trimmed)
        };
    let (address, port_text) = host_port.rsplit_once(':')?;
    let port = port_text.trim().parse::<u16>().ok()?;

    Some(PeerEndpoint {
        participant_id,
        address: address.trim().to_owned(),
        port,
    })
}

fn read_http_request(stream: &mut TcpStream) -> Result<(String, String), std::io::Error> {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end;
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        data.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_subslice(&data, b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
        if data.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
    }

    let headers = String::from_utf8_lossy(&data[..header_end]);
    let mut lines = headers.lines();
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request line")
    })?;
    let mut request_parts = request_line.split_whitespace();
    let _method = request_parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing method"))?;
    let path = request_parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing path"))?
        .to_owned();

    let mut content_length = 0_usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("Content-Length")
            && let Ok(parsed) = value.trim().parse::<usize>()
        {
            content_length = parsed;
        }
    }

    while data.len() < header_end + content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..read]);
    }

    if data.len() < header_end + content_length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "short body",
        ));
    }
    let body = String::from_utf8_lossy(&data[header_end..header_end + content_length]).to_string();
    Ok((path, body))
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    body: &[u8],
) -> Result<(), std::io::Error> {
    let reason = match status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn send_http_post(
    address: &str,
    port: u16,
    path: &str,
    body: &str,
) -> Result<String, std::io::Error> {
    let socket = resolve_socket_addr(address, port)?;
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(IO_TIMEOUT_SECS))?;
    stream.set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))?;
    stream.set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}:{port}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let header_end = find_subslice(&response, b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid response"))?
        + 4;
    let body = String::from_utf8_lossy(&response[header_end..]).to_string();
    Ok(body)
}

fn resolve_socket_addr(address: &str, port: u16) -> Result<SocketAddr, std::io::Error> {
    (address, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address"))
}

fn serialize_envelope(envelope: &crate::auth::SignedEnvelope) -> String {
    let mut out = String::new();
    out.push_str("sid=");
    out.push_str(&envelope.sid);
    out.push('\n');
    out.push_str("sender_id=");
    out.push_str(&envelope.sender_id);
    out.push('\n');
    out.push_str("timestamp_secs=");
    out.push_str(&envelope.timestamp_secs.to_string());
    out.push('\n');
    out.push_str("nonce=");
    out.push_str(&envelope.nonce);
    out.push('\n');
    out.push_str("signature_hex=");
    out.push_str(&envelope.signature_hex);
    out.push('\n');
    match &envelope.context {
        crate::auth::MessageContext::HttpRequest { method, path } => {
            out.push_str("context=http_request\n");
            out.push_str("method=");
            out.push_str(method);
            out.push('\n');
            out.push_str("path=");
            out.push_str(path);
            out.push('\n');
        }
        crate::auth::MessageContext::HttpResponse { status_code, path } => {
            out.push_str("context=http_response\n");
            out.push_str("status_code=");
            out.push_str(&status_code.to_string());
            out.push('\n');
            out.push_str("path=");
            out.push_str(path);
            out.push('\n');
        }
        crate::auth::MessageContext::UdpAnnouncement => {
            out.push_str("context=udp_announcement\n");
        }
    }
    out.push_str("body_hex=");
    out.push_str(&to_hex(&envelope.body));
    out.push('\n');
    out
}

fn parse_envelope(text: &str) -> Result<crate::auth::SignedEnvelope, RuntimeError> {
    let mut values = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    let sid = values.remove("sid").ok_or(RuntimeError::ParseEnvelope)?;
    let sender_id = values
        .remove("sender_id")
        .ok_or(RuntimeError::ParseEnvelope)?;
    let timestamp_secs = values
        .remove("timestamp_secs")
        .ok_or(RuntimeError::ParseEnvelope)?
        .parse::<u64>()
        .map_err(|_| RuntimeError::ParseEnvelope)?;
    let nonce = values.remove("nonce").ok_or(RuntimeError::ParseEnvelope)?;
    let signature_hex = values
        .remove("signature_hex")
        .ok_or(RuntimeError::ParseEnvelope)?;
    let context_kind = values
        .remove("context")
        .ok_or(RuntimeError::ParseEnvelope)?;
    let context = match context_kind.as_str() {
        "http_request" => crate::auth::MessageContext::HttpRequest {
            method: values.remove("method").ok_or(RuntimeError::ParseEnvelope)?,
            path: values.remove("path").ok_or(RuntimeError::ParseEnvelope)?,
        },
        "http_response" => crate::auth::MessageContext::HttpResponse {
            status_code: values
                .remove("status_code")
                .ok_or(RuntimeError::ParseEnvelope)?
                .parse::<u16>()
                .map_err(|_| RuntimeError::ParseEnvelope)?,
            path: values.remove("path").ok_or(RuntimeError::ParseEnvelope)?,
        },
        "udp_announcement" => crate::auth::MessageContext::UdpAnnouncement,
        _ => return Err(RuntimeError::ParseEnvelope),
    };
    let body_hex = values
        .remove("body_hex")
        .ok_or(RuntimeError::ParseEnvelope)?;
    let body = from_hex(&body_hex).ok_or(RuntimeError::ParseEnvelope)?;

    Ok(crate::auth::SignedEnvelope {
        sid,
        sender_id,
        timestamp_secs,
        nonce,
        context,
        body,
        signature_hex,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_port(address: &str) -> Result<u16, RuntimeError> {
    address
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .ok_or_else(|| RuntimeError::ParseListenAddress(address.to_owned()))
}

fn advertised_address(http_listen_addr: &str, participant_id: &str) -> String {
    let host = http_listen_addr
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(http_listen_addr);
    if host == "0.0.0.0" || host == "::" {
        participant_id.to_owned()
    } else {
        host.to_owned()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn next_nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    format!("n-{nanos}")
}

fn expand_home_path(path: &str) -> String {
    if path == "~" {
        return std::env::var("HOME").unwrap_or_else(|_| path.to_owned());
    }
    if let Some(stripped) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{stripped}");
    }
    path.to_owned()
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn from_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let high = decode_nibble(bytes[idx])?;
        let low = decode_nibble(bytes[idx + 1])?;
        output.push((high << 4) | low);
        idx += 2;
    }
    Some(output)
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn pid_file_path(sid: &str) -> String {
    format!("/tmp/ssh-key-sync-{}.pid", sanitize_for_file(sid))
}

fn stop_file_path(sid: &str) -> String {
    format!("/tmp/ssh-key-sync-{}.stop", sanitize_for_file(sid))
}

fn sanitize_for_file(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}
