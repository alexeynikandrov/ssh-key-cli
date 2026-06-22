use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::fs;
use std::path::Path;

const DEFAULT_HTTP_LISTEN_ADDR: &str = "0.0.0.0:9922";
const DEFAULT_UDP_ANNOUNCE_ADDR: &str = "0.0.0.0:9923";
const DEFAULT_SYNC_INTERVAL_SECS: u64 = 30;
const DEFAULT_PUBLIC_KEY_PATH: &str = "~/.ssh/id_ed25519.pub";
const DEFAULT_AUTHORIZED_KEYS_PATH: &str = "~/.ssh/authorized_keys";

#[derive(Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub sid: String,
    pub sid_token: String,
    pub participant_id: String,
    pub http_listen_addr: String,
    pub udp_announce_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub sync_interval_secs: u64,
    pub public_key_path: String,
    pub authorized_keys_path: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_ca_path: Option<String>,
    pub tls_server_name: Option<String>,
    pub insecure_no_tls: bool,
    pub dry_run: bool,
}

impl Debug for AppConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("sid", &self.sid)
            .field("sid_token", &"***")
            .field("participant_id", &self.participant_id)
            .field("http_listen_addr", &self.http_listen_addr)
            .field("udp_announce_addr", &self.udp_announce_addr)
            .field("bootstrap_peers", &self.bootstrap_peers)
            .field("sync_interval_secs", &self.sync_interval_secs)
            .field("public_key_path", &self.public_key_path)
            .field("authorized_keys_path", &self.authorized_keys_path)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .field("tls_ca_path", &self.tls_ca_path)
            .field("tls_server_name", &self.tls_server_name)
            .field("insecure_no_tls", &self.insecure_no_tls)
            .field("dry_run", &self.dry_run)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigMode {
    RequireSyncConfig,
    AllowMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigInput<'a> {
    pub sid: Option<&'a str>,
    pub sid_token: Option<&'a str>,
    pub participant_id: Option<&'a str>,
    pub http_listen_addr: Option<&'a str>,
    pub udp_announce_addr: Option<&'a str>,
    pub bootstrap_peers: Option<&'a str>,
    pub sync_interval_secs: Option<u64>,
    pub public_key_path: Option<&'a str>,
    pub authorized_keys_path: Option<&'a str>,
    pub tls_cert_path: Option<&'a str>,
    pub tls_key_path: Option<&'a str>,
    pub tls_ca_path: Option<&'a str>,
    pub tls_server_name: Option<&'a str>,
    pub insecure_no_tls: bool,
    pub dry_run: bool,
    pub config_path: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    MissingSid,
    MissingSidToken,
    InvalidSid,
    InvalidSidToken,
    InvalidSyncInterval,
    ConfigFileReadFailed(String),
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingSid => write!(f, "Missing SID: set --sid or SSH_KEY_SYNC_SID"),
            ConfigError::MissingSidToken => {
                write!(
                    f,
                    "Missing SID_TOKEN: set --sid-token or SSH_KEY_SYNC_SID_TOKEN"
                )
            }
            ConfigError::InvalidSid => write!(f, "SID must not be empty"),
            ConfigError::InvalidSidToken => write!(f, "SID_TOKEN must not be empty"),
            ConfigError::InvalidSyncInterval => {
                write!(f, "sync-interval-secs must be greater than 0")
            }
            ConfigError::ConfigFileReadFailed(path) => {
                write!(f, "Cannot read config file: {path}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn load_config(
    input: &ConfigInput<'_>,
    mode: ConfigMode,
) -> Result<Option<AppConfig>, ConfigError> {
    load_config_with_sources(input, mode, &collect_env())
}

fn load_config_with_sources(
    input: &ConfigInput<'_>,
    mode: ConfigMode,
    env_data: &HashMap<String, String>,
) -> Result<Option<AppConfig>, ConfigError> {
    let file_data = read_config_file(input.config_path)?;

    let sid = resolve_string(input.sid, "SSH_KEY_SYNC_SID", env_data, &file_data, "SID");
    let sid_token = resolve_string(
        input.sid_token,
        "SSH_KEY_SYNC_SID_TOKEN",
        env_data,
        &file_data,
        "SID_TOKEN",
    );

    if mode == ConfigMode::AllowMissing && sid.is_none() && sid_token.is_none() {
        return Ok(None);
    }

    let sid =
        normalize_non_empty(sid.ok_or(ConfigError::MissingSid)?).ok_or(ConfigError::InvalidSid)?;
    let sid_token = normalize_non_empty(sid_token.ok_or(ConfigError::MissingSidToken)?)
        .ok_or(ConfigError::InvalidSidToken)?;

    let sync_interval_secs = resolve_u64(
        input.sync_interval_secs,
        "SSH_KEY_SYNC_SYNC_INTERVAL_SECS",
        env_data,
        &file_data,
        "SYNC_INTERVAL_SECS",
    )
    .unwrap_or(DEFAULT_SYNC_INTERVAL_SECS);
    if sync_interval_secs == 0 {
        return Err(ConfigError::InvalidSyncInterval);
    }

    let participant_id = resolve_string(
        input.participant_id,
        "SSH_KEY_SYNC_PARTICIPANT_ID",
        env_data,
        &file_data,
        "PARTICIPANT_ID",
    )
    .or_else(|| env_data.get("HOSTNAME").cloned())
    .unwrap_or_else(|| "unknown-participant".to_owned());
    let http_listen_addr = resolve_string(
        input.http_listen_addr,
        "SSH_KEY_SYNC_HTTP_LISTEN_ADDR",
        env_data,
        &file_data,
        "HTTP_LISTEN_ADDR",
    )
    .unwrap_or_else(|| DEFAULT_HTTP_LISTEN_ADDR.to_owned());
    let udp_announce_addr = resolve_string(
        input.udp_announce_addr,
        "SSH_KEY_SYNC_UDP_ANNOUNCE_ADDR",
        env_data,
        &file_data,
        "UDP_ANNOUNCE_ADDR",
    )
    .unwrap_or_else(|| DEFAULT_UDP_ANNOUNCE_ADDR.to_owned());
    let bootstrap_peers = resolve_string(
        input.bootstrap_peers,
        "SSH_KEY_SYNC_BOOTSTRAP_PEERS",
        env_data,
        &file_data,
        "BOOTSTRAP_PEERS",
    )
    .map(parse_csv)
    .unwrap_or_default();
    let public_key_path = resolve_string(
        input.public_key_path,
        "SSH_KEY_SYNC_PUBLIC_KEY_PATH",
        env_data,
        &file_data,
        "PUBLIC_KEY_PATH",
    )
    .unwrap_or_else(|| DEFAULT_PUBLIC_KEY_PATH.to_owned());
    let authorized_keys_path = resolve_string(
        input.authorized_keys_path,
        "SSH_KEY_SYNC_AUTHORIZED_KEYS_PATH",
        env_data,
        &file_data,
        "AUTHORIZED_KEYS_PATH",
    )
    .unwrap_or_else(|| DEFAULT_AUTHORIZED_KEYS_PATH.to_owned());
    let dry_run = resolve_bool(
        input.dry_run,
        "SSH_KEY_SYNC_DRY_RUN",
        env_data,
        &file_data,
        "DRY_RUN",
    );
    let tls_cert_path = resolve_string(
        input.tls_cert_path,
        "SSH_KEY_SYNC_TLS_CERT_PATH",
        env_data,
        &file_data,
        "TLS_CERT_PATH",
    );
    let tls_key_path = resolve_string(
        input.tls_key_path,
        "SSH_KEY_SYNC_TLS_KEY_PATH",
        env_data,
        &file_data,
        "TLS_KEY_PATH",
    );
    let tls_ca_path = resolve_string(
        input.tls_ca_path,
        "SSH_KEY_SYNC_TLS_CA_PATH",
        env_data,
        &file_data,
        "TLS_CA_PATH",
    );
    let tls_server_name = resolve_string(
        input.tls_server_name,
        "SSH_KEY_SYNC_TLS_SERVER_NAME",
        env_data,
        &file_data,
        "TLS_SERVER_NAME",
    );
    let insecure_no_tls = resolve_bool(
        input.insecure_no_tls,
        "SSH_KEY_SYNC_INSECURE_NO_TLS",
        env_data,
        &file_data,
        "INSECURE_NO_TLS",
    );

    Ok(Some(AppConfig {
        sid,
        sid_token,
        participant_id,
        http_listen_addr,
        udp_announce_addr,
        bootstrap_peers,
        sync_interval_secs,
        public_key_path,
        authorized_keys_path,
        tls_cert_path,
        tls_key_path,
        tls_ca_path,
        tls_server_name,
        insecure_no_tls,
        dry_run,
    }))
}

fn collect_env() -> HashMap<String, String> {
    let keys = [
        "SSH_KEY_SYNC_SID",
        "SSH_KEY_SYNC_SID_TOKEN",
        "SSH_KEY_SYNC_PARTICIPANT_ID",
        "SSH_KEY_SYNC_HTTP_LISTEN_ADDR",
        "SSH_KEY_SYNC_UDP_ANNOUNCE_ADDR",
        "SSH_KEY_SYNC_BOOTSTRAP_PEERS",
        "SSH_KEY_SYNC_SYNC_INTERVAL_SECS",
        "SSH_KEY_SYNC_PUBLIC_KEY_PATH",
        "SSH_KEY_SYNC_AUTHORIZED_KEYS_PATH",
        "SSH_KEY_SYNC_TLS_CERT_PATH",
        "SSH_KEY_SYNC_TLS_KEY_PATH",
        "SSH_KEY_SYNC_TLS_CA_PATH",
        "SSH_KEY_SYNC_TLS_SERVER_NAME",
        "SSH_KEY_SYNC_INSECURE_NO_TLS",
        "SSH_KEY_SYNC_DRY_RUN",
        "HOSTNAME",
    ];

    let mut values = HashMap::new();
    for key in keys {
        if let Ok(value) = std::env::var(key) {
            values.insert(key.to_owned(), value);
        }
    }
    values
}

fn read_config_file(path: Option<&str>) -> Result<HashMap<String, String>, ConfigError> {
    let Some(path) = path else {
        return Ok(HashMap::new());
    };

    let content = fs::read_to_string(Path::new(path))
        .map_err(|_| ConfigError::ConfigFileReadFailed(path.to_owned()))?;
    Ok(parse_config_key_values(&content))
}

fn parse_config_key_values(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        map.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    map
}

fn resolve_string(
    arg: Option<&str>,
    env_key: &str,
    env_data: &HashMap<String, String>,
    file_data: &HashMap<String, String>,
    file_key: &str,
) -> Option<String> {
    arg.map(str::to_owned)
        .or_else(|| env_data.get(env_key).cloned())
        .or_else(|| file_data.get(file_key).cloned())
}

fn resolve_u64(
    arg: Option<u64>,
    env_key: &str,
    env_data: &HashMap<String, String>,
    file_data: &HashMap<String, String>,
    file_key: &str,
) -> Option<u64> {
    arg.or_else(|| env_data.get(env_key).and_then(|v| v.parse::<u64>().ok()))
        .or_else(|| file_data.get(file_key).and_then(|v| v.parse::<u64>().ok()))
}

fn resolve_bool(
    arg: bool,
    env_key: &str,
    env_data: &HashMap<String, String>,
    file_data: &HashMap<String, String>,
    file_key: &str,
) -> bool {
    if arg {
        return true;
    }

    env_data
        .get(env_key)
        .cloned()
        .and_then(parse_bool)
        .or_else(|| {
            file_data
                .get(file_key)
                .and_then(|v| parse_bool(v.to_owned()))
        })
        .unwrap_or(false)
}

fn parse_bool(value: String) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_csv(value: String) -> Vec<String> {
    let mut seen = HashSet::new();
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .filter_map(|item| {
            if seen.insert(item.to_owned()) {
                Some(item.to_owned())
            } else {
                None
            }
        })
        .collect()
}

fn normalize_non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, ConfigInput, ConfigMode, load_config, load_config_with_sources};
    use std::collections::HashMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn base_input<'a>() -> ConfigInput<'a> {
        ConfigInput {
            sid: Some("group-a"),
            sid_token: Some("secret-token"),
            participant_id: None,
            http_listen_addr: None,
            udp_announce_addr: None,
            bootstrap_peers: None,
            sync_interval_secs: None,
            public_key_path: None,
            authorized_keys_path: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            tls_server_name: None,
            insecure_no_tls: false,
            dry_run: false,
            config_path: None,
        }
    }

    #[test]
    fn requires_sid_when_mode_is_strict() {
        let mut input = base_input();
        input.sid = None;
        let config = load_config(&input, ConfigMode::RequireSyncConfig);
        assert_eq!(config, Err(ConfigError::MissingSid));
    }

    #[test]
    fn requires_sid_token_when_mode_is_strict() {
        let mut input = base_input();
        input.sid_token = None;
        let config = load_config(&input, ConfigMode::RequireSyncConfig);
        assert_eq!(config, Err(ConfigError::MissingSidToken));
    }

    #[test]
    fn rejects_empty_sid() {
        let mut input = base_input();
        input.sid = Some("   ");
        let config = load_config(&input, ConfigMode::RequireSyncConfig);
        assert_eq!(config, Err(ConfigError::InvalidSid));
    }

    #[test]
    fn rejects_empty_sid_token() {
        let mut input = base_input();
        input.sid_token = Some("  ");
        let config = load_config(&input, ConfigMode::RequireSyncConfig);
        assert_eq!(config, Err(ConfigError::InvalidSidToken));
    }

    #[test]
    fn accepts_values_from_args() {
        let config = load_config(&base_input(), ConfigMode::RequireSyncConfig)
            .expect("config should parse")
            .expect("config should exist");

        assert_eq!(config.sid, "group-a");
        assert_eq!(config.sid_token, "secret-token");
        assert_eq!(config.sync_interval_secs, 30);
    }

    #[test]
    fn allows_missing_config_in_optional_mode() {
        let mut input = base_input();
        input.sid = None;
        input.sid_token = None;
        let config =
            load_config(&input, ConfigMode::AllowMissing).expect("optional mode should work");
        assert!(config.is_none());
    }

    #[test]
    fn does_not_allow_partial_config_in_optional_mode() {
        let mut input = base_input();
        input.sid_token = None;
        let config = load_config(&input, ConfigMode::AllowMissing);
        assert_eq!(config, Err(ConfigError::MissingSidToken));
    }

    #[test]
    fn rejects_zero_sync_interval() {
        let mut input = base_input();
        input.sync_interval_secs = Some(0);
        let config = load_config(&input, ConfigMode::RequireSyncConfig);
        assert_eq!(config, Err(ConfigError::InvalidSyncInterval));
    }

    #[test]
    fn masks_sid_token_in_debug_output() {
        let config = load_config(&base_input(), ConfigMode::RequireSyncConfig)
            .expect("config should parse")
            .expect("config should exist");
        let debug = format!("{config:?}");

        assert!(debug.contains("sid_token: \"***\""));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn reads_values_from_config_file() {
        let config_path = create_temp_config(
            "SID=file-group\n\
             SID_TOKEN=file-token\n\
             PARTICIPANT_ID=file-node\n\
             HTTP_LISTEN_ADDR=127.0.0.1:1234\n\
             UDP_ANNOUNCE_ADDR=127.0.0.1:1235\n\
             BOOTSTRAP_PEERS=node-a:1,node-b:2\n\
             SYNC_INTERVAL_SECS=45\n\
             PUBLIC_KEY_PATH=/tmp/key.pub\n\
             AUTHORIZED_KEYS_PATH=/tmp/authorized_keys\n\
             TLS_CERT_PATH=/tmp/tls.crt\n\
             TLS_KEY_PATH=/tmp/tls.key\n\
             TLS_CA_PATH=/tmp/ca.crt\n\
             TLS_SERVER_NAME=node-a.local\n\
             INSECURE_NO_TLS=false\n\
             DRY_RUN=true\n",
        );

        let mut input = base_input();
        input.sid = None;
        input.sid_token = None;
        input.config_path = Some(&config_path);
        let config = load_config(&input, ConfigMode::RequireSyncConfig)
            .expect("config should parse")
            .expect("config should exist");

        assert_eq!(config.sid, "file-group");
        assert_eq!(config.sid_token, "file-token");
        assert_eq!(config.participant_id, "file-node");
        assert_eq!(config.http_listen_addr, "127.0.0.1:1234");
        assert_eq!(config.udp_announce_addr, "127.0.0.1:1235");
        assert_eq!(
            config.bootstrap_peers,
            vec!["node-a:1".to_owned(), "node-b:2".to_owned()]
        );
        assert_eq!(config.sync_interval_secs, 45);
        assert_eq!(config.public_key_path, "/tmp/key.pub");
        assert_eq!(config.authorized_keys_path, "/tmp/authorized_keys");
        assert_eq!(config.tls_cert_path, Some("/tmp/tls.crt".to_owned()));
        assert_eq!(config.tls_key_path, Some("/tmp/tls.key".to_owned()));
        assert_eq!(config.tls_ca_path, Some("/tmp/ca.crt".to_owned()));
        assert_eq!(config.tls_server_name, Some("node-a.local".to_owned()));
        assert!(!config.insecure_no_tls);
        assert!(config.dry_run);

        fs::remove_file(config_path).expect("temp config should be removed");
    }

    #[test]
    fn cli_values_override_config_file() {
        let config_path = create_temp_config(
            "SID=file-group\n\
             SID_TOKEN=file-token\n\
             SYNC_INTERVAL_SECS=90\n",
        );

        let mut input = base_input();
        input.config_path = Some(&config_path);
        input.sync_interval_secs = Some(10);

        let config = load_config(&input, ConfigMode::RequireSyncConfig)
            .expect("config should parse")
            .expect("config should exist");

        assert_eq!(config.sid, "group-a");
        assert_eq!(config.sid_token, "secret-token");
        assert_eq!(config.sync_interval_secs, 10);

        fs::remove_file(config_path).expect("temp config should be removed");
    }

    #[test]
    fn normalizes_and_deduplicates_bootstrap_peers() {
        let mut input = base_input();
        input.bootstrap_peers = Some(" node-a:1, node-b:2, node-a:1 , node-c:3 ");

        let config = load_config(&input, ConfigMode::RequireSyncConfig)
            .expect("config should parse")
            .expect("config should exist");

        assert_eq!(
            config.bootstrap_peers,
            vec![
                "node-a:1".to_owned(),
                "node-b:2".to_owned(),
                "node-c:3".to_owned()
            ]
        );
    }

    #[test]
    fn reads_values_from_env_sources() {
        let mut input = base_input();
        input.sid = None;
        input.sid_token = None;

        let env_data = HashMap::from([
            ("SSH_KEY_SYNC_SID".to_owned(), "env-group".to_owned()),
            ("SSH_KEY_SYNC_SID_TOKEN".to_owned(), "env-token".to_owned()),
            (
                "SSH_KEY_SYNC_PARTICIPANT_ID".to_owned(),
                "env-node".to_owned(),
            ),
            (
                "SSH_KEY_SYNC_BOOTSTRAP_PEERS".to_owned(),
                "peer-a:1,peer-b:2".to_owned(),
            ),
            (
                "SSH_KEY_SYNC_SYNC_INTERVAL_SECS".to_owned(),
                "75".to_owned(),
            ),
            (
                "SSH_KEY_SYNC_TLS_CERT_PATH".to_owned(),
                "/env/tls.crt".to_owned(),
            ),
            (
                "SSH_KEY_SYNC_TLS_KEY_PATH".to_owned(),
                "/env/tls.key".to_owned(),
            ),
            (
                "SSH_KEY_SYNC_TLS_CA_PATH".to_owned(),
                "/env/ca.crt".to_owned(),
            ),
            (
                "SSH_KEY_SYNC_TLS_SERVER_NAME".to_owned(),
                "peer.env.local".to_owned(),
            ),
            (
                "SSH_KEY_SYNC_INSECURE_NO_TLS".to_owned(),
                "false".to_owned(),
            ),
            ("SSH_KEY_SYNC_DRY_RUN".to_owned(), "true".to_owned()),
        ]);

        let config = load_config_with_sources(&input, ConfigMode::RequireSyncConfig, &env_data)
            .expect("config should parse")
            .expect("config should exist");

        assert_eq!(config.sid, "env-group");
        assert_eq!(config.sid_token, "env-token");
        assert_eq!(config.participant_id, "env-node");
        assert_eq!(
            config.bootstrap_peers,
            vec!["peer-a:1".to_owned(), "peer-b:2".to_owned()]
        );
        assert_eq!(config.sync_interval_secs, 75);
        assert_eq!(config.tls_cert_path, Some("/env/tls.crt".to_owned()));
        assert_eq!(config.tls_key_path, Some("/env/tls.key".to_owned()));
        assert_eq!(config.tls_ca_path, Some("/env/ca.crt".to_owned()));
        assert_eq!(config.tls_server_name, Some("peer.env.local".to_owned()));
        assert!(!config.insecure_no_tls);
        assert!(config.dry_run);
    }

    #[test]
    fn cli_values_override_env_sources() {
        let input = base_input();
        let env_data = HashMap::from([
            ("SSH_KEY_SYNC_SID".to_owned(), "env-group".to_owned()),
            ("SSH_KEY_SYNC_SID_TOKEN".to_owned(), "env-token".to_owned()),
            (
                "SSH_KEY_SYNC_SYNC_INTERVAL_SECS".to_owned(),
                "75".to_owned(),
            ),
        ]);

        let config = load_config_with_sources(&input, ConfigMode::RequireSyncConfig, &env_data)
            .expect("config should parse")
            .expect("config should exist");

        assert_eq!(config.sid, "group-a");
        assert_eq!(config.sid_token, "secret-token");
        assert_eq!(config.sync_interval_secs, 75);
    }

    fn create_temp_config(content: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ssh-key-sync-config-{timestamp}.env"));
        fs::write(&path, content).expect("temp config should be written");
        path.to_string_lossy().to_string()
    }
}
