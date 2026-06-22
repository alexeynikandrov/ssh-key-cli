#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod authorized_keys;
mod config;
#[allow(dead_code)]
mod daemon;
#[allow(dead_code)]
mod discovery;
#[allow(dead_code)]
mod e2e;
mod runtime;
#[allow(dead_code)]
mod ssh_keys;
#[allow(dead_code)]
mod transport;

use clap::{Args, Parser, Subcommand};
use config::{ConfigInput, ConfigMode, load_config};
use std::process::{Command as ProcessCommand, Stdio};

#[derive(Parser, Debug)]
#[command(name = "ssh-key-sync")]
#[command(about = "SSH key synchronization daemon CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Debug)]
struct SyncConfigArgs {
    /// Synchronization group identifier.
    #[arg(long)]
    sid: Option<String>,

    /// Synchronization group secret token.
    #[arg(long)]
    sid_token: Option<String>,

    /// Participant identifier visible to other hosts.
    #[arg(long)]
    participant_id: Option<String>,

    /// HTTP listen address for key exchange API.
    #[arg(long)]
    http_listen_addr: Option<String>,

    /// UDP address for announcement listener/sender.
    #[arg(long)]
    udp_announce_addr: Option<String>,

    /// Bootstrap peers list separated by commas.
    #[arg(long)]
    bootstrap_peers: Option<String>,

    /// Sync interval in seconds.
    #[arg(long)]
    sync_interval_secs: Option<u64>,

    /// Path to local public SSH key.
    #[arg(long)]
    public_key_path: Option<String>,

    /// Path to authorized_keys.
    #[arg(long)]
    authorized_keys_path: Option<String>,

    /// Path to TLS certificate (PEM). Required unless --insecure-no-tls is set.
    #[arg(long)]
    tls_cert_path: Option<String>,

    /// Path to TLS private key (PEM). Required unless --insecure-no-tls is set.
    #[arg(long)]
    tls_key_path: Option<String>,

    /// Path to TLS CA certificate bundle (PEM). Required unless --insecure-no-tls is set.
    #[arg(long)]
    tls_ca_path: Option<String>,

    /// Override TLS server name for outbound certificate validation.
    #[arg(long)]
    tls_server_name: Option<String>,

    /// Disable TLS (dev/test only). Not recommended for production.
    #[arg(long, default_value_t = false)]
    insecure_no_tls: bool,

    /// Dry-run mode without writing changes.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Optional KEY=VALUE config file path.
    #[arg(long)]
    config_path: Option<String>,
}

#[derive(Args, Debug)]
struct StartArgs {
    #[command(flatten)]
    config: SyncConfigArgs,

    /// Keep `start` in foreground (do not daemonize to background).
    #[arg(long, default_value_t = false)]
    foreground: bool,
}

#[derive(Args, Debug)]
struct SyncArgs {
    #[command(flatten)]
    config: SyncConfigArgs,
}

#[derive(Args, Debug)]
struct ControlArgs {
    /// Synchronization group identifier. If omitted, use current daemon SID.
    #[arg(long)]
    sid: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Start(StartArgs),
    Stop(ControlArgs),
    Status(ControlArgs),
    Sync(SyncArgs),
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Stop(args) => {
            let sid = resolve_control_sid(args.sid.as_deref());
            let sid = match sid {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(2);
                }
            };
            match runtime::stop_daemon(&sid) {
                Ok(true) => println!("Stop requested for SID: {sid}"),
                Ok(false) => println!("Daemon is not running for SID: {sid}"),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        Command::Status(args) => {
            let sid = resolve_control_sid(args.sid.as_deref());
            let sid = match sid {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(2);
                }
            };
            match runtime::status_daemon(&sid) {
                Ok(runtime::DaemonStatus::Running { pid }) => {
                    println!("Daemon is running for SID: {sid} (pid: {pid})");
                }
                Ok(runtime::DaemonStatus::Stopped) => {
                    println!("Daemon is stopped for SID: {sid}");
                }
                Ok(runtime::DaemonStatus::StalePidFile { pid }) => {
                    println!("Daemon is stopped for SID: {sid} (stale pid file: {pid})");
                }
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        Command::Start(args) => {
            let input = config_input_from_args(&args.config);
            let config = load_config(&input, ConfigMode::RequireSyncConfig);
            let config = match config {
                Ok(Some(value)) => value,
                Ok(None) => {
                    eprintln!("Missing required configuration for start command");
                    std::process::exit(2);
                }
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(2);
                }
            };

            if !args.foreground && std::env::var("SSH_KEY_SYNC_INTERNAL_FOREGROUND").is_err() {
                match runtime::status_daemon(&config.sid) {
                    Ok(runtime::DaemonStatus::Running { pid }) => {
                        println!(
                            "Daemon is already running for SID: {} (pid: {pid})",
                            config.sid
                        );
                        return;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                }
                match spawn_background_start(&config.sid) {
                    Ok(()) => {
                        let log_path = runtime::daemon_log_file_path(&config.sid)
                            .unwrap_or_else(|_| "<unavailable>".to_owned());
                        println!(
                            "Daemon started in background for SID: {} (log: {log_path})",
                            config.sid
                        );
                        return;
                    }
                    Err(error) => {
                        eprintln!("Failed to start daemon in background: {error}");
                        std::process::exit(1);
                    }
                }
            }
            if let Err(error) = runtime::run_daemon(&config) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Command::Sync(args) => {
            let input = config_input_from_args(&args.config);
            let config = load_config(&input, ConfigMode::RequireSyncConfig);
            let config = match config {
                Ok(Some(value)) => value,
                Ok(None) => {
                    eprintln!("Missing required configuration for sync command");
                    std::process::exit(2);
                }
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(2);
                }
            };
            if let Err(error) = runtime::run_single_sync(&config) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
}

fn config_input_from_args(args: &SyncConfigArgs) -> ConfigInput<'_> {
    ConfigInput {
        sid: args.sid.as_deref(),
        sid_token: args.sid_token.as_deref(),
        participant_id: args.participant_id.as_deref(),
        http_listen_addr: args.http_listen_addr.as_deref(),
        udp_announce_addr: args.udp_announce_addr.as_deref(),
        bootstrap_peers: args.bootstrap_peers.as_deref(),
        sync_interval_secs: args.sync_interval_secs,
        public_key_path: args.public_key_path.as_deref(),
        authorized_keys_path: args.authorized_keys_path.as_deref(),
        tls_cert_path: args.tls_cert_path.as_deref(),
        tls_key_path: args.tls_key_path.as_deref(),
        tls_ca_path: args.tls_ca_path.as_deref(),
        tls_server_name: args.tls_server_name.as_deref(),
        insecure_no_tls: args.insecure_no_tls,
        dry_run: args.dry_run,
        config_path: args.config_path.as_deref(),
    }
}

fn resolve_control_sid(explicit_sid: Option<&str>) -> Result<String, String> {
    if let Some(sid) = explicit_sid {
        let trimmed = sid.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    if let Ok(sid) = std::env::var("SSH_KEY_SYNC_SID") {
        let trimmed = sid.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_owned());
        }
    }
    match runtime::resolve_current_sid() {
        Ok(Some(sid)) => Ok(sid),
        Ok(None) => Err("Missing SID: use --sid or start daemon first".to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

fn spawn_background_start(sid: &str) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (log_file, _) = runtime::open_daemon_log_file(sid).map_err(|error| error.to_string())?;
    let log_err = log_file.try_clone().map_err(|error| error.to_string())?;

    ProcessCommand::new(executable)
        .args(args)
        .env("SSH_KEY_SYNC_INTERNAL_FOREGROUND", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|error| error.to_string())?;

    Ok(())
}
