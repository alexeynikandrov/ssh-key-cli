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

use clap::{Parser, Subcommand};
use config::{ConfigInput, ConfigMode, load_config};
use std::process::{Command as ProcessCommand, Stdio};

#[derive(Parser, Debug)]
#[command(name = "ssh-key-sync")]
#[command(about = "SSH key synchronization daemon CLI")]
struct Cli {
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

    /// Dry-run mode without writing changes.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Optional KEY=VALUE config file path.
    #[arg(long)]
    config_path: Option<String>,

    /// Keep `start` in foreground (do not daemonize to background).
    #[arg(long, default_value_t = false)]
    foreground: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum Command {
    Start,
    Stop,
    Status,
    Sync,
}

fn main() {
    let cli = Cli::parse();
    if matches!(cli.command, Command::Stop | Command::Status) {
        let sid = resolve_sid(&cli);
        let sid = match sid {
            Some(value) => value,
            None => {
                eprintln!("Missing SID: set --sid or SSH_KEY_SYNC_SID");
                std::process::exit(2);
            }
        };

        match cli.command {
            Command::Stop => match runtime::stop_daemon(&sid) {
                Ok(true) => println!("Stop requested for SID: {sid}"),
                Ok(false) => println!("Daemon is not running for SID: {sid}"),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            },
            Command::Status => match runtime::status_daemon(&sid) {
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
            },
            _ => {}
        }
        return;
    }

    let mode = match cli.command {
        Command::Stop | Command::Status => ConfigMode::AllowMissing,
        Command::Start | Command::Sync => ConfigMode::RequireSyncConfig,
    };
    let input = ConfigInput {
        sid: cli.sid.as_deref(),
        sid_token: cli.sid_token.as_deref(),
        participant_id: cli.participant_id.as_deref(),
        http_listen_addr: cli.http_listen_addr.as_deref(),
        udp_announce_addr: cli.udp_announce_addr.as_deref(),
        bootstrap_peers: cli.bootstrap_peers.as_deref(),
        sync_interval_secs: cli.sync_interval_secs,
        public_key_path: cli.public_key_path.as_deref(),
        authorized_keys_path: cli.authorized_keys_path.as_deref(),
        dry_run: cli.dry_run,
        config_path: cli.config_path.as_deref(),
    };
    let config = load_config(&input, mode);

    let config = match config {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

    match cli.command {
        Command::Start => {
            let config = config.expect("required configuration is missing");
            if !cli.foreground && std::env::var("SSH_KEY_SYNC_INTERNAL_FOREGROUND").is_err() {
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
        Command::Stop | Command::Status => unreachable!("handled before config load"),
        Command::Sync => {
            let config = config.expect("required configuration is missing");
            if let Err(error) = runtime::run_single_sync(&config) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
}

fn resolve_sid(cli: &Cli) -> Option<String> {
    cli.sid
        .as_ref()
        .map(ToOwned::to_owned)
        .or_else(|| std::env::var("SSH_KEY_SYNC_SID").ok())
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
