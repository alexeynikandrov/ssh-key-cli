#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonMode {
    Running,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSyncErrorKind {
    AuthFailed,
    Unreachable,
    InvalidPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSyncError {
    pub participant_id: String,
    pub kind: PeerSyncErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCycleResult {
    pub completed_at_secs: u64,
    pub peer_errors: Vec<PeerSyncError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncExecution {
    Success(SyncCycleResult),
    CriticalFailure(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonState {
    pub mode: DaemonMode,
    pub known_peers_count: usize,
    pub sync_trigger_pending: bool,
    pub next_sync_due_secs: u64,
    pub in_flight_sync: bool,
    pub last_successful_sync_at_secs: Option<u64>,
    pub last_peer_errors: Vec<PeerSyncError>,
    pub last_critical_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonLoop {
    sync_interval_secs: u64,
    jitter_secs: u64,
    shutdown_requested: bool,
    state: DaemonState,
}

impl DaemonLoop {
    pub fn new(started_at_secs: u64, sync_interval_secs: u64, jitter_secs: u64) -> Self {
        let sync_interval_secs = sync_interval_secs.max(1);
        let next_sync_due_secs = started_at_secs + sync_interval_secs + jitter_secs;
        Self {
            sync_interval_secs,
            jitter_secs,
            shutdown_requested: false,
            state: DaemonState {
                mode: DaemonMode::Running,
                known_peers_count: 0,
                sync_trigger_pending: false,
                next_sync_due_secs,
                in_flight_sync: false,
                last_successful_sync_at_secs: None,
                last_peer_errors: Vec::new(),
                last_critical_error: None,
            },
        }
    }

    pub fn state(&self) -> &DaemonState {
        &self.state
    }

    pub fn set_known_peers_count(&mut self, count: usize) {
        self.state.known_peers_count = count;
    }

    pub fn trigger_sync_from_discovery(&mut self) {
        if self.state.mode == DaemonMode::Running {
            self.state.sync_trigger_pending = true;
        }
    }

    pub fn request_shutdown(&mut self) {
        self.shutdown_requested = true;
        if self.state.mode == DaemonMode::Stopped {
            return;
        }
        if self.state.in_flight_sync {
            self.state.mode = DaemonMode::Stopping;
        } else {
            self.state.mode = DaemonMode::Stopped;
        }
    }

    pub fn should_start_sync(&self, now_secs: u64) -> bool {
        if self.state.mode == DaemonMode::Stopped
            || self.shutdown_requested
            || self.state.in_flight_sync
        {
            return false;
        }

        self.state.sync_trigger_pending || now_secs >= self.state.next_sync_due_secs
    }

    pub fn start_sync(&mut self, now_secs: u64) -> bool {
        if !self.should_start_sync(now_secs) {
            return false;
        }
        self.state.in_flight_sync = true;
        true
    }

    pub fn run_startup_sync(&mut self, execution: SyncExecution, now_secs: u64) {
        if !self.start_sync(now_secs) {
            self.state.in_flight_sync = true;
        }
        self.finish_sync(execution, now_secs);
    }

    pub fn finish_sync(&mut self, execution: SyncExecution, now_secs: u64) {
        self.state.in_flight_sync = false;
        self.state.sync_trigger_pending = false;

        match execution {
            SyncExecution::Success(result) => {
                self.state.last_successful_sync_at_secs = Some(result.completed_at_secs);
                self.state.last_peer_errors = result.peer_errors;
                self.state.last_critical_error = None;
                self.state.next_sync_due_secs =
                    now_secs + self.sync_interval_secs + self.jitter_secs;
            }
            SyncExecution::CriticalFailure(message) => {
                self.state.last_critical_error = Some(message);
                self.state.mode = DaemonMode::Stopped;
                return;
            }
        }

        if self.shutdown_requested {
            self.state.mode = DaemonMode::Stopped;
        } else {
            self.state.mode = DaemonMode::Running;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DaemonLoop, DaemonMode, PeerSyncError, PeerSyncErrorKind, SyncCycleResult, SyncExecution,
    };

    #[test]
    fn startup_sync_sets_success_state() {
        let mut daemon = DaemonLoop::new(1_000, 30, 5);
        daemon.run_startup_sync(
            SyncExecution::Success(SyncCycleResult {
                completed_at_secs: 1_001,
                peer_errors: Vec::new(),
            }),
            1_001,
        );

        let state = daemon.state();
        assert_eq!(state.mode, DaemonMode::Running);
        assert_eq!(state.last_successful_sync_at_secs, Some(1_001));
        assert_eq!(state.next_sync_due_secs, 1_001 + 30 + 5);
    }

    #[test]
    fn discovery_trigger_starts_sync_before_poll_due() {
        let mut daemon = DaemonLoop::new(1_000, 30, 0);
        assert!(!daemon.should_start_sync(1_010));
        daemon.trigger_sync_from_discovery();
        assert!(daemon.should_start_sync(1_010));
        assert!(daemon.start_sync(1_010));
    }

    #[test]
    fn peer_errors_do_not_stop_daemon() {
        let mut daemon = DaemonLoop::new(1_000, 30, 0);
        assert!(daemon.start_sync(1_031));
        daemon.finish_sync(
            SyncExecution::Success(SyncCycleResult {
                completed_at_secs: 1_032,
                peer_errors: vec![PeerSyncError {
                    participant_id: "node-b".to_owned(),
                    kind: PeerSyncErrorKind::Unreachable,
                    message: "connection timeout".to_owned(),
                }],
            }),
            1_032,
        );

        let state = daemon.state();
        assert_eq!(state.mode, DaemonMode::Running);
        assert_eq!(state.last_peer_errors.len(), 1);
        assert_eq!(state.last_critical_error, None);
    }

    #[test]
    fn critical_error_stops_daemon() {
        let mut daemon = DaemonLoop::new(1_000, 30, 0);
        assert!(daemon.start_sync(1_030));
        daemon.finish_sync(
            SyncExecution::CriticalFailure("failed to update authorized_keys".to_owned()),
            1_031,
        );

        let state = daemon.state();
        assert_eq!(state.mode, DaemonMode::Stopped);
        assert_eq!(
            state.last_critical_error,
            Some("failed to update authorized_keys".to_owned())
        );
    }

    #[test]
    fn graceful_shutdown_waits_for_inflight_sync() {
        let mut daemon = DaemonLoop::new(1_000, 30, 0);
        assert!(daemon.start_sync(1_030));
        daemon.request_shutdown();

        assert_eq!(daemon.state().mode, DaemonMode::Stopping);
        daemon.finish_sync(
            SyncExecution::Success(SyncCycleResult {
                completed_at_secs: 1_031,
                peer_errors: Vec::new(),
            }),
            1_031,
        );
        assert_eq!(daemon.state().mode, DaemonMode::Stopped);
    }

    #[test]
    fn shutdown_without_inflight_sync_stops_immediately() {
        let mut daemon = DaemonLoop::new(1_000, 30, 0);
        daemon.request_shutdown();

        assert_eq!(daemon.state().mode, DaemonMode::Stopped);
        assert!(!daemon.should_start_sync(2_000));
    }

    #[test]
    fn poll_interval_triggers_sync_when_due() {
        let daemon = DaemonLoop::new(1_000, 30, 0);
        assert!(!daemon.should_start_sync(1_029));
        assert!(daemon.should_start_sync(1_030));
    }
}
