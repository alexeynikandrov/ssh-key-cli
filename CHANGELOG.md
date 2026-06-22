# Changelog

All notable changes to this project will be documented in this file.

## [0.1.15] - 2026-06-22

### Changed
- Updated CI workflow to install `pandoc` on `ubuntu-latest` before `make release`.
- Fixed CI failure on manpage generation step (`pandoc: No such file or directory`).

## [0.1.14] - 2026-06-22

### Changed
- Switched CLI command syntax to command-first form:
  `ssh-key-sync <start|sync|status|stop> [options]`.
- Moved sync-related options under `start` and `sync` subcommands.
- Made `--sid` optional for `status` and `stop`:
  SID is resolved from `SSH_KEY_SYNC_SID` or current runtime marker.
- Updated `status` and `stop` behavior to operate on the resolved current SID by default.
- Updated `README.md` and `docs/man.md` examples and command descriptions for the new CLI shape.

## [0.1.13] - 2026-06-22

### Added
- Added RFC-0002 and plan `docs/PLAN-2-2.md` for phased weaknesses remediation.
- Added runtime tests for daemon control path resolution and private permission enforcement.

### Changed
- Moved daemon control artifacts from `/tmp` to
  `${XDG_RUNTIME_DIR}/ssh-key-sync/<sid>/` with fallback to
  `~/.local/run/ssh-key-sync/<sid>/`.
- Switched control file names to `daemon.pid`, `daemon.stop`, and `daemon.log`.
- Enforced private Unix permissions for daemon control artifacts (`0700` directories, `0600` files).
- Updated daemon status/control flows to surface control-path errors explicitly.
- Updated `docs/man.md` with the new daemon runtime file locations.

## [0.1.12] - 2026-06-18

### Added
- Added `docs/man.md` as the man-page source for `ssh-key-sync`.
- Added `make man` target that compiles `docs/man.md` into `target/man/ssh-key-sync.1`.

### Changed
- Updated `make release` to always build the man page before release build.

## [0.1.11] - 2026-06-18

### Added
- Added real runtime execution for `start` and `sync`:
  HTTP listener, UDP announcement processing, peer key fetch, and managed `authorized_keys` update.
- Added manual Docker walkthrough in `docker/README.md` for 2-container local verification flow.
- Added background daemon launch mode for `start` by default (with `--foreground` override).
- Added SID-scoped daemon control paths for `status` and `stop` with PID tracking in `/tmp`.

### Changed
- Updated `stop` behavior to enforce process termination:
  graceful stop request first, then PID-targeted `SIGTERM` fallback on timeout.

## [0.1.10] - 2026-06-18

### Added
- Added `make release` target for optimized release build via
  `cargo build --release --all-targets`.

## [0.1.9] - 2026-06-18

### Added
- Added phase-8 operator documentation in `README.md` for run/configuration, bootstrap peers,
  security model, and managed `authorized_keys` behavior.
- Finalized RFC workflow for RFC-0001 with sequential status transition to `implemented`.

## [0.1.8] - 2026-06-18

### Added
- Added phase-7 end-to-end scenario suite for multi-node behavior:
  two-node key exchange, late joiner sync trigger, SID/SID_TOKEN isolation,
  publish flow, and authorized_keys idempotency.
- Added containerized E2E execution via `docker-compose.e2e.yml` and `make e2e`.

## [0.1.7] - 2026-06-18

### Added
- Added daemon loop state machine with startup sync handling, periodic scheduling, and
  discovery-triggered immediate sync execution.
- Added explicit daemon state reporting for mode, known peers, pending trigger, last successful
  sync, peer-level errors, and critical failures.
- Added graceful shutdown behavior that waits for in-flight sync completion before stop.
- Added daemon tests for poll timing, trigger handling, peer-vs-critical failure paths, and
  shutdown semantics.

## [0.1.6] - 2026-06-18

### Added
- Added discovery engine with bootstrap peer ingestion and signed UDP announcement handling.
- Added SID/SID_TOKEN-gated announcement verification with replay protection integration.
- Added runtime peer-set updates and sync-trigger signaling for immediate follow-up sync cycles.
- Added discovery tests for valid announcements, wrong SID/token, malformed payloads, replay, and
  peer update behavior.

## [0.1.5] - 2026-06-18

### Added
- Added signed HTTP key-exchange service flows for public-key retrieval and participant publication.
- Added strict context checks for signed HTTP envelopes (method/path and status/path).
- Added payload parsing/validation for exchange messages with required-field handling.
- Added transport tests for happy-path exchange flows and invalid signature/payload/context cases.

## [0.1.4] - 2026-06-18

### Added
- Added SSH public key file loading with normalization and format validation.
- Added managed-block update logic for `authorized_keys` with `# ssh-key-sync begin/end` markers.
- Added atomic on-disk update flow for `authorized_keys` (`tmp write + fsync + rename`) and
  secure Unix permissions handling for `.ssh` and `authorized_keys`.
- Added tests for managed-block replacement, manual-key preservation, and invalid-key rejection.

## [0.1.3] - 2026-06-18

### Added
- Implemented HMAC-SHA256 envelope signing and verification for SID-scoped messages.
- Added canonical context support for HTTP requests, HTTP responses, and UDP announcements.
- Added replay protection primitives with timestamp window checks and nonce TTL cache.
- Added auth unit tests for signature integrity, context separation, SID mismatch, timestamp
  window validation, and replay rejection behavior.

## [0.1.2] - 2026-06-18

### Added
- Added phase-1 configuration model with required `SID` and `SID_TOKEN`.
- Added CLI options and env/config-file loading for participant identity, listen addresses,
  bootstrap peers, sync interval, key paths, and dry-run mode.
- Added validation for non-empty `SID`/`SID_TOKEN`, positive sync interval, and normalized
  deduplicated bootstrap peers.
- Added configuration tests for source precedence (`CLI > ENV > config file`) and error paths.

## [0.1.1] - 2026-06-18

### Added
- Initialized Rust CLI project for `ssh-key-sync`.
- Added clap-based subcommands: `start`, `stop`, `status`, `sync`.
- Added baseline modules for upcoming RFC-0001 implementation:
  `config`, `daemon`, `discovery`, `transport`, `auth`, `ssh_keys`, `authorized_keys`.
- Added `Makefile` commands: `fmt`, `lint`, `test`, `build`, `check`.
- Added `.gitignore` entries for local artifacts (`target/`, `a.out`).
