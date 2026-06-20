% SSH-KEY-SYNC(1) ssh-key-sync 0.1.11
% ssh-key-sync maintainers
% June 2026

# NAME

ssh-key-sync - synchronize SSH public keys across trusted hosts

# SYNOPSIS

**ssh-key-sync** [*OPTIONS*] <**start**|**stop**|**status**|**sync**>

# DESCRIPTION

`ssh-key-sync` exchanges and manages SSH public keys for participants in the same
`SID` group. Network messages are authenticated with `SID_TOKEN`.

The tool updates only the managed block in `authorized_keys`:

```
# ssh-key-sync begin
...
# ssh-key-sync end
```

# COMMANDS

**start**
: Start daemon mode. By default, starts in background and writes logs to
  `/tmp/ssh-key-sync-<sid>.log`.

**stop**
: Stop background daemon for the given `SID`.

**status**
: Show daemon status for the given `SID`.

**sync**
: Run a single synchronization cycle and exit.

# REQUIRED OPTIONS

For `start` and `sync`:

- `--sid` (or `SSH_KEY_SYNC_SID`)
- `--sid-token` (or `SSH_KEY_SYNC_SID_TOKEN`)

For `stop` and `status`:

- `--sid` (or `SSH_KEY_SYNC_SID`)

# OPTIONS

**--sid** *SID*
: Synchronization group identifier.

**--sid-token** *TOKEN*
: Synchronization group secret token used for HMAC signatures.

**--participant-id** *ID*
: Participant identifier visible to peers.

**--http-listen-addr** *ADDR:PORT*
: HTTP listen address for key exchange API.
  Default: `0.0.0.0:9922`.

**--udp-announce-addr** *ADDR:PORT*
: UDP address for announcement listener/sender.
  Default: `0.0.0.0:9923`.

**--bootstrap-peers** *LIST*
: Comma-separated peers list in one of formats:
  `<participant_id>@<address>:<port>` or `<address>:<port>`.

**--sync-interval-secs** *SECONDS*
: Periodic sync interval.
  Default: `30`.

**--public-key-path** *PATH*
: Path to local public SSH key file.
  Default: `~/.ssh/id_ed25519.pub`.

**--authorized-keys-path** *PATH*
: Path to authorized_keys file.
  Default: `~/.ssh/authorized_keys`.

**--dry-run**
: Run without writing `authorized_keys`.

**--config-path** *PATH*
: Optional `KEY=VALUE` configuration file.

**--foreground**
: Keep `start` in foreground mode (no background daemonization).

# FILES

`/tmp/ssh-key-sync-<sid>.pid`
: PID file for running daemon.

`/tmp/ssh-key-sync-<sid>.stop`
: Stop request file used by `stop`.

`/tmp/ssh-key-sync-<sid>.log`
: Background daemon log file.

# EXAMPLES

Start daemon in background:

```
ssh-key-sync --sid group-a --sid-token token-a start
```

Check status and stop:

```
ssh-key-sync --sid group-a status
ssh-key-sync --sid group-a stop
```

Run one-shot sync:

```
ssh-key-sync --sid group-a --sid-token token-a sync
```

# EXIT STATUS

`0` on success, non-zero on error.
