# ssh-key-sync

`ssh-key-sync` is a daemon-oriented CLI for synchronizing SSH public keys between trusted hosts.

## Run

Required:

- `--sid` (or `SSH_KEY_SYNC_SID`)
- `--sid-token` (or `SSH_KEY_SYNC_SID_TOKEN`)

Commands:

```bash
ssh-key-sync --sid group-a --sid-token secret-token start
ssh-key-sync --sid group-a --sid-token secret-token sync
ssh-key-sync --sid group-a status
ssh-key-sync --sid group-a stop
```

## Configuration

The CLI supports configuration from:

1. CLI arguments
2. Environment variables
3. `KEY=VALUE` config file via `--config-path`

Source precedence is: **CLI > ENV > config file**.

Important options:

- `--participant-id`
- `--http-listen-addr`
- `--udp-announce-addr`
- `--bootstrap-peers`
- `--sync-interval-secs`
- `--public-key-path`
- `--authorized-keys-path`
- `--dry-run`

## bootstrap-peers format

Supported peer formats:

- `<participant_id>@<address>:<port>`
- `<address>:<port>` (participant ID falls back to the full host:port text)

Examples:

```text
node-a@10.0.0.2:2222,node-b@10.0.0.3:2222,10.0.0.4:2222
```

## Security model (phase baseline)

- All exchange messages are scoped by `SID`.
- Message signatures are HMAC-SHA256 with `SID_TOKEN`.
- Signed contexts include HTTP request/response and UDP announcement.
- Replay protection uses timestamp skew window plus nonce cache TTL.
- Messages with wrong SID, wrong signature, stale timestamp, or replayed nonce are ignored/rejected.
- `SID_TOKEN` is treated as a secret and is masked in debug output.

## `authorized_keys` behavior

The tool manages only the dedicated block:

```text
# ssh-key-sync begin
...
# ssh-key-sync end
```

Behavior:

- only the managed block is replaced/updated;
- user-managed lines outside this block are preserved;
- updates are idempotent (reapplying same keys does not duplicate entries);
- file writes use atomic temp write + fsync + rename flow;
- on Unix, secure permissions are enforced (`~/.ssh` = `0700`, `authorized_keys` = `0600`).

## Validation commands

```bash
make check
make e2e
```
