# ssh-key-sync

`ssh-key-sync` is a daemon-oriented CLI for synchronizing SSH public keys between trusted hosts.

## Run

Required:

- `--sid` (or `SSH_KEY_SYNC_SID`)
- `--sid-token` (or `SSH_KEY_SYNC_SID_TOKEN`)

Commands:

```bash
ssh-key-sync start --sid group-a --sid-token secret-token \
  --tls-cert-path ./certs/node-a.crt \
  --tls-key-path ./certs/node-a.key \
  --tls-ca-path ./certs/ca.crt
ssh-key-sync sync --sid group-a --sid-token secret-token \
  --tls-cert-path ./certs/node-a.crt \
  --tls-key-path ./certs/node-a.key \
  --tls-ca-path ./certs/ca.crt
ssh-key-sync status
ssh-key-sync stop
```

## Configuration

The CLI supports configuration from:

1. CLI arguments
2. Environment variables
3. `KEY=VALUE` config file via `--config-path`

Source precedence is: **CLI > ENV > config file**.

## Config file (`--config-path`)

`--config-path` is used by `start` and `sync` commands.
`status` and `stop` do not read config file.

Config file format is `KEY=VALUE` per line (`#` for comments).
Supported keys map to ENV names without `SSH_KEY_SYNC_` prefix:

- `SID`
- `SID_TOKEN`
- `PARTICIPANT_ID`
- `HTTP_LISTEN_ADDR`
- `UDP_ANNOUNCE_ADDR`
- `BOOTSTRAP_PEERS`
- `SYNC_INTERVAL_SECS`
- `PUBLIC_KEY_PATH`
- `AUTHORIZED_KEYS_PATH`
- `TLS_CERT_PATH`
- `TLS_KEY_PATH`
- `TLS_CA_PATH`
- `TLS_SERVER_NAME`
- `INSECURE_NO_TLS`
- `DRY_RUN`

Example config file:

```env
# ssh-key-sync.env
SID=group-a
SID_TOKEN=secret-token
PARTICIPANT_ID=node-a
HTTP_LISTEN_ADDR=0.0.0.0:9922
UDP_ANNOUNCE_ADDR=0.0.0.0:9923
BOOTSTRAP_PEERS=node-b@10.0.0.3:9922,node-c@10.0.0.4:9922
SYNC_INTERVAL_SECS=30
PUBLIC_KEY_PATH=/home/app/.ssh/id_ed25519.pub
AUTHORIZED_KEYS_PATH=/home/app/.ssh/authorized_keys
TLS_CERT_PATH=/etc/ssh-key-sync/certs/node-a.crt
TLS_KEY_PATH=/etc/ssh-key-sync/certs/node-a.key
TLS_CA_PATH=/etc/ssh-key-sync/certs/ca.crt
TLS_SERVER_NAME=node-b.internal
INSECURE_NO_TLS=false
DRY_RUN=false
```

Run with config file:

```bash
ssh-key-sync start --config-path ./ssh-key-sync.env
ssh-key-sync sync --config-path ./ssh-key-sync.env
```

## Environment variables

All supported environment variables:

- `SSH_KEY_SYNC_SID` (required for `start`/`sync` if `--sid` is not provided)  
  Example: `SSH_KEY_SYNC_SID=group-a`
- `SSH_KEY_SYNC_SID_TOKEN` (required for `start`/`sync` if `--sid-token` is not provided)  
  Example: `SSH_KEY_SYNC_SID_TOKEN=secret-token`
- `SSH_KEY_SYNC_PARTICIPANT_ID` (optional; falls back to `HOSTNAME`, then `unknown-participant`)  
  Example: `SSH_KEY_SYNC_PARTICIPANT_ID=node-a`
- `SSH_KEY_SYNC_HTTP_LISTEN_ADDR` (optional; default `0.0.0.0:9922`)  
  Example: `SSH_KEY_SYNC_HTTP_LISTEN_ADDR=0.0.0.0:9922`
- `SSH_KEY_SYNC_UDP_ANNOUNCE_ADDR` (optional; default `0.0.0.0:9923`)  
  Example: `SSH_KEY_SYNC_UDP_ANNOUNCE_ADDR=0.0.0.0:9923`
- `SSH_KEY_SYNC_BOOTSTRAP_PEERS` (optional; comma-separated list)  
  Example: `SSH_KEY_SYNC_BOOTSTRAP_PEERS=node-a@10.0.0.2:9922,node-b@10.0.0.3:9922`
- `SSH_KEY_SYNC_SYNC_INTERVAL_SECS` (optional; default `30`)  
  Example: `SSH_KEY_SYNC_SYNC_INTERVAL_SECS=30`
- `SSH_KEY_SYNC_PUBLIC_KEY_PATH` (optional; default `~/.ssh/id_ed25519.pub`)  
  Example: `SSH_KEY_SYNC_PUBLIC_KEY_PATH=/home/app/.ssh/id_ed25519.pub`
- `SSH_KEY_SYNC_AUTHORIZED_KEYS_PATH` (optional; default `~/.ssh/authorized_keys`)  
  Example: `SSH_KEY_SYNC_AUTHORIZED_KEYS_PATH=/home/app/.ssh/authorized_keys`
- `SSH_KEY_SYNC_TLS_CERT_PATH` (required in TLS mode)  
  Example: `SSH_KEY_SYNC_TLS_CERT_PATH=/etc/ssh-key-sync/certs/node-a.crt`
- `SSH_KEY_SYNC_TLS_KEY_PATH` (required in TLS mode)  
  Example: `SSH_KEY_SYNC_TLS_KEY_PATH=/etc/ssh-key-sync/certs/node-a.key`
- `SSH_KEY_SYNC_TLS_CA_PATH` (required in TLS mode)  
  Example: `SSH_KEY_SYNC_TLS_CA_PATH=/etc/ssh-key-sync/certs/ca.crt`
- `SSH_KEY_SYNC_TLS_SERVER_NAME` (optional; outbound TLS verification override)  
  Example: `SSH_KEY_SYNC_TLS_SERVER_NAME=node-b.internal`
- `SSH_KEY_SYNC_INSECURE_NO_TLS` (optional; `true`/`false`, default `false`)  
  Example: `SSH_KEY_SYNC_INSECURE_NO_TLS=false`
- `SSH_KEY_SYNC_DRY_RUN` (optional; `true`/`false`, default `false`)  
  Example: `SSH_KEY_SYNC_DRY_RUN=true`

Minimal env-based start example:

```bash
export SSH_KEY_SYNC_SID=group-a
export SSH_KEY_SYNC_SID_TOKEN=secret-token
export SSH_KEY_SYNC_PARTICIPANT_ID=node-a
export SSH_KEY_SYNC_BOOTSTRAP_PEERS=node-b@10.0.0.3:9922
export SSH_KEY_SYNC_TLS_CERT_PATH=./certs/node-a.crt
export SSH_KEY_SYNC_TLS_KEY_PATH=./certs/node-a.key
export SSH_KEY_SYNC_TLS_CA_PATH=./certs/ca.crt
ssh-key-sync start
```

Important options:

- `--participant-id`
- `--http-listen-addr`
- `--udp-announce-addr`
- `--bootstrap-peers`
- `--sync-interval-secs`
- `--public-key-path`
- `--authorized-keys-path`
- `--tls-cert-path`
- `--tls-key-path`
- `--tls-ca-path`
- `--tls-server-name`
- `--insecure-no-tls` (dev/test only)
- `--dry-run`

## TLS certificate generation (quick start)

Create a local CA:

```bash
mkdir -p certs
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 \
  -subj "/CN=ssh-key-sync-local-ca" \
  -out certs/ca.crt
```

Create node certificate and key (example for node-a):

```bash
openssl genrsa -out certs/node-a.key 2048
cat > certs/node-a.cnf <<'EOF'
[req]
distinguished_name=req
prompt=no
req_extensions=req_ext
[req_ext]
subjectAltName=DNS:node-a,IP:10.0.0.2
EOF
openssl req -new -key certs/node-a.key -out certs/node-a.csr \
  -subj "/CN=node-a" -config certs/node-a.cnf
openssl x509 -req -in certs/node-a.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/node-a.crt -days 825 -sha256 \
  -extfile certs/node-a.cnf -extensions req_ext
```

Repeat per node with matching SAN entries (DNS/IP that peers use for connection).

## TLS run examples

Start daemon with strict TLS verification:

```bash
ssh-key-sync start \
  --sid group-a \
  --sid-token secret-token \
  --participant-id node-a \
  --http-listen-addr 0.0.0.0:9922 \
  --tls-cert-path ./certs/node-a.crt \
  --tls-key-path ./certs/node-a.key \
  --tls-ca-path ./certs/ca.crt
```

If peer address differs from cert SAN naming, set explicit verification name:

```bash
ssh-key-sync sync \
  --sid group-a \
  --sid-token secret-token \
  --bootstrap-peers node-b@10.0.0.3:9922 \
  --tls-cert-path ./certs/node-a.crt \
  --tls-key-path ./certs/node-a.key \
  --tls-ca-path ./certs/ca.crt \
  --tls-server-name node-b
```

## Insecure mode (dev/test only)

```bash
ssh-key-sync start --sid group-a --sid-token secret-token --insecure-no-tls
```

This mode disables transport encryption and certificate validation. Do not use it in production.

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
