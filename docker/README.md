# Docker local test (2 containers)

This guide shows a manual smoke-test flow with two containers in one Docker network.

## 1. Build image and binary

From repository root:

```bash
docker build -f docker/Dockerfile -t ssh-key-sync-sshd:test .
make build
```

## 2. Create network and run two containers

```bash
docker network create ssh-sync-net

docker run -d --name node-a --network ssh-sync-net ssh-key-sync-sshd:test
docker run -d --name node-b --network ssh-sync-net ssh-key-sync-sshd:test
```

## 3. Copy `ssh-key-sync` binary into containers

```bash
docker cp target/release/ssh-key-sync node-a:/usr/local/bin/ssh-key-sync
docker cp target/release/ssh-key-sync node-b:/usr/local/bin/ssh-key-sync
```

## 4. Generate SSH keys in each container

Open shell:

```bash
docker exec -it node-a bash
```

Inside `node-a`:

```bash
mkdir -p ~/.ssh
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
exit
```

Repeat for `node-b`:

```bash
docker exec -it node-b bash
mkdir -p ~/.ssh
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
exit
```

## 5. Run `ssh-key-sync` in both containers

Use same `SID` and `SID_TOKEN`. Start one daemon in each container and point
bootstrap peers to the **HTTP exchange port** (`9922` in this example):

```bash
docker exec -it node-a bash -lc \
  'ssh-key-sync --sid group-a --sid-token token-a --participant-id node-a --http-listen-addr 0.0.0.0:9922 --udp-announce-addr 0.0.0.0:9923 --bootstrap-peers node-b@node-b:9922 --public-key-path /root/.ssh/id_ed25519.pub --authorized-keys-path /root/.ssh/authorized_keys start'

docker exec -it node-b bash -lc \
  'ssh-key-sync --sid group-a --sid-token token-a --participant-id node-b --http-listen-addr 0.0.0.0:9922 --udp-announce-addr 0.0.0.0:9923 --bootstrap-peers node-a@node-a:9922 --public-key-path /root/.ssh/id_ed25519.pub --authorized-keys-path /root/.ssh/authorized_keys start'
```

## 6. Optional checks

Container connectivity:

```bash
docker exec node-a bash -lc "ping -c 1 node-b"
docker exec node-b bash -lc "ping -c 1 node-a"
```

SSH daemon config:

```bash
docker exec node-a bash -lc "sshd -T | grep -E 'pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication'"
docker exec node-b bash -lc "sshd -T | grep -E 'pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication'"
```

Managed keys block:

```bash
docker exec node-a bash -lc "cat /root/.ssh/authorized_keys"
docker exec node-b bash -lc "cat /root/.ssh/authorized_keys"
```

## 7. Cleanup

```bash
docker rm -f node-a node-b
docker network rm ssh-sync-net
```