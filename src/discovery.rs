use crate::auth::{EnvelopeVerifier, MessageContext, SignedEnvelope, sign_envelope};
use crate::ssh_keys::normalize_public_key;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub participant_id: String,
    pub address: String,
    pub port: u16,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryAnnouncement {
    pub sid: String,
    pub participant_id: String,
    pub address: String,
    pub port: u16,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    Ignored,
    PeerAdded(String),
    PeerUpdated(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    InvalidAnnouncementPayload,
    InvalidPublicKey,
}

pub struct DiscoveryEngine {
    sid: String,
    sid_token: String,
    verifier: EnvelopeVerifier,
    peers: HashMap<String, PeerRecord>,
    sync_trigger_pending: bool,
}

impl DiscoveryEngine {
    pub fn new(
        sid: impl Into<String>,
        sid_token: impl Into<String>,
        timestamp_skew_secs: u64,
        nonce_ttl_secs: u64,
    ) -> Self {
        let sid = sid.into();
        let sid_token = sid_token.into();
        let verifier = EnvelopeVerifier::new(
            sid_token.clone(),
            sid.clone(),
            timestamp_skew_secs,
            nonce_ttl_secs,
        );
        Self {
            sid,
            sid_token,
            verifier,
            peers: HashMap::new(),
            sync_trigger_pending: false,
        }
    }

    pub fn add_bootstrap_peers(&mut self, bootstrap_peers: &[String]) {
        for peer in bootstrap_peers {
            let parsed = parse_bootstrap_peer(peer);
            let Some((participant_id, address, port)) = parsed else {
                continue;
            };
            let peer_record = PeerRecord {
                participant_id: participant_id.clone(),
                address,
                port,
                public_key: String::new(),
            };
            if self.peers.insert(participant_id, peer_record).is_none() {
                self.sync_trigger_pending = true;
            }
        }
    }

    pub fn build_startup_announcement(
        &self,
        participant_id: &str,
        address: &str,
        port: u16,
        public_key: &str,
        timestamp_secs: u64,
        nonce: &str,
    ) -> Result<SignedEnvelope, DiscoveryError> {
        let public_key =
            normalize_public_key(public_key).map_err(|_| DiscoveryError::InvalidPublicKey)?;
        let body = serialize_payload(&[
            ("sid", self.sid.clone()),
            ("participant_id", participant_id.to_owned()),
            ("address", address.to_owned()),
            ("port", port.to_string()),
            ("public_key", public_key),
        ]);

        Ok(sign_envelope(
            &self.sid,
            &self.sid_token,
            participant_id,
            timestamp_secs,
            nonce,
            MessageContext::UdpAnnouncement,
            &body,
        ))
    }

    pub fn process_announcement(
        &mut self,
        envelope: &SignedEnvelope,
        now_secs: u64,
    ) -> Result<DiscoveryEvent, DiscoveryError> {
        if !matches!(envelope.context, MessageContext::UdpAnnouncement) {
            return Ok(DiscoveryEvent::Ignored);
        }

        if self.verifier.verify(envelope, now_secs).is_err() {
            return Ok(DiscoveryEvent::Ignored);
        }

        let announcement = parse_announcement_payload(&envelope.body)?;
        if announcement.sid != self.sid {
            return Ok(DiscoveryEvent::Ignored);
        }
        if announcement.participant_id.trim().is_empty() {
            return Err(DiscoveryError::InvalidAnnouncementPayload);
        }

        let participant_id = announcement.participant_id.clone();
        let new_record = PeerRecord {
            participant_id: announcement.participant_id,
            address: announcement.address,
            port: announcement.port,
            public_key: announcement.public_key,
        };

        let event = match self.peers.get(&participant_id) {
            None => DiscoveryEvent::PeerAdded(participant_id.clone()),
            Some(existing) if existing == &new_record => DiscoveryEvent::Ignored,
            Some(_) => DiscoveryEvent::PeerUpdated(participant_id.clone()),
        };

        if !matches!(event, DiscoveryEvent::Ignored) {
            self.peers.insert(participant_id, new_record);
            self.sync_trigger_pending = true;
        }

        Ok(event)
    }

    pub fn take_sync_trigger(&mut self) -> bool {
        if self.sync_trigger_pending {
            self.sync_trigger_pending = false;
            true
        } else {
            false
        }
    }

    pub fn peers(&self) -> &HashMap<String, PeerRecord> {
        &self.peers
    }
}

fn parse_bootstrap_peer(value: &str) -> Option<(String, String, u16)> {
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
    let address = address.trim().to_owned();
    if address.is_empty() {
        return None;
    }
    Some((participant_id, address, port))
}

fn parse_announcement_payload(body: &[u8]) -> Result<DiscoveryAnnouncement, DiscoveryError> {
    let payload = parse_payload(body)?;
    let sid = payload
        .get("sid")
        .cloned()
        .ok_or(DiscoveryError::InvalidAnnouncementPayload)?;
    let participant_id = payload
        .get("participant_id")
        .cloned()
        .ok_or(DiscoveryError::InvalidAnnouncementPayload)?;
    let address = payload
        .get("address")
        .cloned()
        .ok_or(DiscoveryError::InvalidAnnouncementPayload)?;
    let port = payload
        .get("port")
        .ok_or(DiscoveryError::InvalidAnnouncementPayload)?
        .parse::<u16>()
        .map_err(|_| DiscoveryError::InvalidAnnouncementPayload)?;
    let public_key = payload
        .get("public_key")
        .cloned()
        .ok_or(DiscoveryError::InvalidAnnouncementPayload)?;
    let public_key =
        normalize_public_key(&public_key).map_err(|_| DiscoveryError::InvalidPublicKey)?;

    if sid.is_empty() || address.is_empty() {
        return Err(DiscoveryError::InvalidAnnouncementPayload);
    }

    Ok(DiscoveryAnnouncement {
        sid,
        participant_id,
        address,
        port,
        public_key,
    })
}

fn serialize_payload(entries: &[(&str, String)]) -> Vec<u8> {
    let mut output = String::new();
    for (key, value) in entries {
        output.push_str(key);
        output.push('=');
        output.push_str(value);
        output.push('\n');
    }
    output.into_bytes()
}

fn parse_payload(body: &[u8]) -> Result<HashMap<String, String>, DiscoveryError> {
    let text = std::str::from_utf8(body).map_err(|_| DiscoveryError::InvalidAnnouncementPayload)?;
    let mut map = HashMap::new();

    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(DiscoveryError::InvalidAnnouncementPayload)?;
        map.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::{DiscoveryEngine, DiscoveryError, DiscoveryEvent};

    #[test]
    fn loads_bootstrap_peers_and_sets_trigger() {
        let mut engine = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        engine.add_bootstrap_peers(&[
            "node-a@10.0.0.2:2222".to_owned(),
            "10.0.0.3:2222".to_owned(),
            "invalid".to_owned(),
        ]);

        assert!(engine.peers().contains_key("node-a"));
        assert!(engine.peers().contains_key("10.0.0.3:2222"));
        assert!(engine.take_sync_trigger());
        assert!(!engine.take_sync_trigger());
    }

    #[test]
    fn accepts_valid_announcement_and_adds_peer() {
        let mut receiver = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let sender = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let envelope = sender
            .build_startup_announcement(
                "node-b",
                "10.0.0.5",
                2222,
                "ssh-ed25519 AAAAB3Nza node-b",
                1_700_000_000,
                "n-1",
            )
            .expect("announcement should be built");

        let event = receiver
            .process_announcement(&envelope, 1_700_000_010)
            .expect("announcement should process");
        assert_eq!(event, DiscoveryEvent::PeerAdded("node-b".to_owned()));
        assert!(receiver.peers().contains_key("node-b"));
        assert!(receiver.take_sync_trigger());
    }

    #[test]
    fn ignores_announcement_with_wrong_sid_token() {
        let mut receiver = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let sender = DiscoveryEngine::new("group-a", "wrong-token", 60, 120);
        let envelope = sender
            .build_startup_announcement(
                "node-b",
                "10.0.0.5",
                2222,
                "ssh-ed25519 AAAAB3Nza node-b",
                1_700_000_000,
                "n-1",
            )
            .expect("announcement should be built");

        let event = receiver
            .process_announcement(&envelope, 1_700_000_010)
            .expect("processing should not fail");
        assert_eq!(event, DiscoveryEvent::Ignored);
        assert!(!receiver.peers().contains_key("node-b"));
        assert!(!receiver.take_sync_trigger());
    }

    #[test]
    fn ignores_announcement_with_other_sid() {
        let mut receiver = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let sender = DiscoveryEngine::new("group-b", "secret-token", 60, 120);
        let envelope = sender
            .build_startup_announcement(
                "node-b",
                "10.0.0.5",
                2222,
                "ssh-ed25519 AAAAB3Nza node-b",
                1_700_000_000,
                "n-1",
            )
            .expect("announcement should be built");

        let event = receiver
            .process_announcement(&envelope, 1_700_000_010)
            .expect("processing should not fail");
        assert_eq!(event, DiscoveryEvent::Ignored);
    }

    #[test]
    fn rejects_malformed_payload() {
        let mut receiver = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let sender = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let mut envelope = sender
            .build_startup_announcement(
                "node-b",
                "10.0.0.5",
                2222,
                "ssh-ed25519 AAAAB3Nza node-b",
                1_700_000_000,
                "n-1",
            )
            .expect("announcement should be built");
        envelope.body =
            b"sid=group-a\nparticipant_id=node-b\naddress=10.0.0.5\nport=bad\n".to_vec();
        envelope.signature_hex = crate::auth::sign_envelope(
            "group-a",
            "secret-token",
            "node-b",
            envelope.timestamp_secs,
            &envelope.nonce,
            crate::auth::MessageContext::UdpAnnouncement,
            &envelope.body,
        )
        .signature_hex;

        let event = receiver.process_announcement(&envelope, 1_700_000_010);
        assert_eq!(event, Err(DiscoveryError::InvalidAnnouncementPayload));
    }

    #[test]
    fn updates_existing_peer_and_triggers_sync() {
        let mut receiver = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let sender = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let first = sender
            .build_startup_announcement(
                "node-b",
                "10.0.0.5",
                2222,
                "ssh-ed25519 AAAAB3Nza node-b",
                1_700_000_000,
                "n-1",
            )
            .expect("announcement should be built");
        let second = sender
            .build_startup_announcement(
                "node-b",
                "10.0.0.6",
                2222,
                "ssh-ed25519 AAAAB3Nza node-b",
                1_700_000_001,
                "n-2",
            )
            .expect("announcement should be built");

        assert_eq!(
            receiver
                .process_announcement(&first, 1_700_000_005)
                .expect("first should process"),
            DiscoveryEvent::PeerAdded("node-b".to_owned())
        );
        assert!(receiver.take_sync_trigger());
        assert_eq!(
            receiver
                .process_announcement(&second, 1_700_000_006)
                .expect("second should process"),
            DiscoveryEvent::PeerUpdated("node-b".to_owned())
        );
        assert!(receiver.take_sync_trigger());
    }

    #[test]
    fn ignores_replayed_nonce() {
        let mut receiver = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let sender = DiscoveryEngine::new("group-a", "secret-token", 60, 120);
        let envelope = sender
            .build_startup_announcement(
                "node-b",
                "10.0.0.5",
                2222,
                "ssh-ed25519 AAAAB3Nza node-b",
                1_700_000_000,
                "n-replay",
            )
            .expect("announcement should be built");

        assert_eq!(
            receiver
                .process_announcement(&envelope, 1_700_000_005)
                .expect("first should process"),
            DiscoveryEvent::PeerAdded("node-b".to_owned())
        );
        assert_eq!(
            receiver
                .process_announcement(&envelope, 1_700_000_006)
                .expect("second should process"),
            DiscoveryEvent::Ignored
        );
    }
}
