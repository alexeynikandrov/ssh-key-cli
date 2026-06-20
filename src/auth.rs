use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageContext {
    HttpRequest { method: String, path: String },
    HttpResponse { status_code: u16, path: String },
    UdpAnnouncement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub sid: String,
    pub sender_id: String,
    pub timestamp_secs: u64,
    pub nonce: String,
    pub context: MessageContext,
    pub body: Vec<u8>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    SidMismatch,
    InvalidSignatureEncoding,
    InvalidSignature,
    TimestampOutsideWindow,
    ReplayNonce,
}

pub fn sign_envelope(
    sid: &str,
    sid_token: &str,
    sender_id: &str,
    timestamp_secs: u64,
    nonce: &str,
    context: MessageContext,
    body: &[u8],
) -> SignedEnvelope {
    let canonical = canonical_payload(sid, sender_id, timestamp_secs, nonce, &context, body);
    let signature_hex = hmac_signature_hex(sid_token, canonical.as_bytes());

    SignedEnvelope {
        sid: sid.to_owned(),
        sender_id: sender_id.to_owned(),
        timestamp_secs,
        nonce: nonce.to_owned(),
        context,
        body: body.to_vec(),
        signature_hex,
    }
}

pub fn verify_envelope(
    envelope: &SignedEnvelope,
    sid_token: &str,
    expected_sid: &str,
) -> Result<(), AuthError> {
    if envelope.sid != expected_sid {
        return Err(AuthError::SidMismatch);
    }

    let signature =
        decode_hex(&envelope.signature_hex).ok_or(AuthError::InvalidSignatureEncoding)?;
    let canonical = canonical_payload(
        &envelope.sid,
        &envelope.sender_id,
        envelope.timestamp_secs,
        &envelope.nonce,
        &envelope.context,
        &envelope.body,
    );

    let mut mac = HmacSha256::new_from_slice(sid_token.as_bytes())
        .expect("HMAC accepts secret keys of any size");
    mac.update(canonical.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| AuthError::InvalidSignature)
}

pub struct EnvelopeVerifier {
    sid_token: String,
    expected_sid: String,
    timestamp_skew_secs: u64,
    nonce_ttl_secs: u64,
    seen_nonces: HashMap<String, u64>,
}

impl EnvelopeVerifier {
    pub fn new(
        sid_token: impl Into<String>,
        expected_sid: impl Into<String>,
        timestamp_skew_secs: u64,
        nonce_ttl_secs: u64,
    ) -> Self {
        Self {
            sid_token: sid_token.into(),
            expected_sid: expected_sid.into(),
            timestamp_skew_secs,
            nonce_ttl_secs,
            seen_nonces: HashMap::new(),
        }
    }

    pub fn verify(&mut self, envelope: &SignedEnvelope, now_secs: u64) -> Result<(), AuthError> {
        verify_envelope(envelope, &self.sid_token, &self.expected_sid)?;

        let earliest = now_secs.saturating_sub(self.timestamp_skew_secs);
        let latest = now_secs.saturating_add(self.timestamp_skew_secs);
        if envelope.timestamp_secs < earliest || envelope.timestamp_secs > latest {
            return Err(AuthError::TimestampOutsideWindow);
        }

        self.prune_nonces(now_secs);
        let nonce_key = format!("{}:{}", envelope.sender_id, envelope.nonce);
        if self.seen_nonces.contains_key(&nonce_key) {
            return Err(AuthError::ReplayNonce);
        }
        self.seen_nonces.insert(nonce_key, now_secs);
        Ok(())
    }

    fn prune_nonces(&mut self, now_secs: u64) {
        let nonce_ttl_secs = self.nonce_ttl_secs;
        self.seen_nonces
            .retain(|_, seen_at| now_secs.saturating_sub(*seen_at) <= nonce_ttl_secs);
    }
}

fn canonical_payload(
    sid: &str,
    sender_id: &str,
    timestamp_secs: u64,
    nonce: &str,
    context: &MessageContext,
    body: &[u8],
) -> String {
    let context_value = canonical_context(context);
    let body_hash = hash_body_hex(body);
    format!("{sid}\n{sender_id}\n{timestamp_secs}\n{nonce}\n{context_value}\n{body_hash}")
}

fn canonical_context(context: &MessageContext) -> String {
    match context {
        MessageContext::HttpRequest { method, path } => {
            format!("http_request:{}:{}", method.to_uppercase(), path)
        }
        MessageContext::HttpResponse { status_code, path } => {
            format!("http_response:{}:{}", status_code, path)
        }
        MessageContext::UdpAnnouncement => "udp_announcement".to_owned(),
    }
}

fn hash_body_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let digest = hasher.finalize();
    encode_hex(&digest)
}

fn hmac_signature_hex(sid_token: &str, payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(sid_token.as_bytes()).expect("HMAC accepts keys of any size");
    mac.update(payload);
    let signature = mac.finalize().into_bytes();
    encode_hex(&signature)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        output.push(HEX[(b >> 4) as usize] as char);
        output.push(HEX[(b & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars: Vec<char> = value.chars().collect();
    for index in (0..chars.len()).step_by(2) {
        let high = decode_nibble(chars[index])?;
        let low = decode_nibble(chars[index + 1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn decode_nibble(value: char) -> Option<u8> {
    match value {
        '0'..='9' => Some(value as u8 - b'0'),
        'a'..='f' => Some(value as u8 - b'a' + 10),
        'A'..='F' => Some(value as u8 - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthError, EnvelopeVerifier, MessageContext, sign_envelope, verify_envelope};

    #[test]
    fn signs_and_verifies_envelope() {
        let envelope = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::UdpAnnouncement,
            b"{\"addr\":\"10.0.0.2\"}",
        );

        let result = verify_envelope(&envelope, "secret-token", "group-a");
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rejects_sid_mismatch() {
        let envelope = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::UdpAnnouncement,
            b"payload",
        );

        let result = verify_envelope(&envelope, "secret-token", "group-b");
        assert_eq!(result, Err(AuthError::SidMismatch));
    }

    #[test]
    fn rejects_tampered_body() {
        let mut envelope = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::UdpAnnouncement,
            b"payload",
        );
        envelope.body = b"modified".to_vec();

        let result = verify_envelope(&envelope, "secret-token", "group-a");
        assert_eq!(result, Err(AuthError::InvalidSignature));
    }

    #[test]
    fn rejects_invalid_signature_encoding() {
        let mut envelope = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::UdpAnnouncement,
            b"payload",
        );
        envelope.signature_hex = "not-hex".to_owned();

        let result = verify_envelope(&envelope, "secret-token", "group-a");
        assert_eq!(result, Err(AuthError::InvalidSignatureEncoding));
    }

    #[test]
    fn canonical_signature_is_stable_for_same_payload() {
        let first = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::HttpRequest {
                method: "POST".to_owned(),
                path: "/v1/keys".to_owned(),
            },
            b"payload",
        );
        let second = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::HttpRequest {
                method: "POST".to_owned(),
                path: "/v1/keys".to_owned(),
            },
            b"payload",
        );

        assert_eq!(first.signature_hex, second.signature_hex);
    }

    #[test]
    fn different_contexts_produce_different_signatures() {
        let request = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::HttpRequest {
                method: "GET".to_owned(),
                path: "/v1/keys".to_owned(),
            },
            b"payload",
        );
        let response = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::HttpResponse {
                status_code: 200,
                path: "/v1/keys".to_owned(),
            },
            b"payload",
        );
        let announcement = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_781_771_000,
            "nonce-1",
            MessageContext::UdpAnnouncement,
            b"payload",
        );

        assert_ne!(request.signature_hex, response.signature_hex);
        assert_ne!(request.signature_hex, announcement.signature_hex);
        assert_ne!(response.signature_hex, announcement.signature_hex);
    }

    #[test]
    fn verifier_rejects_outside_timestamp_window() {
        let mut verifier = EnvelopeVerifier::new("secret-token", "group-a", 30, 120);
        let envelope = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_000,
            "nonce-1",
            MessageContext::UdpAnnouncement,
            b"payload",
        );

        let result = verifier.verify(&envelope, 2_000);
        assert_eq!(result, Err(AuthError::TimestampOutsideWindow));
    }

    #[test]
    fn verifier_rejects_replayed_nonce_inside_ttl() {
        let mut verifier = EnvelopeVerifier::new("secret-token", "group-a", 30, 120);
        let envelope = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_000,
            "nonce-1",
            MessageContext::UdpAnnouncement,
            b"payload",
        );

        let first = verifier.verify(&envelope, 1_005);
        let second = verifier.verify(&envelope, 1_010);

        assert_eq!(first, Ok(()));
        assert_eq!(second, Err(AuthError::ReplayNonce));
    }

    #[test]
    fn verifier_accepts_same_nonce_after_ttl_expiry() {
        let mut verifier = EnvelopeVerifier::new("secret-token", "group-a", 300, 5);
        let envelope = sign_envelope(
            "group-a",
            "secret-token",
            "node-1",
            1_000,
            "nonce-1",
            MessageContext::UdpAnnouncement,
            b"payload",
        );

        let first = verifier.verify(&envelope, 1_002);
        let second = verifier.verify(&envelope, 1_010);

        assert_eq!(first, Ok(()));
        assert_eq!(second, Ok(()));
    }
}
