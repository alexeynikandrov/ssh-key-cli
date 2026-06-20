use crate::auth::{AuthError, MessageContext, SignedEnvelope, sign_envelope, verify_envelope};
use crate::ssh_keys::normalize_public_key;
use std::collections::HashMap;

pub const PATH_GET_PUBLIC_KEY: &str = "/v1/keys/get";
pub const PATH_PUBLISH_PARTICIPANT: &str = "/v1/participants/publish";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchangeHttpRequest {
    pub path: String,
    pub sender_id: String,
    pub timestamp_secs: u64,
    pub nonce: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchangeHttpResponse {
    pub path: String,
    pub status_code: u16,
    pub sender_id: String,
    pub timestamp_secs: u64,
    pub nonce: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyPayload {
    pub sid: String,
    pub participant_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantPublishPayload {
    pub participant_id: String,
    pub address: String,
    pub port: u16,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Auth(AuthError),
    UnexpectedContext,
    InvalidPayload,
    MissingPayloadField(&'static str),
}

impl From<AuthError> for TransportError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpKeyExchangeService {
    sid: String,
    sid_token: String,
    participant_id: String,
    public_key: String,
}

impl HttpKeyExchangeService {
    pub fn new(
        sid: impl Into<String>,
        sid_token: impl Into<String>,
        participant_id: impl Into<String>,
        public_key: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let public_key =
            normalize_public_key(&public_key.into()).map_err(|_| TransportError::InvalidPayload)?;
        Ok(Self {
            sid: sid.into(),
            sid_token: sid_token.into(),
            participant_id: participant_id.into(),
            public_key,
        })
    }

    pub fn build_get_public_key_request(
        &self,
        sender_id: &str,
        timestamp_secs: u64,
        nonce: &str,
    ) -> SignedEnvelope {
        let request = KeyExchangeHttpRequest {
            path: PATH_GET_PUBLIC_KEY.to_owned(),
            sender_id: sender_id.to_owned(),
            timestamp_secs,
            nonce: nonce.to_owned(),
            body: serialize_payload(&[("request", "public_key".to_owned())]),
        };
        sign_http_request(&self.sid, &self.sid_token, &request)
    }

    pub fn handle_get_public_key_request(
        &self,
        request_envelope: &SignedEnvelope,
        response_timestamp_secs: u64,
        response_nonce: &str,
    ) -> Result<SignedEnvelope, TransportError> {
        verify_http_request(request_envelope, &self.sid_token, &self.sid)?;
        expect_http_request_context(request_envelope, "POST", PATH_GET_PUBLIC_KEY)?;

        let body = serialize_payload(&[
            ("sid", self.sid.clone()),
            ("participant_id", self.participant_id.clone()),
            ("public_key", self.public_key.clone()),
        ]);
        let response = KeyExchangeHttpResponse {
            path: PATH_GET_PUBLIC_KEY.to_owned(),
            status_code: 200,
            sender_id: self.participant_id.clone(),
            timestamp_secs: response_timestamp_secs,
            nonce: response_nonce.to_owned(),
            body,
        };
        Ok(sign_http_response(&self.sid, &self.sid_token, &response))
    }

    pub fn verify_and_parse_public_key_response(
        &self,
        envelope: &SignedEnvelope,
    ) -> Result<PublicKeyPayload, TransportError> {
        verify_http_response(envelope, &self.sid_token, &self.sid)?;
        expect_http_response_context(envelope, 200, PATH_GET_PUBLIC_KEY)?;

        let payload = parse_payload(&envelope.body)?;
        let sid = get_required(&payload, "sid")?;
        let participant_id = get_required(&payload, "participant_id")?;
        let public_key = normalize_public_key(&get_required(&payload, "public_key")?)
            .map_err(|_| TransportError::InvalidPayload)?;

        Ok(PublicKeyPayload {
            sid,
            participant_id,
            public_key,
        })
    }

    pub fn build_publish_request(
        &self,
        sender_id: &str,
        timestamp_secs: u64,
        nonce: &str,
        payload: &ParticipantPublishPayload,
    ) -> SignedEnvelope {
        let body = serialize_payload(&[
            ("participant_id", payload.participant_id.clone()),
            ("address", payload.address.clone()),
            ("port", payload.port.to_string()),
            ("public_key", payload.public_key.clone()),
        ]);
        let request = KeyExchangeHttpRequest {
            path: PATH_PUBLISH_PARTICIPANT.to_owned(),
            sender_id: sender_id.to_owned(),
            timestamp_secs,
            nonce: nonce.to_owned(),
            body,
        };
        sign_http_request(&self.sid, &self.sid_token, &request)
    }

    pub fn handle_publish_request(
        &self,
        request_envelope: &SignedEnvelope,
        response_timestamp_secs: u64,
        response_nonce: &str,
    ) -> Result<SignedEnvelope, TransportError> {
        verify_http_request(request_envelope, &self.sid_token, &self.sid)?;
        expect_http_request_context(request_envelope, "POST", PATH_PUBLISH_PARTICIPANT)?;
        let payload = parse_publish_request(&request_envelope.body)?;
        let _ = normalize_public_key(&payload.public_key)
            .map_err(|_| TransportError::InvalidPayload)?;

        let body = serialize_payload(&[
            ("status", "accepted".to_owned()),
            ("participant_id", payload.participant_id),
        ]);
        let response = KeyExchangeHttpResponse {
            path: PATH_PUBLISH_PARTICIPANT.to_owned(),
            status_code: 202,
            sender_id: self.participant_id.clone(),
            timestamp_secs: response_timestamp_secs,
            nonce: response_nonce.to_owned(),
            body,
        };
        Ok(sign_http_response(&self.sid, &self.sid_token, &response))
    }
}

pub fn sign_http_request(
    sid: &str,
    sid_token: &str,
    request: &KeyExchangeHttpRequest,
) -> SignedEnvelope {
    sign_envelope(
        sid,
        sid_token,
        &request.sender_id,
        request.timestamp_secs,
        &request.nonce,
        MessageContext::HttpRequest {
            method: "POST".to_owned(),
            path: request.path.clone(),
        },
        &request.body,
    )
}

pub fn sign_http_response(
    sid: &str,
    sid_token: &str,
    response: &KeyExchangeHttpResponse,
) -> SignedEnvelope {
    sign_envelope(
        sid,
        sid_token,
        &response.sender_id,
        response.timestamp_secs,
        &response.nonce,
        MessageContext::HttpResponse {
            status_code: response.status_code,
            path: response.path.clone(),
        },
        &response.body,
    )
}

pub fn verify_http_request(
    envelope: &SignedEnvelope,
    sid_token: &str,
    expected_sid: &str,
) -> Result<(), AuthError> {
    verify_envelope(envelope, sid_token, expected_sid)
}

pub fn verify_http_response(
    envelope: &SignedEnvelope,
    sid_token: &str,
    expected_sid: &str,
) -> Result<(), AuthError> {
    verify_envelope(envelope, sid_token, expected_sid)
}

fn expect_http_request_context(
    envelope: &SignedEnvelope,
    expected_method: &str,
    expected_path: &str,
) -> Result<(), TransportError> {
    match &envelope.context {
        MessageContext::HttpRequest { method, path }
            if method.eq_ignore_ascii_case(expected_method) && path == expected_path =>
        {
            Ok(())
        }
        _ => Err(TransportError::UnexpectedContext),
    }
}

fn expect_http_response_context(
    envelope: &SignedEnvelope,
    expected_status: u16,
    expected_path: &str,
) -> Result<(), TransportError> {
    match &envelope.context {
        MessageContext::HttpResponse { status_code, path }
            if *status_code == expected_status && path == expected_path =>
        {
            Ok(())
        }
        _ => Err(TransportError::UnexpectedContext),
    }
}

fn parse_publish_request(body: &[u8]) -> Result<ParticipantPublishPayload, TransportError> {
    let payload = parse_payload(body)?;
    let participant_id = get_required(&payload, "participant_id")?;
    let address = get_required(&payload, "address")?;
    let port = get_required(&payload, "port")?
        .parse::<u16>()
        .map_err(|_| TransportError::InvalidPayload)?;
    let public_key = get_required(&payload, "public_key")?;

    Ok(ParticipantPublishPayload {
        participant_id,
        address,
        port,
        public_key,
    })
}

fn get_required(
    payload: &HashMap<String, String>,
    field: &'static str,
) -> Result<String, TransportError> {
    payload
        .get(field)
        .cloned()
        .ok_or(TransportError::MissingPayloadField(field))
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

fn parse_payload(body: &[u8]) -> Result<HashMap<String, String>, TransportError> {
    let text = std::str::from_utf8(body).map_err(|_| TransportError::InvalidPayload)?;
    let mut map = HashMap::new();

    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(TransportError::InvalidPayload)?;
        map.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::{
        HttpKeyExchangeService, KeyExchangeHttpRequest, KeyExchangeHttpResponse,
        PATH_GET_PUBLIC_KEY, PATH_PUBLISH_PARTICIPANT, ParticipantPublishPayload,
        sign_http_request, sign_http_response, verify_http_request, verify_http_response,
    };
    use crate::auth::AuthError;

    #[test]
    fn signs_and_verifies_http_request_envelope() {
        let request = KeyExchangeHttpRequest {
            path: "/v1/keys".to_owned(),
            sender_id: "node-a".to_owned(),
            timestamp_secs: 1_781_771_234,
            nonce: "req-1".to_owned(),
            body: br#"public_key=ssh-ed25519 AAAA node-a"#.to_vec(),
        };
        let envelope = sign_http_request("group-a", "secret-token", &request);

        let verified = verify_http_request(&envelope, "secret-token", "group-a");
        assert_eq!(verified, Ok(()));
    }

    #[test]
    fn signs_and_verifies_http_response_envelope() {
        let response = KeyExchangeHttpResponse {
            path: "/v1/keys".to_owned(),
            status_code: 200,
            sender_id: "node-b".to_owned(),
            timestamp_secs: 1_781_771_240,
            nonce: "res-1".to_owned(),
            body: br#"public_key=ssh-ed25519 BBBB node-b"#.to_vec(),
        };
        let envelope = sign_http_response("group-a", "secret-token", &response);

        let verified = verify_http_response(&envelope, "secret-token", "group-a");
        assert_eq!(verified, Ok(()));
    }

    #[test]
    fn rejects_http_request_with_wrong_sid_token() {
        let request = KeyExchangeHttpRequest {
            path: "/v1/keys".to_owned(),
            sender_id: "node-a".to_owned(),
            timestamp_secs: 1_781_771_234,
            nonce: "req-1".to_owned(),
            body: br#"public_key=ssh-ed25519 AAAA node-a"#.to_vec(),
        };
        let envelope = sign_http_request("group-a", "secret-token", &request);

        let verified = verify_http_request(&envelope, "wrong-token", "group-a");
        assert_eq!(verified, Err(AuthError::InvalidSignature));
    }

    #[test]
    fn handles_get_public_key_request_and_response_without_secret_leak() {
        let service = HttpKeyExchangeService::new(
            "group-a",
            "secret-token",
            "node-local",
            "ssh-ed25519 AAAA node-local",
        )
        .expect("service should initialize");
        let request = service.build_get_public_key_request("node-remote", 1_700_000_000, "req-1");
        let response = service
            .handle_get_public_key_request(&request, 1_700_000_001, "res-1")
            .expect("request should be handled");

        let payload = service
            .verify_and_parse_public_key_response(&response)
            .expect("response should parse");

        assert_eq!(payload.sid, "group-a");
        assert_eq!(payload.participant_id, "node-local");
        assert_eq!(payload.public_key, "ssh-ed25519 AAAA node-local");
        let body_text = String::from_utf8(response.body).expect("response body should be utf-8");
        assert!(!body_text.contains("secret-token"));
    }

    #[test]
    fn handles_publish_request_with_valid_key() {
        let service = HttpKeyExchangeService::new(
            "group-a",
            "secret-token",
            "node-local",
            "ssh-ed25519 AAAA node-local",
        )
        .expect("service should initialize");
        let request = service.build_publish_request(
            "node-remote",
            1_700_000_010,
            "pub-1",
            &ParticipantPublishPayload {
                participant_id: "node-remote".to_owned(),
                address: "10.0.0.5".to_owned(),
                port: 2222,
                public_key: "ssh-ed25519 BBBB node-remote".to_owned(),
            },
        );

        let response = service
            .handle_publish_request(&request, 1_700_000_011, "ack-1")
            .expect("publish request should be handled");
        let verified = verify_http_response(&response, "secret-token", "group-a");
        assert_eq!(verified, Ok(()));
        assert!(matches!(
            response.context,
            crate::auth::MessageContext::HttpResponse {
                status_code: 202,
                ref path
            } if path == PATH_PUBLISH_PARTICIPANT
        ));
    }

    #[test]
    fn rejects_publish_request_with_invalid_public_key() {
        let service = HttpKeyExchangeService::new(
            "group-a",
            "secret-token",
            "node-local",
            "ssh-ed25519 AAAA node-local",
        )
        .expect("service should initialize");
        let request = service.build_publish_request(
            "node-remote",
            1_700_000_010,
            "pub-1",
            &ParticipantPublishPayload {
                participant_id: "node-remote".to_owned(),
                address: "10.0.0.5".to_owned(),
                port: 2222,
                public_key: "invalid".to_owned(),
            },
        );

        let response = service.handle_publish_request(&request, 1_700_000_011, "ack-1");
        assert_eq!(response, Err(super::TransportError::InvalidPayload));
    }

    #[test]
    fn rejects_get_public_key_request_with_wrong_context_path() {
        let service = HttpKeyExchangeService::new(
            "group-a",
            "secret-token",
            "node-local",
            "ssh-ed25519 AAAA node-local",
        )
        .expect("service should initialize");

        let request = KeyExchangeHttpRequest {
            path: "/v1/other".to_owned(),
            sender_id: "node-remote".to_owned(),
            timestamp_secs: 1_700_000_000,
            nonce: "req-1".to_owned(),
            body: br#"request=public_key"#.to_vec(),
        };
        let envelope = sign_http_request("group-a", "secret-token", &request);

        let response = service.handle_get_public_key_request(&envelope, 1_700_000_001, "res-1");
        assert_eq!(response, Err(super::TransportError::UnexpectedContext));

        let _ = PATH_GET_PUBLIC_KEY;
    }
}
