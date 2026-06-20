#[cfg(test)]
mod tests {
    use crate::authorized_keys::upsert_managed_block;
    use crate::discovery::{DiscoveryEngine, DiscoveryEvent};
    use crate::transport::{HttpKeyExchangeService, ParticipantPublishPayload};

    #[test]
    fn two_participants_exchange_public_keys() {
        let node_a =
            HttpKeyExchangeService::new("group-a", "token-a", "node-a", "ssh-ed25519 AAAA node-a")
                .expect("node-a service should initialize");
        let node_b =
            HttpKeyExchangeService::new("group-a", "token-a", "node-b", "ssh-ed25519 BBBB node-b")
                .expect("node-b service should initialize");

        let request = node_a.build_get_public_key_request("node-a", 1_700_001_000, "req-1");
        let response = node_b
            .handle_get_public_key_request(&request, 1_700_001_001, "res-1")
            .expect("node-b should serve key");
        let payload = node_a
            .verify_and_parse_public_key_response(&response)
            .expect("node-a should parse response");

        assert_eq!(payload.participant_id, "node-b");
        assert_eq!(payload.public_key, "ssh-ed25519 BBBB node-b");
    }

    #[test]
    fn late_joiner_triggers_discovery_sync() {
        let mut node_a = DiscoveryEngine::new("group-a", "token-a", 60, 120);
        node_a.add_bootstrap_peers(&["node-b@10.0.0.2:2222".to_owned()]);
        assert!(node_a.take_sync_trigger());

        let node_c = DiscoveryEngine::new("group-a", "token-a", 60, 120);
        let announcement = node_c
            .build_startup_announcement(
                "node-c",
                "10.0.0.3",
                2222,
                "ssh-ed25519 CCCC node-c",
                1_700_001_100,
                "late-1",
            )
            .expect("announcement should be built");

        let event = node_a
            .process_announcement(&announcement, 1_700_001_101)
            .expect("announcement should be processed");
        assert_eq!(event, DiscoveryEvent::PeerAdded("node-c".to_owned()));
        assert!(node_a.take_sync_trigger());
    }

    #[test]
    fn isolation_by_sid_and_sid_token() {
        let mut receiver = DiscoveryEngine::new("group-a", "token-a", 60, 120);

        let wrong_sid_sender = DiscoveryEngine::new("group-b", "token-a", 60, 120);
        let wrong_sid = wrong_sid_sender
            .build_startup_announcement(
                "node-x",
                "10.0.0.9",
                2222,
                "ssh-ed25519 XXXX node-x",
                1_700_001_200,
                "sid-1",
            )
            .expect("announcement should be built");
        let sid_event = receiver
            .process_announcement(&wrong_sid, 1_700_001_201)
            .expect("processing should not fail");
        assert_eq!(sid_event, DiscoveryEvent::Ignored);

        let wrong_token_sender = DiscoveryEngine::new("group-a", "token-b", 60, 120);
        let wrong_token = wrong_token_sender
            .build_startup_announcement(
                "node-y",
                "10.0.0.10",
                2222,
                "ssh-ed25519 YYYY node-y",
                1_700_001_210,
                "tok-1",
            )
            .expect("announcement should be built");
        let token_event = receiver
            .process_announcement(&wrong_token, 1_700_001_211)
            .expect("processing should not fail");
        assert_eq!(token_event, DiscoveryEvent::Ignored);
    }

    #[test]
    fn idempotent_authorized_keys_on_restart() {
        let initial = "ssh-ed25519 LOCAL local\n";
        let managed = vec![
            "ssh-ed25519 AAAA node-a".to_owned(),
            "ssh-ed25519 BBBB node-b".to_owned(),
        ];

        let first = upsert_managed_block(initial, &managed).expect("first apply should work");
        let second = upsert_managed_block(&first, &managed).expect("second apply should work");

        assert_eq!(first, second);
    }

    #[test]
    fn publish_flow_accepts_valid_remote_participant() {
        let node_a =
            HttpKeyExchangeService::new("group-a", "token-a", "node-a", "ssh-ed25519 AAAA node-a")
                .expect("node-a service should initialize");
        let node_b =
            HttpKeyExchangeService::new("group-a", "token-a", "node-b", "ssh-ed25519 BBBB node-b")
                .expect("node-b service should initialize");

        let publish_request = node_a.build_publish_request(
            "node-a",
            1_700_001_300,
            "pub-1",
            &ParticipantPublishPayload {
                participant_id: "node-a".to_owned(),
                address: "10.0.0.11".to_owned(),
                port: 2222,
                public_key: "ssh-ed25519 AAAA node-a".to_owned(),
            },
        );
        let response = node_b
            .handle_publish_request(&publish_request, 1_700_001_301, "ack-1")
            .expect("publish should be accepted");

        let payload = node_a
            .verify_and_parse_public_key_response(
                &node_b
                    .handle_get_public_key_request(
                        &node_a.build_get_public_key_request("node-a", 1_700_001_302, "req-2"),
                        1_700_001_303,
                        "res-2",
                    )
                    .expect("get should be handled"),
            )
            .expect("get response should parse");
        assert_eq!(payload.participant_id, "node-b");
        assert!(matches!(
            response.context,
            crate::auth::MessageContext::HttpResponse {
                status_code: 202,
                ref path
            } if path == "/v1/participants/publish"
        ));
    }
}
