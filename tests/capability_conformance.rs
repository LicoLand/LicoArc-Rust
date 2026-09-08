use std::collections::BTreeMap;

use licoarc::{
    ErrorCode,
    encoding::CborValue,
    governance::{
        self, Adoption, Authorization, ConsistencyObservation, GovernanceCandidate,
        GovernanceState, RecoveryEvent, Role,
    },
    group::{
        self, AggregateOutcome, GroupResult, GroupState, MAX_GROUP_MEMBERS, Member, MemberRole,
        ResultAuthority, ResultOutcome,
    },
    identity,
    messaging::{self, Message, MessageKind},
    provider::RustCryptoProvider,
    reliable,
    transport::{self, Operation},
};
use serde_json::json;

#[test]
fn opaque_message_round_trips_exact_bytes() {
    let message = Message {
        id: [1; 16],
        kind: MessageKind::Request,
        relates_to: None,
        content_type: 42,
        payload: vec![0, 1, 2, 254, 255],
        extensions: Default::default(),
        critical: vec![],
        chunk_index: None,
        chunk_final: None,
        attachment_id: None,
        attachments: vec![],
    };
    let bytes = message.encode().unwrap();
    assert_eq!(Message::decode(&bytes).unwrap(), message);
}

#[test]
fn stream_chunk_requires_exactly_one_terminal_form() {
    let message = Message {
        id: [1; 16],
        kind: MessageKind::StreamChunk,
        relates_to: Some([2; 16]),
        content_type: 42,
        payload: vec![],
        extensions: Default::default(),
        critical: vec![],
        chunk_index: Some(0),
        chunk_final: None,
        attachment_id: None,
        attachments: vec![],
    };
    assert_eq!(
        message.validate().unwrap_err().code,
        ErrorCode::InvalidTransition
    );
}

#[test]
fn receive_state_requires_verified_completion_and_exact_replays() {
    let pending = messaging::ReceiveState {
        attachment_id: [4; 16],
        ranges: vec![messaging::ChunkRange { start: 0, end: 1 }],
        state_update: 1,
        outcome: messaging::ReceiveOutcome::Pending,
        failure_code: None,
        recovery_round: 0,
    };
    let complete = messaging::ReceiveState {
        ranges: vec![],
        state_update: 2,
        outcome: messaging::ReceiveOutcome::Complete,
        ..pending.clone()
    };
    assert!(pending.validate_successor(&complete, false).is_err());
    pending.validate_successor(&complete, true).unwrap();
    assert!(pending.validate_successor(&pending, false).is_ok());

    let same_version_mutation = messaging::ReceiveState {
        recovery_round: 1,
        ..pending.clone()
    };
    assert_eq!(
        pending
            .validate_successor(&same_version_mutation, false)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(complete.validate_successor(&complete, true).is_ok());
    let rewritten_terminal = messaging::ReceiveState {
        state_update: 3,
        ..complete.clone()
    };
    assert!(
        complete
            .validate_successor(&rewritten_terminal, true)
            .is_err()
    );

    let empty_pending = messaging::ReceiveState {
        ranges: vec![],
        ..pending
    };
    assert!(empty_pending.validate().is_err());
}

#[test]
fn group_is_bounded_and_projects_per_member() {
    let members: Vec<_> = (0..MAX_GROUP_MEMBERS)
        .map(|index| {
            let mut endpoint = [0; 32];
            endpoint[31] = index as u8;
            Member {
                endpoint,
                role: if index == 0 {
                    MemberRole::StateAuthority
                } else {
                    MemberRole::Member
                },
            }
        })
        .collect();
    let state = GroupState {
        group_id: [7; 32],
        epoch: 0,
        previous_digest: None,
        members,
        transition_digest: [8; 32],
    };
    let projections = state
        .projections(&RustCryptoProvider, [9; 16], &[0; 32], b"opaque")
        .unwrap();
    assert_eq!(projections.len(), MAX_GROUP_MEMBERS - 1);
    let partial = group::aggregate_results(
        &projections,
        &[GroupResult {
            projection_id: *projections[0].id(),
            recipient: *projections[0].recipient(),
            outcome: ResultOutcome::Delivered,
            failure_code: None,
            authority: ResultAuthority::EndpointConfirmation,
        }],
    )
    .unwrap();
    assert_eq!(partial.outcome, AggregateOutcome::Partial);
    assert_eq!(partial.pending, projections.len() - 1);
    assert!(
        group::aggregate_results(
            &projections,
            &[GroupResult {
                projection_id: [0; 16],
                recipient: *projections[0].recipient(),
                outcome: ResultOutcome::Delivered,
                failure_code: None,
                authority: ResultAuthority::EndpointConfirmation,
            }],
        )
        .is_err()
    );
    let mut over = state.clone();
    over.members.push(Member {
        endpoint: [255; 32],
        role: MemberRole::Member,
    });
    assert_eq!(over.validate().unwrap_err().code, ErrorCode::BoundExceeded);
}

#[test]
fn reliable_records_use_closed_current_grammars() {
    let intent = CborValue::Map(BTreeMap::from([
        (0, CborValue::Bytes(vec![1; 16])),
        (1, CborValue::Bytes(vec![2; 32])),
        (2, CborValue::Bytes(b"idempotency".to_vec())),
        (3, CborValue::Bytes(b"payload".to_vec())),
        (4, CborValue::Unsigned(42)),
        (5, CborValue::Bytes(vec![3; 32])),
    ]));
    reliable::validate_intent_record(&intent).unwrap();

    let mut missing_intent = intent.clone();
    let CborValue::Map(values) = &mut missing_intent else {
        unreachable!("constructed map")
    };
    values.remove(&5);
    assert_eq!(
        reliable::validate_intent_record(&missing_intent)
            .unwrap_err()
            .code,
        ErrorCode::UnknownField
    );

    let confirmation = CborValue::Map(BTreeMap::from([
        (0, CborValue::Bytes(vec![5; 16])),
        (1, CborValue::Unsigned(0)),
        (2, CborValue::Unsigned(0)),
        (3, CborValue::Array(vec![CborValue::Bytes(vec![1; 16])])),
    ]));
    reliable::validate_confirmation_record(&confirmation).unwrap();
}

#[test]
fn reliable_retry_preserves_packet_identity_and_lifetime_bounds() {
    let state = reliable::ReliableState {
        intent_digest: [1; 32],
        route_digest: [2; 32],
        protected_packet_digest: [3; 32],
        retries: 0,
        migrations: 0,
        transitions: 0,
        outcome: reliable::Outcome::Pending,
    };
    let next = state.retry([2; 32], [1; 32], [3; 32]).unwrap();
    assert_eq!((next.retries, next.transitions), (1, 1));
    assert_eq!(
        state.retry([2; 32], [1; 32], [4; 32]).unwrap_err().code,
        ErrorCode::InvalidTransition
    );
    assert!(reliable::validate_route_successor(2, 2).is_err());
    assert!(reliable::validate_route_successor(0, 9_007_199_254_740_992).is_err());
    assert!(reliable::validate_absorbing_state("failed", "endpointAccepted").is_err());
    assert!(reliable::validate_absorbing_state("failed", "duplicate").is_err());
    assert!(reliable::validate_station_stage_authority("stationHint", "accepted").is_err());
    assert!(reliable::validate_projection_outcome_successor("delivered", "failed").is_err());

    let terminal = reliable::ReliableState {
        outcome: reliable::Outcome::EffectCompleted,
        ..state
    };
    assert_eq!(
        terminal.retry([2; 32], [1; 32], [3; 32]).unwrap_err().code,
        ErrorCode::InvalidTransition
    );
}

#[test]
fn transport_control_records_validate_operation_specific_semantics() {
    let claim = CborValue::Map(BTreeMap::from([(0, CborValue::Unsigned(64))]));
    transport::validate_control_record(Operation::Claim, &claim).unwrap();
    let body = licoarc::encoding::encode(&claim).unwrap();
    let path = format!("/v1/handles/{}/claim", "A".repeat(43));
    let request = transport::TransportRequest {
        scheme: "https",
        tls_version: "1.3",
        tls_cipher_suite: "TLS_AES_128_GCM_SHA256",
        certificate_chain_valid: true,
        http_version: "2",
        renegotiation: false,
        method: "POST",
        path: &path,
        query_present: false,
        fragment_present: false,
        early_data: false,
        name_validated: true,
        authority_present: true,
        header_names_lowercase: true,
        header_bytes: 256,
        operation_id: Some([1; 16]),
        operation_id_canonical: true,
        media_type: "application/licoarc-transport+cbor",
        media_type_parameters: false,
        content_length: Some(body.len()),
        content_length_canonical: true,
        transfer_encoding: false,
        content_encoding_identity: true,
        trailers: false,
        streaming: false,
        body: &body,
    };
    transport::validate_endpoint_request(&request).unwrap();

    let mut malformed = request;
    malformed.body = &[0xa0];
    malformed.content_length = Some(1);
    assert_eq!(
        transport::validate_endpoint_request(&malformed)
            .unwrap_err()
            .code,
        ErrorCode::UnknownField
    );
    let over_bound = CborValue::Map(BTreeMap::from([(0, CborValue::Unsigned(65))]));
    assert_eq!(
        transport::validate_control_record(Operation::Claim, &over_bound)
            .unwrap_err()
            .code,
        ErrorCode::BoundExceeded
    );
    assert!(
        transport::operation_from_path(&format!("/v1/handles/{}B/claim", "A".repeat(42))).is_err()
    );

    let duplicate_settlement = CborValue::Map(BTreeMap::from([
        (0, CborValue::Bytes(vec![1; 32])),
        (1, CborValue::Unsigned(1)),
        (
            2,
            CborValue::Array(vec![
                CborValue::Map(BTreeMap::from([
                    (0, CborValue::Bytes(vec![2; 32])),
                    (1, CborValue::Unsigned(0)),
                ])),
                CborValue::Map(BTreeMap::from([
                    (0, CborValue::Bytes(vec![2; 32])),
                    (1, CborValue::Unsigned(1)),
                ])),
            ]),
        ),
    ]));
    assert_eq!(
        transport::validate_control_record(Operation::Settle, &duplicate_settlement)
            .unwrap_err()
            .code,
        ErrorCode::InvalidRepresentation
    );
}

#[test]
fn identity_definition_validation_is_closed_at_nested_boundaries() {
    let record = json!({
        "recordType": "firstContact",
        "handleClass": "firstContact",
        "deliveryHandle": "01".repeat(32),
        "audienceDigest": "02".repeat(32),
        "invitationBinding": "03".repeat(32),
        "purpose": "firstContact",
        "singleUse": true,
        "expiresAt": 42,
        "protectedInvitation": {
            "inviterEndpointIdentityRef": "04".repeat(32),
            "invitationBinding": "03".repeat(32),
            "purpose": "firstContact",
            "audienceDigest": "02".repeat(32)
        },
        "peerVerificationState": "unverified"
    });
    identity::validate_definition_record(&record).unwrap();

    let mut unknown = record;
    unknown["protectedInvitation"]["unknown"] = json!(true);
    assert_eq!(
        identity::validate_definition_record(&unknown)
            .unwrap_err()
            .code,
        ErrorCode::UnknownField
    );
}

#[test]
fn identity_complete_key_and_signature_shapes_are_closed() {
    let profile = "176b912b9547ca9c47ace10f881457ab63fcd493ef953616f5859e76b830fd60";
    let signature = json!({
        "keyProfileId": profile,
        "keyId": "11".repeat(32),
        "signaturePurpose": "endpoint-continuity",
        "signatureValue": "22".repeat(64)
    });
    let record = json!({
        "recordType": "identityUpdate",
        "protocolLineId": "01".repeat(32),
        "endpointIdentityRef": "02".repeat(32),
        "identityEpoch": 1,
        "transition": "genesis",
        "stateDigest": "03".repeat(32),
        "keyAuthorizations": [{
            "keyId": "11".repeat(32),
            "keyPurpose": "identity",
            "keyState": "active",
            "keyProfileId": profile,
            "publicKey": "44".repeat(32),
            "validFromEpoch": 1
        }],
        "continuityProof": {
            "proofKind": "genesis",
            "predecessorStateDigest": null,
            "signature": signature.clone()
        },
        "endpointSignature": signature
    });
    identity::validate_definition_record(&record).unwrap();
}

#[test]
fn station_descriptor_uses_complete_profile_bound_keys() {
    let profile = "176b912b9547ca9c47ace10f881457ab63fcd493ef953616f5859e76b830fd60";
    let descriptor = json!({
        "recordType": "stationDescriptor",
        "stationId": "01".repeat(32),
        "descriptorSequence": 1,
        "notBefore": 1,
        "notAfter": 2,
        "listeners": [{
            "transportProfileId": "02".repeat(32),
            "endpointUri": "https://station.example/listen"
        }],
        "signingKeys": [{
            "keyProfileId": profile,
            "keyId": "03".repeat(32),
            "publicKey": "04".repeat(32)
        }],
        "signatures": [{
            "keyProfileId": profile,
            "keyId": "03".repeat(32),
            "signaturePurpose": "station-descriptor",
            "signatureValue": "05".repeat(64)
        }]
    });
    identity::validate_definition_record(&descriptor).unwrap();
}

#[test]
fn governance_reducer_is_bounded_and_requires_coherent_rotation_facts() {
    let roles = [
        Role::Membership,
        Role::Compatibility,
        Role::Revocation,
        Role::Distribution,
        Role::Consistency,
        Role::Recovery,
        Role::Abuse,
    ];
    let role_versions = roles.into_iter().map(|role| (role, 1)).collect();
    let authorizations = roles
        .into_iter()
        .flat_map(|role| {
            (0..4).map(move |index| Authorization {
                root: [1 + index / 2; 16],
                key: [1 + index; 16],
                role,
            })
        })
        .collect();
    let current = GovernanceState {
        network_ref: [1; 32],
        bundle_epoch: 0,
        bundle_digest: None,
        role_versions: BTreeMap::new(),
    };
    let candidate = GovernanceCandidate {
        network_ref: [1; 32],
        bundle_epoch: 1,
        bundle_digest: [2; 32],
        role_versions,
        expires_at: 2,
        authorizations,
        active_roots_only: true,
        canonical_digest_valid: true,
        distribution_consistent: true,
        signature_scope_valid: true,
        recovery_event: RecoveryEvent::None,
        recovery_predecessor: None,
        observations: vec![
            ConsistencyObservation {
                observer_ref: [4; 32],
                observed_version: 1,
                observed_digest: [2; 32],
                statement_digest: [5; 32],
            },
            ConsistencyObservation {
                observer_ref: [6; 32],
                observed_version: 1,
                observed_digest: [2; 32],
                statement_digest: [7; 32],
            },
        ],
        split_view: false,
        endpoint_admission_local: true,
        abuse_advisory_only: true,
    };
    let committed = match governance::evaluate_candidate(&current, &candidate, 1).unwrap() {
        Adoption::Commit(state) => state,
        Adoption::Replay => panic!("genesis candidate cannot be a replay"),
    };
    assert_eq!(
        governance::evaluate_candidate(&committed, &candidate, 1).unwrap(),
        Adoption::Replay
    );

    let mut split_view = candidate.clone();
    split_view.observations[1].observed_digest = [8; 32];
    assert!(governance::evaluate_candidate(&current, &split_view, 1).is_err());

    let mut inconsistent_replay = candidate.clone();
    inconsistent_replay
        .role_versions
        .insert(Role::Membership, 2);
    assert_eq!(
        governance::evaluate_candidate(&committed, &inconsistent_replay, 1)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );

    let mut incoherent = candidate.clone();
    incoherent.recovery_predecessor = Some([9; 32]);
    assert_eq!(
        governance::evaluate_candidate(&current, &incoherent, 1)
            .unwrap_err()
            .code,
        ErrorCode::InvalidTransition
    );

    let mut over_bound = current;
    over_bound.bundle_epoch = u64::MAX;
    over_bound.bundle_digest = Some([1; 32]);
    assert_eq!(
        governance::evaluate_candidate(&over_bound, &candidate, 1)
            .unwrap_err()
            .code,
        ErrorCode::BoundExceeded
    );
}
