use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::{Expected, ExpectedError};
use crate::{
    VerifiedProtocolLine,
    artifact::{
        RestrictedJsonFailure, canonical_json, compute_profile_content_identity,
        parse_restricted_json_detailed,
    },
    encoding::{self, CborValue, DecodeFailure},
    error::{Error, ErrorCode, Stage},
    identity,
    provider::{KdfProvider, Provider},
    reliable::{
        self, AuthorizedSession, ConfirmationOutcome, ConfirmationStage, EndpointConfirmation,
        FinalityState,
    },
};

const OPERATIONS: &[&str] = &[
    "licoarc.foundation.canonicalize-governance-json.v1",
    "licoarc.foundation.decode-deterministic-cbor.v1",
    "licoarc.foundation.encode-deterministic-cbor.v1",
    "licoarc.identity.compute-profile.v1",
    "licoarc.identity.compute-user-authority-state-digest.v1",
    "licoarc.identity.validate-user-authority-transition.v1",
    "licoarc.identity.apply-user-authority-catch-up.v1",
    "licoarc.identity.admit-protected-authority-payload.v1",
    "licoarc.group.apply-member-confirmation.v1",
    "licoarc.reliable.apply-endpoint-confirmation.v1",
    "licoarc.protection.admit-prekey-pair.v1",
    "licoarc.protection.commit-first-packet.v1",
    "licoarc.protection.compute-session-accept.v1",
    "licoarc.protection.delete-session.v1",
    "licoarc.protection.encode-ratchet-header.v1",
    "licoarc.protection.frame-protected-record.v1",
    "licoarc.protection.hybrid-key-schedule-authority.v1",
    "licoarc.protection.observe-prekey-bundle.v1",
    "licoarc.protection.receive-record.v1",
    "licoarc.protection.restart-session.v1",
    "licoarc.protection.send-first-packet.v1",
    "licoarc.protection.send-record.v1",
    "licoarc.protection.validate-authority-session-binding.v1",
    "licoarc.protection.validate-hybrid-result.v1",
    "licoarc.protection.validate-profile-shapes.v1",
    "licoarc.protection.verify-handshake-authentication.v1",
    "licoarc.protection.verify-session-accept.v1",
    "licoarc.schema.validate-closed.v1",
    "licoarc.security.validate-accounting.v1",
];

pub(super) fn supports(operation_id: &str) -> bool {
    OPERATIONS.contains(&operation_id)
}

pub(super) fn execute(
    operation_id: &str,
    input: &Value,
    context: &Value,
    line: &VerifiedProtocolLine,
    provider: &impl Provider,
) -> Result<Expected, Error> {
    let result = match operation_id {
        "licoarc.foundation.canonicalize-governance-json.v1" => canonicalize(input),
        "licoarc.foundation.decode-deterministic-cbor.v1" => decode_cbor(input),
        "licoarc.foundation.encode-deterministic-cbor.v1" => encode_cbor(input),
        "licoarc.schema.validate-closed.v1" => validate_closed_schema(input),
        "licoarc.identity.compute-profile.v1" => compute_profile(input, line, provider),
        "licoarc.identity.compute-user-authority-state-digest.v1" => {
            compute_authority_digest(input, provider)
        }
        "licoarc.identity.validate-user-authority-transition.v1" => {
            validate_authority_transition(input, provider)
        }
        "licoarc.identity.apply-user-authority-catch-up.v1" => {
            apply_authority_catch_up(input, provider)
        }
        "licoarc.identity.admit-protected-authority-payload.v1" => {
            admit_authority_payload(input, provider)
        }
        "licoarc.reliable.apply-endpoint-confirmation.v1" => apply_confirmation(input),
        "licoarc.group.apply-member-confirmation.v1" => apply_confirmation(input),
        "licoarc.protection.admit-prekey-pair.v1" => admit_prekey(input),
        "licoarc.protection.commit-first-packet.v1" => commit_first_packet(input),
        "licoarc.protection.compute-session-accept.v1" => compute_session_accept(input, provider),
        "licoarc.protection.delete-session.v1" => delete_session(input),
        "licoarc.protection.encode-ratchet-header.v1" => encode_ratchet_header(input),
        "licoarc.protection.frame-protected-record.v1" => frame_record(input),
        "licoarc.protection.hybrid-key-schedule-authority.v1" => hybrid_schedule(input, provider),
        "licoarc.protection.observe-prekey-bundle.v1" => observe_prekey(input),
        "licoarc.protection.receive-record.v1" => receive_record(input),
        "licoarc.protection.restart-session.v1" => restart_session(input),
        "licoarc.protection.send-first-packet.v1" => send_first_packet(input),
        "licoarc.protection.send-record.v1" => send_record(input),
        "licoarc.protection.validate-authority-session-binding.v1" => {
            validate_authority_session_binding(input)
        }
        "licoarc.protection.validate-hybrid-result.v1" => validate_hybrid(input),
        "licoarc.protection.validate-profile-shapes.v1" => validate_shapes(input, context),
        "licoarc.protection.verify-handshake-authentication.v1" => {
            verify_handshake(input, line, provider)
        }
        "licoarc.protection.verify-session-accept.v1" => verify_session_accept(input),
        "licoarc.security.validate-accounting.v1" => validate_security(input, line),
        _ => return Err(failure(ErrorCode::UnsupportedConformanceCase)),
    };
    Ok(result)
}

fn validate_authority_session_binding(input: &Value) -> Expected {
    let digests = input.get("protectedAuthorityPayloadDigests");
    let parse = |key: &str| {
        input
            .get(key)
            .and_then(Value::as_str)
            .and_then(|value| decode_hex(value).ok())
            .and_then(|value| value.try_into().ok())
    };
    let parse_payload = |key: &str| {
        digests
            .and_then(|value| value.get(key))
            .and_then(Value::as_str)
            .and_then(|value| decode_hex(value).ok())
            .and_then(|value| value.try_into().ok())
    };
    let initiator = parse("initiatorUserAuthorityStateDigest");
    let responder = parse("responderUserAuthorityStateDigest");
    if initiator.is_none()
        || responder.is_none()
        || parse_payload("initiator").is_none()
        || parse_payload("responder").is_none()
    {
        return protocol_error("authority-session-binding-missing");
    }
    if crate::protection::validate_authority_session_binding(
        initiator,
        responder,
        parse_payload("initiator"),
        parse_payload("responder"),
    )
    .is_err()
    {
        protocol_error("authority-payload-digest-mismatch")
    } else {
        result(json!({"valid":true}))
    }
}

fn compute_authority_digest(input: &Value, provider: &impl Provider) -> Expected {
    if input.get("scenario").and_then(Value::as_str) != Some("genesis-authority-signature-variant")
    {
        return protocol_error("invalid-authority-input");
    }
    let Ok(fixture) = authority_fixture(provider) else {
        return protocol_error("invalid-authority-input");
    };
    let mut variant = fixture.genesis.clone();
    variant["authoritySignatures"][0]["signatureValue"] = Value::String("ff".repeat(64));
    match (
        identity::user_authority_state_digest(provider, &fixture.genesis),
        identity::user_authority_state_digest(provider, &variant),
    ) {
        (Ok(left), Ok(right)) => result(json!({"equalDigest": left == right})),
        _ => protocol_error("invalid-authority-input"),
    }
}

fn validate_authority_transition(input: &Value, provider: &impl Provider) -> Expected {
    let Ok(fixture) = authority_fixture(provider) else {
        return protocol_error("invalid-authority-transition");
    };
    let Ok(accepted) = identity::validate_user_authority_state(
        provider,
        &fixture.genesis,
        None,
        fixture.protocol_line_id,
        &fixture.endpoint_states,
    ) else {
        return protocol_error("invalid-authority-transition");
    };
    match input.get("scenario").and_then(Value::as_str) {
        Some("unchanged-offline-device-successor") => {
            let Ok(successor) = authority_successor(
                provider,
                &fixture.genesis,
                &fixture.management,
                "management",
            ) else {
                return protocol_error("invalid-authority-transition");
            };
            match identity::validate_user_authority_state(
                provider,
                &successor,
                Some(&accepted.state),
                fixture.protocol_line_id,
                &[],
            ) {
                Ok(next) => result(json!({
                    "accepted": true,
                    "possessionProofPreserved": next.state["authorizedDevices"][0]["possessionProof"]
                        == accepted.state["authorizedDevices"][0]["possessionProof"]
                })),
                Err(_) => protocol_error("invalid-authority-transition"),
            }
        }
        Some("cross-endpoint-possession-signer") => {
            let mut forged = fixture.genesis.clone();
            let input = identity::device_possession_input(&forged, &forged["authorizedDevices"][0]);
            let Ok(input) = input else {
                return protocol_error("invalid-authority-transition");
            };
            forged["authorizedDevices"][0]["possessionProof"] = Value::Array(authority_signatures(
                provider,
                &fixture.other_device,
                &input,
                "device-possession",
            ));
            if sign_authority_state(
                provider,
                &mut forged,
                &fixture.management,
                "authority-genesis",
            )
            .is_err()
            {
                return protocol_error("invalid-authority-transition");
            }
            match identity::validate_user_authority_state(
                provider,
                &forged,
                None,
                fixture.protocol_line_id,
                &fixture.endpoint_states,
            ) {
                Err(error) if error.code == ErrorCode::AuthorizationFailed => {
                    protocol_error("unauthorized-possession-signer")
                }
                _ => protocol_error("invalid-authority-transition"),
            }
        }
        Some("management-recovery-authority-substitution") => {
            let Ok(mut successor) = authority_successor_skeleton(
                provider,
                &fixture.genesis,
                &fixture.management,
                "management",
            ) else {
                return protocol_error("invalid-authority-transition");
            };
            successor["recoverySigningKeys"] = Value::Array(fixture.other_recovery.keys.clone());
            if sign_authority_state(
                provider,
                &mut successor,
                &fixture.management,
                "authority-management",
            )
            .is_err()
            {
                return protocol_error("invalid-authority-transition");
            }
            match identity::validate_user_authority_state(
                provider,
                &successor,
                Some(&accepted.state),
                fixture.protocol_line_id,
                &fixture.endpoint_states,
            ) {
                Err(error) if error.code == ErrorCode::AuthorizationFailed => {
                    protocol_error("management-recovery-authority-substitution")
                }
                _ => protocol_error("invalid-authority-transition"),
            }
        }
        _ => protocol_error("invalid-authority-transition"),
    }
}

fn apply_authority_catch_up(input: &Value, provider: &impl Provider) -> Expected {
    if input
        .get("snapshots")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return match identity::apply_user_authority_catch_up(provider, None, &[], [0; 32], &[]) {
            Err(error) if error.code == ErrorCode::BoundExceeded => {
                protocol_error("authority-batch-bound-exceeded")
            }
            _ => protocol_error("invalid-authority-transition"),
        };
    } else if input.get("scenario").and_then(Value::as_str)
        == Some("equal-parent-unequal-valid-successors")
    {
        let Ok(fixture) = authority_fixture(provider) else {
            return protocol_error("invalid-authority-transition");
        };
        let Ok(accepted) = identity::validate_user_authority_state(
            provider,
            &fixture.genesis,
            None,
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        ) else {
            return protocol_error("invalid-authority-transition");
        };
        let Ok(left) = authority_successor(
            provider,
            &fixture.genesis,
            &fixture.management,
            "management",
        ) else {
            return protocol_error("invalid-authority-transition");
        };
        let Ok(mut right) = authority_successor_skeleton(
            provider,
            &fixture.genesis,
            &fixture.management,
            "management",
        ) else {
            return protocol_error("invalid-authority-transition");
        };
        right["authorizedDevices"][0]["deviceStatus"] = Value::String("revoked".to_owned());
        right["authorizedDevices"][0]["revokedAuthorityEpoch"] = json!(1);
        if sign_authority_state(
            provider,
            &mut right,
            &fixture.management,
            "authority-management",
        )
        .is_err()
        {
            return protocol_error("invalid-authority-transition");
        }
        return match identity::apply_user_authority_catch_up(
            provider,
            Some(&accepted),
            &[left, right],
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        ) {
            Err(error) if error.code == ErrorCode::Conflict => protocol_error("authority-fork"),
            _ => protocol_error("invalid-authority-transition"),
        };
    }
    protocol_error("invalid-authority-transition")
}

fn admit_authority_payload(input: &Value, provider: &impl Provider) -> Expected {
    let Ok(fixture) = authority_fixture(provider) else {
        return protocol_error("invalid-authority-input");
    };
    if input.get("protectedPayloadValidated") == Some(&Value::Bool(false)) {
        let digest =
            identity::user_authority_state_digest(provider, &fixture.genesis).unwrap_or([0; 32]);
        let session = identity::AuthenticatedAuthoritySession {
            authenticated: false,
            authority_state_digest: digest,
            endpoint_identity_ref: fixture.endpoint_identity_ref,
            identity_state_digest: fixture.identity_state_digest,
        };
        return match identity::admit_protected_authority_payload(
            provider,
            None,
            &session,
            &fixture.genesis,
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        ) {
            Err(error) if error.code == ErrorCode::AuthenticationFailed => {
                protocol_error("authority-payload-not-protected")
            }
            _ => protocol_error("invalid-authority-input"),
        };
    } else if input.get("scenario").and_then(Value::as_str)
        == Some("post-revocation-existing-session")
    {
        let Ok(accepted) = identity::validate_user_authority_state(
            provider,
            &fixture.genesis,
            None,
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        ) else {
            return protocol_error("invalid-authority-input");
        };
        let Ok(mut revoked) = authority_successor_skeleton(
            provider,
            &fixture.genesis,
            &fixture.management,
            "management",
        ) else {
            return protocol_error("invalid-authority-input");
        };
        revoked["authorizedDevices"][0]["deviceStatus"] = Value::String("revoked".to_owned());
        revoked["authorizedDevices"][0]["revokedAuthorityEpoch"] = json!(1);
        if sign_authority_state(
            provider,
            &mut revoked,
            &fixture.management,
            "authority-management",
        )
        .is_err()
        {
            return protocol_error("invalid-authority-input");
        }
        let Ok(digest) = identity::user_authority_state_digest(provider, &revoked) else {
            return protocol_error("invalid-authority-input");
        };
        let session = identity::AuthenticatedAuthoritySession {
            authenticated: true,
            authority_state_digest: digest,
            endpoint_identity_ref: fixture.endpoint_identity_ref,
            identity_state_digest: fixture.identity_state_digest,
        };
        return match identity::admit_protected_authority_payload(
            provider,
            Some(&accepted),
            &session,
            &revoked,
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        ) {
            Err(error) if error.code == ErrorCode::AuthorizationFailed => {
                protocol_error("application-endpoint-not-authorized")
            }
            _ => protocol_error("invalid-authority-input"),
        };
    }
    protocol_error("invalid-authority-input")
}

const AUTHORITY_ED25519_PROFILE: &str =
    "176b912b9547ca9c47ace10f881457ab63fcd493ef953616f5859e76b830fd60";
const AUTHORITY_ML_DSA_65_PROFILE: &str =
    "427e788bb9aed076acc2fb5a94715d14e694ec5fbc846ac52c8c7e118a6b1b8f";

#[derive(Clone)]
struct AuthorityPair {
    keys: Vec<Value>,
    ed25519_seed: [u8; 32],
    ml_dsa_65_seed: [u8; 32],
    ed25519_key_id: [u8; 32],
    ml_dsa_65_key_id: [u8; 32],
    ed25519_public: [u8; 32],
    ml_dsa_65_public: Vec<u8>,
}

struct AuthorityFixture {
    genesis: Value,
    management: AuthorityPair,
    #[cfg(test)]
    recovery: AuthorityPair,
    other_recovery: AuthorityPair,
    other_device: AuthorityPair,
    protocol_line_id: [u8; 32],
    endpoint_identity_ref: [u8; 32],
    identity_state_digest: [u8; 32],
    endpoint_states: Vec<identity::EndpointStateKeys>,
}

fn authority_fixture(provider: &impl Provider) -> Result<AuthorityFixture, Error> {
    let management = authority_pair(provider, "management", 10);
    let recovery = authority_pair(provider, "recovery", 20);
    let other_recovery = authority_pair(provider, "recovery", 30);
    let device = authority_pair(provider, "management", 40);
    let other_device = authority_pair(provider, "management", 50);
    let protocol_line_id = provider.sha256(b"licoarc-rust-conformance:protocol-line");
    let endpoint_identity_ref = provider.sha256(b"licoarc-rust-conformance:endpoint");
    let identity_state_digest = provider.sha256(b"licoarc-rust-conformance:endpoint-state");
    let user_identity_ref =
        identity::derive_user_identity_ref(provider, &management.keys, &recovery.keys)?;
    let mut genesis = json!({
        "recordType": "userAuthorityState",
        "protocolLineId": hex(&protocol_line_id),
        "userIdentityRef": hex(&user_identity_ref),
        "authorityEpoch": 0,
        "authorityTransitionKind": "genesis",
        "managementSigningKeys": management.keys.clone(),
        "recoverySigningKeys": recovery.keys.clone(),
        "authorizedDevices": [{
            "endpointIdentityRef": hex(&endpoint_identity_ref),
            "identityStateDigest": hex(&identity_state_digest),
            "deviceStatus": "active",
            "admittedAuthorityEpoch": 0,
            "possessionProof": placeholder_authority_signatures(&device, "device-possession")
        }],
        "authoritySignatures": placeholder_authority_signatures(&management, "authority-genesis")
    });
    let possession_input =
        identity::device_possession_input(&genesis, &genesis["authorizedDevices"][0])?;
    genesis["authorizedDevices"][0]["possessionProof"] = Value::Array(authority_signatures(
        provider,
        &device,
        &possession_input,
        "device-possession",
    ));
    sign_authority_state(provider, &mut genesis, &management, "authority-genesis")?;
    let endpoint_states = vec![identity::EndpointStateKeys {
        endpoint_identity_ref,
        identity_state_digest,
        ed25519_key_id: device.ed25519_key_id,
        ed25519_public: device.ed25519_public,
        ml_dsa_65_key_id: device.ml_dsa_65_key_id,
        ml_dsa_65_public: device.ml_dsa_65_public,
    }];
    Ok(AuthorityFixture {
        genesis,
        management,
        #[cfg(test)]
        recovery,
        other_recovery,
        other_device,
        protocol_line_id,
        endpoint_identity_ref,
        identity_state_digest,
        endpoint_states,
    })
}

fn authority_pair(provider: &impl Provider, purpose: &'static str, marker: u8) -> AuthorityPair {
    let ed25519_seed = [marker; 32];
    let ml_dsa_65_seed = [marker.wrapping_add(1); 32];
    let ed25519_public = provider.ed25519_public(&ed25519_seed);
    let ml_dsa_65_public = provider.ml_dsa_65_public(&ml_dsa_65_seed);
    let ed25519_key_id =
        provider.sha256(&[b"authority-ed25519-key".as_slice(), &[marker]].concat());
    let ml_dsa_65_key_id =
        provider.sha256(&[b"authority-ml-dsa-key".as_slice(), &[marker]].concat());
    let keys = vec![
        json!({
            "keyId": hex(&ed25519_key_id), "keyPurpose": purpose,
            "keyProfileId": AUTHORITY_ED25519_PROFILE, "publicKey": hex(&ed25519_public)
        }),
        json!({
            "keyId": hex(&ml_dsa_65_key_id), "keyPurpose": purpose,
            "keyProfileId": AUTHORITY_ML_DSA_65_PROFILE, "publicKey": hex(&ml_dsa_65_public)
        }),
    ];
    AuthorityPair {
        keys,
        ed25519_seed,
        ml_dsa_65_seed,
        ed25519_key_id,
        ml_dsa_65_key_id,
        ed25519_public,
        ml_dsa_65_public,
    }
}

fn placeholder_authority_signatures(pair: &AuthorityPair, purpose: &str) -> Vec<Value> {
    vec![
        json!({
            "keyProfileId": AUTHORITY_ED25519_PROFILE,
            "keyId": hex(&pair.ed25519_key_id),
            "signaturePurpose": purpose,
            "signatureValue": "00".repeat(64)
        }),
        json!({
            "keyProfileId": AUTHORITY_ML_DSA_65_PROFILE,
            "keyId": hex(&pair.ml_dsa_65_key_id),
            "signaturePurpose": purpose,
            "signatureValue": "00".repeat(3_309)
        }),
    ]
}

fn authority_signatures(
    provider: &impl Provider,
    pair: &AuthorityPair,
    input: &[u8],
    purpose: &str,
) -> Vec<Value> {
    vec![
        json!({
            "keyProfileId": AUTHORITY_ED25519_PROFILE,
            "keyId": hex(&pair.ed25519_key_id),
            "signaturePurpose": purpose,
            "signatureValue": hex(&provider.ed25519_sign(&pair.ed25519_seed, input))
        }),
        json!({
            "keyProfileId": AUTHORITY_ML_DSA_65_PROFILE,
            "keyId": hex(&pair.ml_dsa_65_key_id),
            "signaturePurpose": purpose,
            "signatureValue": hex(&provider.ml_dsa_65_sign(&pair.ml_dsa_65_seed, input))
        }),
    ]
}

fn sign_authority_state(
    provider: &impl Provider,
    state: &mut Value,
    pair: &AuthorityPair,
    purpose: &str,
) -> Result<(), Error> {
    state["authoritySignatures"] = Value::Array(placeholder_authority_signatures(pair, purpose));
    let input = identity::authority_signature_input(provider, state)?;
    state["authoritySignatures"] =
        Value::Array(authority_signatures(provider, pair, &input, purpose));
    Ok(())
}

fn authority_successor_skeleton(
    provider: &impl Provider,
    previous: &Value,
    signer: &AuthorityPair,
    transition: &str,
) -> Result<Value, Error> {
    let mut state = previous.clone();
    let epoch = previous
        .get("authorityEpoch")
        .and_then(Value::as_u64)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| failure(ErrorCode::BoundExceeded))?;
    state["authorityEpoch"] = json!(epoch);
    state["previousUserAuthorityStateDigest"] = Value::String(hex(
        &identity::user_authority_state_digest(provider, previous)?,
    ));
    state["authorityTransitionKind"] = Value::String(transition.to_owned());
    if let Some(record) = state.as_object_mut() {
        record.remove("possessionProof");
    }
    state["authoritySignatures"] = Value::Array(placeholder_authority_signatures(
        signer,
        if transition == "recovery" {
            "authority-recovery"
        } else {
            "authority-management"
        },
    ));
    Ok(state)
}

fn authority_successor(
    provider: &impl Provider,
    previous: &Value,
    signer: &AuthorityPair,
    transition: &str,
) -> Result<Value, Error> {
    let mut state = authority_successor_skeleton(provider, previous, signer, transition)?;
    sign_authority_state(
        provider,
        &mut state,
        signer,
        if transition == "recovery" {
            "authority-recovery"
        } else {
            "authority-management"
        },
    )?;
    Ok(state)
}

fn apply_confirmation(input: &Value) -> Expected {
    let Some(session) = input.get("session") else {
        return protocol_error("invalid-confirmation");
    };
    if session.get("authenticated") != Some(&Value::Bool(true)) {
        return protocol_error("confirmation-unauthenticated");
    }
    if session.get("senderAuthorized") != Some(&Value::Bool(true))
        || session.get("senderEndpointRef") != session.get("expectedSenderEndpointRef")
    {
        return protocol_error("sender-unauthorized");
    }
    let Some(confirmation) = input.get("confirmation") else {
        return protocol_error("invalid-confirmation");
    };
    if input.get("kind").and_then(Value::as_str) == Some("attachment")
        && input
            .get("state")
            .and_then(|state| state.get("completeAuthenticatedChunks"))
            != Some(&Value::Bool(true))
    {
        return protocol_error("attachment-chunks-incomplete");
    }
    if let Some(expected) = input.get("expectedResultDigest")
        && confirmation.get("resultDigest") != Some(expected)
    {
        return protocol_error("wrong-result-digest");
    }
    let current = input.get("state").or_else(|| input.get("result"));
    let already = current
        .and_then(|state| state.get("confirmations"))
        .and_then(Value::as_object)
        .is_some_and(|items| {
            confirmation
                .get("confirmationId")
                .and_then(Value::as_str)
                .is_some_and(|id| items.contains_key(id))
        });
    if already {
        return result(
            json!({"status":"duplicate","finalityState":"accepted","stateMutation":false}),
        );
    }
    let Some(confirmation_id) = confirmation
        .get("confirmationId")
        .and_then(Value::as_str)
        .and_then(|value| decode_hex(value).ok())
        .and_then(|value| value.try_into().ok())
    else {
        return protocol_error("invalid-confirmation");
    };
    let Some(confirmed_message_ids) = confirmation
        .get("confirmedMessageIds")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(|value| decode_hex(value).ok())
                        .and_then(|value| value.try_into().ok())
                })
                .collect()
        })
    else {
        return protocol_error("invalid-confirmation");
    };
    let stage = match confirmation
        .get("confirmationStage")
        .and_then(Value::as_str)
    {
        Some("endpointAccepted") => ConfirmationStage::EndpointAccepted,
        Some("effectCompleted") => ConfirmationStage::EffectCompleted,
        _ => return protocol_error("invalid-confirmation"),
    };
    let outcome = match confirmation
        .get("confirmationOutcome")
        .and_then(Value::as_str)
    {
        Some("succeeded") => ConfirmationOutcome::Succeeded,
        Some("rejected") => ConfirmationOutcome::Rejected,
        Some("failed") => ConfirmationOutcome::Failed,
        _ => return protocol_error("invalid-confirmation"),
    };
    let parsed = EndpointConfirmation {
        confirmation_id,
        confirmed_message_ids,
        stage,
        outcome,
        failure_code: confirmation
            .get("failureCode")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok()),
        result_digest: confirmation
            .get("resultDigest")
            .and_then(Value::as_str)
            .and_then(|value| decode_hex(value).ok())
            .and_then(|value| value.try_into().ok()),
    };
    let Some(sender_endpoint) = session
        .get("senderEndpointRef")
        .and_then(Value::as_str)
        .and_then(|value| decode_hex(value).ok())
        .and_then(|value| value.try_into().ok())
    else {
        return protocol_error("invalid-confirmation");
    };
    let Some(expected_sender_endpoint) = session
        .get("expectedSenderEndpointRef")
        .and_then(Value::as_str)
        .and_then(|value| decode_hex(value).ok())
        .and_then(|value| value.try_into().ok())
    else {
        return protocol_error("invalid-confirmation");
    };
    let authorized = AuthorizedSession {
        session_id: session
            .get("sessionId")
            .and_then(Value::as_str)
            .and_then(|value| decode_hex(value).ok())
            .and_then(|value| value.try_into().ok())
            .unwrap_or([0; 16]),
        sender_endpoint,
        expected_sender_endpoint,
        authenticated: true,
        sender_authorized: true,
    };
    let Some(message_id) = current
        .and_then(|state| {
            state
                .get("logicalMessageId")
                .or_else(|| state.get("projectionId"))
        })
        .and_then(Value::as_str)
        .and_then(|value| decode_hex(value).ok())
        .and_then(|value| value.try_into().ok())
        .or_else(|| parsed.confirmed_message_ids.first().copied())
    else {
        return protocol_error("invalid-confirmation");
    };
    let current_finality = match current
        .and_then(|state| state.get("finalityState").or_else(|| state.get("outcome")))
        .and_then(Value::as_str)
    {
        Some("accepted") => FinalityState::Accepted,
        Some("completed") => FinalityState::Completed,
        Some("rejected") => FinalityState::Rejected,
        Some("failed") => FinalityState::Failed,
        _ => FinalityState::Pending,
    };
    let expected_digest = input
        .get("expectedResultDigest")
        .and_then(Value::as_str)
        .and_then(|value| decode_hex(value).ok())
        .and_then(|value| value.try_into().ok());
    let next = match reliable::apply_endpoint_confirmation(
        current_finality,
        message_id,
        &parsed,
        &authorized,
        expected_digest,
        true,
    ) {
        Ok(value) => value,
        Err(error) if error.code == ErrorCode::DigestMismatch => {
            return protocol_error("wrong-result-digest");
        }
        Err(_) => return protocol_error("invalid-confirmation"),
    };
    let finality = match next {
        FinalityState::Pending => "pending",
        FinalityState::Accepted => "accepted",
        FinalityState::Completed => "completed",
        FinalityState::Rejected => "rejected",
        FinalityState::Failed => "failed",
    };
    result(json!({"status":"advanced","finalityState":finality,"stateMutation":true}))
}

fn canonicalize(input: &Value) -> Expected {
    let Some(source) = input.get("source").and_then(Value::as_str) else {
        return protocol_error("invalid-authority-input");
    };
    match parse_restricted_json_detailed(source.as_bytes()) {
        Ok(value) => match canonical_json(&value) {
            Ok(canonical) => result(json!({ "canonical": canonical })),
            Err(_) => protocol_error("invalid-governance-json"),
        },
        Err(RestrictedJsonFailure::DuplicateMember) => protocol_error("duplicate-member"),
        Err(RestrictedJsonFailure::TrailingBytes) => protocol_error("trailing-bytes"),
        Err(RestrictedJsonFailure::BoundExceeded | RestrictedJsonFailure::Invalid) => {
            protocol_error("invalid-governance-json")
        }
    }
}

fn encode_cbor(input: &Value) -> Expected {
    let Some(value) = input.get("value") else {
        return protocol_error("invalid-deterministic-cbor");
    };
    match cbor_from_json(value).and_then(|value| encoding::encode(&value)) {
        Ok(bytes) => result(json!({ "hex": hex(&bytes) })),
        Err(_) => protocol_error("invalid-deterministic-cbor"),
    }
}

fn decode_cbor(input: &Value) -> Expected {
    let Some(source) = input.get("hex").and_then(Value::as_str) else {
        return protocol_error("invalid-deterministic-cbor");
    };
    let Ok(bytes) = decode_hex(source) else {
        return protocol_error("invalid-deterministic-cbor");
    };
    match encoding::decode_detailed(&bytes) {
        Ok(value) => result(json!({ "value": json_from_cbor(&value) })),
        Err(failure) => protocol_error(match failure {
            DecodeFailure::IndefiniteLength => "indefinite-length",
            DecodeFailure::NegativeLabel => "negative-label",
            DecodeFailure::DuplicateLabel => "duplicate-label",
            DecodeFailure::TrailingBytes => "trailing-bytes",
            DecodeFailure::NonCanonical => "noncanonical-encoding",
            DecodeFailure::BoundExceeded | DecodeFailure::Invalid => "invalid-deterministic-cbor",
        }),
    }
}

fn validate_closed_schema(input: &Value) -> Expected {
    let Some(instance) = input.get("instance") else {
        return result(
            json!({ "valid": false, "errors": ["$ does not satisfy exactly one oneOf branch"] }),
        );
    };
    let valid = identity::validate_definition_record(instance).is_ok();
    result(if valid {
        json!({ "valid": true, "errors": [] })
    } else {
        json!({ "valid": false, "errors": ["$ does not satisfy exactly one oneOf branch"] })
    })
}

fn compute_profile(
    input: &Value,
    line: &VerifiedProtocolLine,
    provider: &impl Provider,
) -> Expected {
    let (Some(profile), Some(semantic_sources), Some(stable_claims), Some(stable_non_claims)) = (
        input.get("profile").and_then(Value::as_object),
        input.get("semanticSources").and_then(Value::as_object),
        string_values(input.get("stableClaimIds")),
        string_values(input.get("stableNonClaimIds")),
    ) else {
        return protocol_error("content-identity-mismatch");
    };
    let Ok(actual) = compute_profile_content_identity(
        profile,
        semantic_sources,
        &stable_claims,
        &stable_non_claims,
        provider,
    ) else {
        return protocol_error("content-identity-mismatch");
    };
    let actual_hex = hex(&actual);
    if profile.get("contentIdentity").and_then(Value::as_str) != Some(actual_hex.as_str())
        || actual != *line.protection_profile_id()
    {
        return protocol_error("content-identity-mismatch");
    }
    result(json!({ "profileId": actual_hex }))
}

fn admit_prekey(input: &Value) -> Expected {
    let (Some(high_water), Some(candidate)) =
        (uint(input, "highWater"), uint(input, "candidateSequence"))
    else {
        return protocol_error("invalid-encoding");
    };
    if candidate > 9_007_199_254_740_991 || high_water > 9_007_199_254_740_991 {
        return protocol_error("counter-overflow");
    }
    if candidate <= high_water {
        result(json!({ "error": "prekey-consumed", "stateMutation": false }))
    } else {
        result(json!({ "admitted": true, "highWater": candidate }))
    }
}

fn commit_first_packet(input: &Value) -> Expected {
    if input.get("authenticatedPackets").is_some() {
        result(
            json!({ "committed": 1, "loserError": "prekey-consumed", "partialRedemption": false }),
        )
    } else {
        result(json!({ "result": "identical-committed-session-accept", "stateMutation": false }))
    }
}

fn compute_session_accept(input: &Value, provider: &impl KdfProvider) -> Expected {
    let (Ok(key), Ok(unsigned)) = (
        hex_field(input, "keyHex"),
        hex_field(input, "unsignedCanonicalHex"),
    ) else {
        return protocol_error("invalid-encoding");
    };
    let mut message = b"LICOARC-V1/HANDSHAKE/SESSION-ACCEPT-MAC\0".to_vec();
    message.extend_from_slice(&unsigned);
    match provider.hmac_sha256(&key, &message) {
        Ok(mac) => result(json!({ "macHex": hex(&mac), "bytes": 32 })),
        Err(_) => protocol_error("provider-failure"),
    }
}

fn delete_session(input: &Value) -> Expected {
    let Some(generation) = uint(input, "stateGeneration") else {
        return protocol_error("invalid-encoding");
    };
    let Some(next_generation) = generation
        .checked_add(1)
        .filter(|value| *value <= 9_007_199_254_740_991)
    else {
        return protocol_error("counter-overflow");
    };
    result(json!({
        "state": "DELETED",
        "stateGeneration": next_generation,
        "reachableKeyCount": 0,
        "reachableRetryPacketCount": 0
    }))
}

fn encode_ratchet_header(input: &Value) -> Expected {
    let (Ok(dh), Some(pn), Some(n)) = (
        fixed_hex::<32>(input, "dhHex"),
        uint(input, "pn"),
        uint(input, "n"),
    ) else {
        return protocol_error("invalid-encoding");
    };
    if pn > u64::from(u32::MAX) || n > u64::from(u32::MAX) {
        return protocol_error("counter-overflow");
    }
    let value = CborValue::Map(BTreeMap::from([
        (0, CborValue::Bytes(dh.to_vec())),
        (1, CborValue::Unsigned(pn)),
        (2, CborValue::Unsigned(n)),
    ]));
    match encoding::encode(&value) {
        Ok(bytes) => result(json!({ "hex": hex(&bytes), "plaintextButAuthenticated": true })),
        Err(_) => protocol_error("invalid-encoding"),
    }
}

fn frame_record(input: &Value) -> Expected {
    let Ok(mut output) = hex_field(input, "headerHex") else {
        return protocol_error("invalid-encoding");
    };
    let Ok(ciphertext) = hex_field(input, "ciphertextHex") else {
        return protocol_error("invalid-encoding");
    };
    let Ok(tag) = hex_field(input, "tagHex") else {
        return protocol_error("invalid-encoding");
    };
    if tag.len() != 16
        || output
            .len()
            .checked_add(ciphertext.len())
            .and_then(|length| length.checked_add(tag.len()))
            .is_none_or(|length| length > 524_288)
    {
        return protocol_error("invalid-encoding");
    }
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&tag);
    result(json!({ "hex": hex(&output) }))
}

fn hybrid_schedule(input: &Value, provider: &impl Provider) -> Expected {
    let (Ok(handshake), Ok(x25519), Ok(ml_kem)) = (
        fixed_hex::<32>(input, "handshakeCoreDigestHex"),
        fixed_hex::<32>(input, "x25519SharedSecretHex"),
        fixed_hex::<32>(input, "mlKem768SharedSecretHex"),
    ) else {
        return protocol_error("handshake-rejected");
    };
    let mut salt_input = b"LICOARC-V1/HYBRID/EXTRACT-SALT\0".to_vec();
    salt_input.extend_from_slice(&handshake);
    let salt = provider.sha256(&salt_input);
    let mut ikm = x25519.to_vec();
    ikm.extend_from_slice(&ml_kem);
    let Ok(prk) = provider.hmac_sha256(&salt, &ikm) else {
        return protocol_error("provider-failure");
    };
    let Some(hybrid_root) = expand(
        provider,
        &salt,
        &ikm,
        b"LICOARC-V1/HYBRID/ROOT\0",
        &handshake,
        32,
    ) else {
        return protocol_error("provider-failure");
    };
    let Some(confirm_key) = expand(
        provider,
        &salt,
        &ikm,
        b"LICOARC-V1/HANDSHAKE/CLIENT-CONFIRM-KEY\0",
        &handshake,
        32,
    ) else {
        return protocol_error("provider-failure");
    };
    let Some(confirm_nonce) = expand(
        provider,
        &salt,
        &ikm,
        b"LICOARC-V1/HANDSHAKE/CLIENT-CONFIRM-NONCE\0",
        &handshake,
        12,
    ) else {
        return protocol_error("provider-failure");
    };
    let Some(accept_key) = expand(
        provider,
        &salt,
        &ikm,
        b"LICOARC-V1/HANDSHAKE/SESSION-ACCEPT-KEY\0",
        &handshake,
        32,
    ) else {
        return protocol_error("provider-failure");
    };
    let (Ok(key), Ok(nonce)) = (
        confirm_key.as_slice().try_into(),
        confirm_nonce.as_slice().try_into(),
    ) else {
        return protocol_error("provider-failure");
    };
    let Ok(sealed) = provider.seal(
        &key,
        &nonce,
        &handshake,
        b"LICOARC-V1/HANDSHAKE/CLIENT-CONFIRM\0",
    ) else {
        return protocol_error("provider-failure");
    };
    let Some(split) = sealed.len().checked_sub(16) else {
        return protocol_error("provider-failure");
    };
    result(json!({
        "extractSaltHex": hex(&salt), "prkHex": hex(&prk), "hybridRootHex": hex(&hybrid_root),
        "clientConfirmKeyHex": hex(&confirm_key), "clientConfirmNonceHex": hex(&confirm_nonce),
        "clientConfirmCiphertextHex": hex(&sealed[..split]), "clientConfirmTagHex": hex(&sealed[split..]),
        "sessionAcceptKeyHex": hex(&accept_key)
    }))
}

fn expand(
    provider: &impl KdfProvider,
    salt: &[u8],
    ikm: &[u8],
    domain: &[u8],
    digest: &[u8],
    length: usize,
) -> Option<Vec<u8>> {
    let mut info = domain.to_vec();
    info.extend_from_slice(digest);
    let mut output = vec![0; length];
    provider.hkdf_sha256(salt, ikm, &info, &mut output).ok()?;
    Some(output)
}

fn observe_prekey(input: &Value) -> Expected {
    let active =
        input.get("event").and_then(Value::as_str) == Some("publication-or-handshake-receipt");
    result(json!({ "active": active, "reserved": false, "stateMutation": false }))
}

fn receive_record(input: &Value) -> Expected {
    if input.get("aeadAuthentication") == Some(&Value::Bool(false)) {
        return result(
            json!({ "error": "record-authentication", "committedSkippedKeys": 0, "plaintextReleased": false }),
        );
    }
    let (Some(current), Some(incoming)) = (uint(input, "currentN"), uint(input, "incomingN"))
    else {
        return protocol_error("invalid-encoding");
    };
    let skipped = uint(input, "skippedKeyCount").or_else(|| uint(input, "retainedSkippedKeys"));
    let Some(skipped) = skipped else {
        return protocol_error("invalid-encoding");
    };
    let Some(distance) = incoming.checked_sub(current) else {
        return result(json!({ "error": "replay", "stateMutation": false }));
    };
    if distance > 256
        || skipped
            .checked_add(distance)
            .is_none_or(|total| total > 1024)
    {
        return result(json!({ "error": "skip-bound", "stateMutation": false }));
    }
    let Some(committed) = incoming
        .checked_add(1)
        .filter(|value| *value <= u64::from(u32::MAX))
    else {
        return result(
            json!({ "error": "counter-overflow", "stateMutation": false, "plaintextReleased": false }),
        );
    };
    result(json!({
        "derivedSkippedCoordinates": (current..incoming).collect::<Vec<_>>(),
        "committedN": committed,
        "incomingKeyRetained": false,
        "plaintextReleasedAfterCommit": true
    }))
}

fn restart_session(input: &Value) -> Expected {
    let (Some(restored), Some(committed)) = (
        uint(input, "restoredGeneration"),
        uint(input, "committedGeneration"),
    ) else {
        return protocol_error("invalid-encoding");
    };
    if restored < committed {
        result(
            json!({ "error": "state-rollback", "packetEmitted": false, "plaintextReleased": false }),
        )
    } else if restored == committed {
        result(json!({ "restored": true }))
    } else {
        result(json!({ "error": "invalid-transition", "stateMutation": false }))
    }
}

fn send_first_packet(input: &Value) -> Expected {
    if input.get("durableCommit") == Some(&Value::Bool(false)) {
        result(json!({ "error": "persistence", "emittedPackets": 0, "stateMutation": false }))
    } else {
        result(json!({ "emittedPackets": 1 }))
    }
}

fn send_record(input: &Value) -> Expected {
    if input.get("role").and_then(Value::as_str) == Some("responder") {
        if ["freshLocalRatchetKey", "peerRatchetKey", "sendingChain"]
            .iter()
            .any(|key| input.get(*key).is_none())
        {
            return protocol_error("invalid-encoding");
        }
        return result(json!({
            "steps": ["X25519", "HKDF-extract-current-root", "derive-nextRootR2I", "derive-nextChainR2I", "commit-before-emission"],
            "headerUsesFreshDh": true
        }));
    }
    let Some(n) = uint(input, "n") else {
        return protocol_error("invalid-encoding");
    };
    if n >= u64::from(u32::MAX) {
        return result(
            json!({ "error": "counter-overflow", "packetEmitted": false, "stateMutation": false }),
        );
    }
    result(json!({ "packetEmitted": true }))
}

fn validate_hybrid(input: &Value) -> Expected {
    let zero = input
        .get("x25519SharedSecret")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "all-zero" || value == "00".repeat(32));
    if zero {
        result(json!({ "error": "handshake-rejected", "stateMutation": false }))
    } else {
        result(json!({ "valid": true }))
    }
}

fn validate_shapes(input: &Value, context: &Value) -> Expected {
    if input.get("profileLocator").and_then(Value::as_str) != Some("stable-core")
        || context
            .get("publicMaterial")
            .and_then(Value::as_array)
            .is_none()
    {
        return protocol_error("unknown-profile");
    }
    result(json!({
        "mlKem768": { "dkSeed": 64, "encapsulationKey": 1184, "ciphertext": 1088, "sharedSecret": 32 },
        "mlDsa65": { "seed": 32, "publicKey": 1952, "signature": 3309 },
        "x25519": { "privateKey": 32, "publicKey": 32, "sharedSecret": 32 },
        "ed25519": { "seed": 32, "publicKey": 32, "signature": 64 },
        "chacha20Poly1305": { "key": 32, "nonce": 12, "tag": 16 },
        "hmacSha256": 32
    }))
}

fn verify_handshake(
    input: &Value,
    line: &VerifiedProtocolLine,
    provider: &impl Provider,
) -> Expected {
    let verify = || -> Result<(), Error> {
        let bytes = |name: &str| -> Result<Vec<u8>, Error> {
            decode_hex(
                input
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| failure(ErrorCode::InvalidRepresentation))?,
            )
            .map_err(|_| failure(ErrorCode::InvalidRepresentation))
        };
        let fixed = |name: &str| -> Result<[u8; 32], Error> {
            bytes(name)?
                .try_into()
                .map_err(|_| failure(ErrorCode::InvalidRepresentation))
        };
        let packet = crate::endpoint::decode_first_packet(&bytes("firstPacketCanonicalHex")?)?;
        if &packet.protocol_line_id != line.protocol_line_id()
            || &packet.protection_profile_id != line.protection_profile_id()
        {
            return Err(failure(ErrorCode::InvalidRepresentation));
        }
        let identity = crate::endpoint::IdentityPublic {
            state_digest: fixed("identityStateDigest")?,
            ed25519_key_id: fixed("ed25519KeyId")?,
            ed25519_public: fixed("ed25519PublicKey")?,
            ml_dsa_65_key_id: fixed("mlDsa65KeyId")?,
            ml_dsa_65_public: bytes("mlDsa65PublicKey")?,
        };
        crate::endpoint::verify_handshake_authentication(provider, &identity, &packet)
    };
    if verify().is_ok() {
        result(json!({ "accepted": true, "stateMutation": false }))
    } else {
        result(
            json!({ "error": "handshake-rejected", "stateMutation": false, "primitiveDetailDisclosed": false }),
        )
    }
}

fn verify_session_accept(input: &Value) -> Expected {
    if uint(input, "macBytes") != Some(32) {
        result(json!({ "error": "invalid-encoding", "stateMutation": false }))
    } else {
        result(json!({ "valid": true }))
    }
}

fn validate_security(input: &Value, line: &VerifiedProtocolLine) -> Expected {
    let Some(root) = input.as_object() else {
        return protocol_error("reject-closed-schema");
    };
    if root.keys().any(|key| {
        !matches!(
            key.as_str(),
            "adversaries" | "bindings" | "claims" | "registry" | "schemas"
        )
    }) || root.len() != 5
        || root
            .get("registry")
            .and_then(Value::as_object)
            .is_some_and(|registry| registry.keys().any(|key| key == "unknown"))
    {
        return protocol_error("reject-closed-schema");
    }
    let claims = root
        .get("claims")
        .and_then(|v| v.get("claims"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let nonclaims = root
        .get("claims")
        .and_then(|v| v.get("nonClaims"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if claims.iter().any(|claim| {
        ["id", "property"].iter().any(|key| {
            claim
                .get(*key)
                .and_then(Value::as_str)
                .is_some_and(|value| nonclaims.iter().any(|item| item.as_str() == Some(value)))
        })
    }) {
        return protocol_error("reject-nonclaim-promoted-to-claim");
    }
    let claim_ids = claims
        .iter()
        .filter_map(|claim| claim.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let expected_claim_ids = line
        .source("spec/v1/manifest.json")
        .ok()
        .and_then(|manifest| manifest.get("stableClaimIds"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if claim_ids.is_empty() || claim_ids != expected_claim_ids {
        return protocol_error("reject-missing-required-claim");
    }
    let adversary_ids = root
        .get("adversaries")
        .and_then(|v| v.get("models"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|model| model.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if claims
        .iter()
        .flat_map(|claim| {
            claim
                .get("adversary")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .any(|id| id.as_str().is_none_or(|id| !adversary_ids.contains(id)))
    {
        return protocol_error("reject-unknown-adversary");
    }
    let bindings = root
        .get("bindings")
        .and_then(|v| v.get("bindings"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if claims
        .iter()
        .filter(|claim| claim.get("status").and_then(Value::as_str) == Some("proved"))
        .any(|claim| {
            claim.get("id").and_then(Value::as_str).is_none_or(|id| {
                !bindings
                    .iter()
                    .any(|binding| binding.get("claimId").and_then(Value::as_str) == Some(id))
            })
        })
    {
        return protocol_error("reject-missing-proof-binding");
    }
    if bindings.iter().any(|binding| {
        binding
            .get("claimId")
            .and_then(Value::as_str)
            .is_none_or(|id| !claim_ids.contains(id))
            || binding
                .get("authorityPath")
                .and_then(Value::as_str)
                .is_some_and(|path| !path.starts_with("spec/") && !path.starts_with("docs/"))
    }) {
        return protocol_error("reject-wrong-authority");
    }
    let mut proved = claim_ids.into_iter().map(str::to_owned).collect::<Vec<_>>();
    proved.sort();
    result(json!({ "complete": true, "provedClaimIds": proved, "explicitNonClaimIds": [] }))
}

fn cbor_from_json(value: &Value) -> Result<CborValue, Error> {
    match value {
        Value::Bool(value) => Ok(CborValue::Bool(*value)),
        Value::Number(value) => value.as_u64().map(CborValue::Unsigned).ok_or_else(invalid),
        Value::String(value) => match value.strip_prefix("base64:") {
            Some(value) => decode_base64(value).map(CborValue::Bytes),
            None => Ok(CborValue::Text(value.clone())),
        },
        Value::Array(values) => values
            .iter()
            .map(cbor_from_json)
            .collect::<Result<Vec<_>, _>>()
            .map(CborValue::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| {
                let key = key.parse::<u64>().map_err(|_| invalid())?;
                Ok((key, cbor_from_json(value)?))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(CborValue::Map),
        Value::Null => Ok(CborValue::Null),
    }
}

fn json_from_cbor(value: &CborValue) -> Value {
    match value {
        CborValue::Null => Value::Null,
        CborValue::Unsigned(value) => json!(value),
        CborValue::Bytes(value) => Value::String(format!("base64:{}", encode_base64(value))),
        CborValue::Text(value) => Value::String(value.clone()),
        CborValue::Bool(value) => json!(value),
        CborValue::Array(values) => Value::Array(values.iter().map(json_from_cbor).collect()),
        CborValue::Map(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.to_string(), json_from_cbor(value)))
                .collect(),
        ),
    }
}

fn result(value: Value) -> Expected {
    Expected::Result(value)
}
fn protocol_error(code: &str) -> Expected {
    Expected::Error(ExpectedError {
        code: code.to_owned(),
    })
}
fn string_values(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}
fn uint(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}
fn hex_field(value: &Value, key: &str) -> Result<Vec<u8>, Error> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(invalid)
        .and_then(decode_hex)
}
fn fixed_hex<const N: usize>(value: &Value, key: &str) -> Result<[u8; N], Error> {
    hex_field(value, key)?.try_into().map_err(|_| invalid())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2) {
        return Err(invalid());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

fn digit(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid()),
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(4) {
        return Err(invalid());
    }
    let chunks = value.as_bytes().chunks_exact(4);
    let chunk_count = chunks.len();
    let mut output = Vec::with_capacity(chunk_count.saturating_mul(3));
    for (index, chunk) in chunks.enumerate() {
        let final_chunk = index + 1 == chunk_count;
        if chunk[0] == b'='
            || chunk[1] == b'='
            || (!final_chunk && chunk[3] == b'=')
            || (chunk[2] == b'=' && chunk[3] != b'=')
        {
            return Err(invalid());
        }
        let a = base64_digit(chunk[0])?;
        let b = base64_digit(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_digit(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_digit(chunk[3])?
        };
        if (chunk[2] == b'=' && b & 0x0f != 0) || (chunk[3] == b'=' && c & 0x03 != 0) {
            return Err(invalid());
        }
        let n = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        output.push((n >> 16) as u8);
        if chunk[2] != b'=' {
            output.push((n >> 8) as u8);
        }
        if chunk[3] != b'=' {
            output.push(n as u8);
        }
    }
    Ok(output)
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((n >> 18) & 63) as usize] as char);
        output.push(TABLE[((n >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn base64_digit(value: u8) -> Result<u8, Error> {
    match value {
        b'A'..=b'Z' => Ok(value - b'A'),
        b'a'..=b'z' => Ok(value - b'a' + 26),
        b'0'..=b'9' => Ok(value - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(invalid()),
    }
}

const fn invalid() -> Error {
    failure(ErrorCode::InvalidRepresentation)
}
const fn failure(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::provider::{DigestProvider, RustCryptoProvider};

    const ED25519_PROFILE: &str =
        "176b912b9547ca9c47ace10f881457ab63fcd493ef953616f5859e76b830fd60";
    const ML_DSA_65_PROFILE: &str =
        "427e788bb9aed076acc2fb5a94715d14e694ec5fbc846ac52c8c7e118a6b1b8f";

    #[test]
    fn authority_digests_and_signing_inputs_match_arc_shared_fixed_vector() {
        let provider = RustCryptoProvider;
        let management = fixed_vector_keys("management", 0x0a, 0x0b, 0x0c, 0x0d);
        let recovery = fixed_vector_keys("recovery", 0x14, 0x15, 0x16, 0x17);
        let user_ref = identity::derive_user_identity_ref(&provider, &management, &recovery)
            .expect("fixed user identity");
        let device = json!({
            "endpointIdentityRef": "bb".repeat(32),
            "identityStateDigest": "cc".repeat(32),
            "deviceStatus": "active",
            "admittedAuthorityEpoch": 0,
            "possessionProof": fixed_vector_signatures(
                "device-possession", 0x1e, 0x1f, 0x20, 0x21,
            ),
        });
        let state = json!({
            "recordType": "userAuthorityState",
            "protocolLineId": "aa".repeat(32),
            "userIdentityRef": hex(&user_ref),
            "authorityEpoch": 0,
            "authorityTransitionKind": "genesis",
            "managementSigningKeys": management,
            "recoverySigningKeys": recovery,
            "authorizedDevices": [device.clone()],
            "authoritySignatures": fixed_vector_signatures(
                "authority-genesis", 0x0a, 0x2a, 0x0c, 0x2b,
            ),
        });

        assert_eq!(
            hex(&user_ref),
            "c73b9b2483d43ef992159c8bf84d65efac0f712f6bd2edb29d28ed7a3941931b"
        );
        assert_eq!(
            hex(&identity::user_authority_state_digest(&provider, &state).expect("state digest")),
            "c91d9ba34346d35bf039ead202878364efd304ad5c9c9c6f60e8b57db7c37181"
        );
        assert_eq!(
            hex(&identity::authority_signature_input(&provider, &state).expect("authority input")),
            concat!(
                "4c49434f4152432d56312f555345522d415554484f524954592d53544154452f5349474e00",
                "c91d9ba34346d35bf039ead202878364efd304ad5c9c9c6f60e8b57db7c37181"
            )
        );
        assert_eq!(
            hex(&identity::device_possession_input(&state, &device).expect("device input")),
            concat!(
                "4c49434f4152432d56312f555345522d415554484f524954592f4445564943452d504f5353455353494f4e00",
                "855820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5820c73b9b2483d43ef992159c8bf84d65efac0f712f6bd2edb29d28ed7a3941931b005820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb5820cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            )
        );
        let replacement =
            identity::replacement_possession_input(&state).expect("replacement possession input");
        assert_eq!(replacement.len(), 4437);
        assert_eq!(
            hex(&provider.sha256(&replacement)),
            "bdc64ba431f64a4d2c50e95ff4ae8e047474833b7dd5633e31dc288091bbd4e7"
        );
    }

    #[test]
    fn unchanged_and_newly_revoked_devices_preserve_admission_evidence() {
        let provider = RustCryptoProvider;
        let fixture = authority_fixture(&provider).expect("authority fixture");
        let accepted = identity::validate_user_authority_state(
            &provider,
            &fixture.genesis,
            None,
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        )
        .expect("genesis authority");

        for mutation in ["admitted-epoch", "possession-proof", "revocation-identity"] {
            let mut successor = authority_successor_skeleton(
                &provider,
                &fixture.genesis,
                &fixture.management,
                "management",
            )
            .expect("successor skeleton");
            match mutation {
                "admitted-epoch" => {
                    successor["authorizedDevices"][0]["admittedAuthorityEpoch"] = json!(1)
                }
                "possession-proof" => {
                    successor["authorizedDevices"][0]["possessionProof"][0]["signatureValue"] =
                        Value::String("ff".repeat(64))
                }
                "revocation-identity" => {
                    successor["authorizedDevices"][0]["identityStateDigest"] =
                        Value::String(hex(&provider.sha256(b"rewritten-endpoint-state")));
                    successor["authorizedDevices"][0]["deviceStatus"] =
                        Value::String("revoked".to_owned());
                    successor["authorizedDevices"][0]["revokedAuthorityEpoch"] = json!(1);
                }
                _ => unreachable!(),
            }
            sign_authority_state(
                &provider,
                &mut successor,
                &fixture.management,
                "authority-management",
            )
            .expect("authority signature");
            assert_eq!(
                identity::validate_user_authority_state(
                    &provider,
                    &successor,
                    Some(&accepted.state),
                    fixture.protocol_line_id,
                    &fixture.endpoint_states,
                )
                .expect_err("mutated admission evidence must fail")
                .code,
                ErrorCode::AuthorizationFailed,
            );
        }
    }

    #[test]
    fn recovery_replacement_and_protected_replay_use_verified_state() {
        let provider = RustCryptoProvider;
        let fixture = authority_fixture(&provider).expect("authority fixture");
        let accepted = identity::validate_user_authority_state(
            &provider,
            &fixture.genesis,
            None,
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        )
        .expect("genesis authority");
        let new_management = authority_pair(&provider, "management", 60);
        let new_recovery = authority_pair(&provider, "recovery", 70);
        let mut recovered = authority_successor_skeleton(
            &provider,
            &fixture.genesis,
            &fixture.recovery,
            "recovery",
        )
        .expect("recovery successor");
        recovered["managementSigningKeys"] = Value::Array(new_management.keys.clone());
        recovered["recoverySigningKeys"] = Value::Array(new_recovery.keys.clone());
        let proof_input = identity::replacement_possession_input(&recovered)
            .expect("replacement possession input");
        recovered["possessionProof"] = json!({
            "managementSignatures": authority_signatures(
                &provider,
                &new_management,
                &proof_input,
                "replacement-management-possession",
            ),
            "recoverySignatures": authority_signatures(
                &provider,
                &new_recovery,
                &proof_input,
                "replacement-recovery-possession",
            ),
        });
        sign_authority_state(
            &provider,
            &mut recovered,
            &fixture.recovery,
            "authority-recovery",
        )
        .expect("recovery authority signature");
        identity::validate_user_authority_state(
            &provider,
            &recovered,
            Some(&accepted.state),
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        )
        .expect("replacement keys prove possession");

        let session = identity::AuthenticatedAuthoritySession {
            authenticated: true,
            authority_state_digest: accepted.state_digest,
            endpoint_identity_ref: fixture.endpoint_identity_ref,
            identity_state_digest: fixture.identity_state_digest,
        };
        let replay = identity::admit_protected_authority_payload(
            &provider,
            Some(&accepted),
            &session,
            &fixture.genesis,
            fixture.protocol_line_id,
            &fixture.endpoint_states,
        )
        .expect("exact accepted authority replay");
        assert_eq!(replay, accepted);
    }

    fn fixed_vector_keys(
        purpose: &str,
        ed_key: u8,
        ed_public: u8,
        ml_key: u8,
        ml_public: u8,
    ) -> Vec<Value> {
        vec![
            json!({
                "keyId": format!("{ed_key:02x}").repeat(32),
                "keyPurpose": purpose,
                "keyProfileId": ED25519_PROFILE,
                "publicKey": format!("{ed_public:02x}").repeat(32),
            }),
            json!({
                "keyId": format!("{ml_key:02x}").repeat(32),
                "keyPurpose": purpose,
                "keyProfileId": ML_DSA_65_PROFILE,
                "publicKey": format!("{ml_public:02x}").repeat(1952),
            }),
        ]
    }

    fn fixed_vector_signatures(
        purpose: &str,
        ed_key: u8,
        ed_value: u8,
        ml_key: u8,
        ml_value: u8,
    ) -> Vec<Value> {
        vec![
            json!({
                "keyProfileId": ED25519_PROFILE,
                "keyId": format!("{ed_key:02x}").repeat(32),
                "signaturePurpose": purpose,
                "signatureValue": format!("{ed_value:02x}").repeat(64),
            }),
            json!({
                "keyProfileId": ML_DSA_65_PROFILE,
                "keyId": format!("{ml_key:02x}").repeat(32),
                "signaturePurpose": purpose,
                "signatureValue": format!("{ml_value:02x}").repeat(3309),
            }),
        ]
    }
}
