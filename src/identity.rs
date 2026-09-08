use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{
    artifact::canonical_json,
    encoding::{self, CborValue},
    error::{Error, ErrorCode, Stage},
    provider::{DigestProvider, SignatureProvider},
};

pub const MAX_CHAIN_RECORDS: u64 = 64;
const MAX_EPOCH: u64 = 9_007_199_254_740_991;
const ED25519_PROFILE_ID: &str = "176b912b9547ca9c47ace10f881457ab63fcd493ef953616f5859e76b830fd60";
const ML_DSA_65_PROFILE_ID: &str =
    "427e788bb9aed076acc2fb5a94715d14e694ec5fbc846ac52c8c7e118a6b1b8f";
const USER_IDENTITY_DOMAIN: &[u8] = b"LICOARC-V1/USER-IDENTITY-REF\0";
const AUTHORITY_STATE_DOMAIN: &[u8] = b"LICOARC-V1/USER-AUTHORITY-STATE\0";
const AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"LICOARC-V1/USER-AUTHORITY-STATE/SIGN\0";
const DEVICE_POSSESSION_DOMAIN: &[u8] = b"LICOARC-V1/USER-AUTHORITY/DEVICE-POSSESSION\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointStateKeys {
    pub endpoint_identity_ref: [u8; 32],
    pub identity_state_digest: [u8; 32],
    pub ed25519_key_id: [u8; 32],
    pub ed25519_public: [u8; 32],
    pub ml_dsa_65_key_id: [u8; 32],
    pub ml_dsa_65_public: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedUserAuthority {
    pub state: Value,
    pub user_identity_ref: [u8; 32],
    pub authority_epoch: u64,
    pub state_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedAuthoritySession {
    pub authenticated: bool,
    pub authority_state_digest: [u8; 32],
    pub endpoint_identity_ref: [u8; 32],
    pub identity_state_digest: [u8; 32],
}

pub fn derive_user_identity_ref(
    provider: &impl DigestProvider,
    management: &[Value],
    recovery: &[Value],
) -> Result<[u8; 32], Error> {
    validate_authority_keys(management, "management")?;
    validate_authority_keys(recovery, "recovery")?;
    let projection = CborValue::Array(vec![
        authority_key_projection(management)?,
        authority_key_projection(recovery)?,
    ]);
    Ok(provider.sha256(&domain_input(
        USER_IDENTITY_DOMAIN,
        &encoding::encode(&projection)?,
    )))
}

pub fn user_authority_state_digest(
    provider: &impl DigestProvider,
    state: &Value,
) -> Result<[u8; 32], Error> {
    validate_definition_record(state)?;
    let projection = authority_state_projection(
        state
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?,
    )?;
    Ok(provider.sha256(&domain_input(
        AUTHORITY_STATE_DOMAIN,
        &encoding::encode(&projection)?,
    )))
}

pub fn authority_signature_input(
    provider: &impl DigestProvider,
    state: &Value,
) -> Result<Vec<u8>, Error> {
    Ok(domain_input(
        AUTHORITY_SIGNATURE_DOMAIN,
        &user_authority_state_digest(provider, state)?,
    ))
}

pub fn device_possession_input(state: &Value, device: &Value) -> Result<Vec<u8>, Error> {
    let record = state
        .as_object()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    let item = device
        .as_object()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    let projection = CborValue::Array(vec![
        CborValue::Bytes(decoded_hex::<32>(record, "protocolLineId")?.to_vec()),
        CborValue::Bytes(decoded_hex::<32>(record, "userIdentityRef")?.to_vec()),
        CborValue::Unsigned(unsigned(record, "authorityEpoch")?),
        CborValue::Bytes(decoded_hex::<32>(item, "endpointIdentityRef")?.to_vec()),
        CborValue::Bytes(decoded_hex::<32>(item, "identityStateDigest")?.to_vec()),
    ]);
    Ok(domain_input(
        DEVICE_POSSESSION_DOMAIN,
        &encoding::encode(&projection)?,
    ))
}

pub fn replacement_possession_input(state: &Value) -> Result<Vec<u8>, Error> {
    let record = state
        .as_object()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    let projection = CborValue::Array(vec![
        CborValue::Text("AuthorityKeyReplacementV1".to_owned()),
        CborValue::Bytes(decoded_hex::<32>(record, "protocolLineId")?.to_vec()),
        CborValue::Bytes(decoded_hex::<32>(record, "userIdentityRef")?.to_vec()),
        CborValue::Unsigned(unsigned(record, "authorityEpoch")?),
        authority_key_projection(array(record, "managementSigningKeys")?)?,
        authority_key_projection(array(record, "recoverySigningKeys")?)?,
    ]);
    Ok(domain_input(
        DEVICE_POSSESSION_DOMAIN,
        &encoding::encode(&projection)?,
    ))
}

pub fn validate_user_authority_state<P: DigestProvider + SignatureProvider>(
    provider: &P,
    state: &Value,
    predecessor: Option<&Value>,
    expected_protocol_line_id: [u8; 32],
    endpoint_states: &[EndpointStateKeys],
) -> Result<AcceptedUserAuthority, Error> {
    validate_definition_record(state)?;
    let record = state
        .as_object()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    let epoch = unsigned(record, "authorityEpoch")?;
    let user_ref = decoded_hex::<32>(record, "userIdentityRef")?;
    if decoded_hex::<32>(record, "protocolLineId")? != expected_protocol_line_id {
        return Err(validation(ErrorCode::AuthorizationFailed));
    }
    let transition = text(record, "authorityTransitionKind")?;
    let management = array(record, "managementSigningKeys")?;
    let recovery = array(record, "recoverySigningKeys")?;
    validate_authority_keys(management, "management")?;
    validate_authority_keys(recovery, "recovery")?;
    if let Some(previous) = predecessor {
        validate_definition_record(previous)?;
    }
    let previous_record = predecessor
        .map(|previous| {
            previous
                .as_object()
                .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))
        })
        .transpose()?;
    let signing_keys = match (transition, previous_record) {
        ("genesis", None)
            if epoch == 0
                && !record.contains_key("previousUserAuthorityStateDigest")
                && !record.contains_key("possessionProof")
                && user_ref == derive_user_identity_ref(provider, management, recovery)? =>
        {
            management
        }
        ("management", Some(previous_record)) | ("recovery", Some(previous_record)) => {
            let digest = user_authority_state_digest(
                provider,
                predecessor.ok_or_else(|| validation(ErrorCode::InvalidTransition))?,
            )?;
            if epoch
                != unsigned(previous_record, "authorityEpoch")?
                    .checked_add(1)
                    .ok_or_else(|| validation(ErrorCode::BoundExceeded))?
                || record
                    .get("previousUserAuthorityStateDigest")
                    .and_then(Value::as_str)
                    != Some(hex_bytes(&digest).as_str())
                || record.get("userIdentityRef") != previous_record.get("userIdentityRef")
                || record.get("protocolLineId") != previous_record.get("protocolLineId")
            {
                return Err(validation(ErrorCode::Conflict));
            }
            if transition == "management"
                && record.get("recoverySigningKeys") != previous_record.get("recoverySigningKeys")
            {
                return Err(validation(ErrorCode::AuthorizationFailed));
            }
            validate_roster_transition(
                array(previous_record, "authorizedDevices")?,
                array(record, "authorizedDevices")?,
                epoch,
            )?;
            array(
                previous_record,
                if transition == "management" {
                    "managementSigningKeys"
                } else {
                    "recoverySigningKeys"
                },
            )?
        }
        _ => return Err(validation(ErrorCode::InvalidTransition)),
    };
    let digest = user_authority_state_digest(provider, state)?;
    verify_signature_pair(
        provider,
        array(record, "authoritySignatures")?,
        signing_keys,
        match transition {
            "genesis" => "authority-genesis",
            "management" => "authority-management",
            _ => "authority-recovery",
        },
        &domain_input(AUTHORITY_SIGNATURE_DOMAIN, &digest),
    )?;
    let devices = array(record, "authorizedDevices")?;
    if devices.is_empty() || devices.len() > 16 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let mut previous_ref: Option<[u8; 32]> = None;
    let prior_devices = previous_record
        .map(|previous| array(previous, "authorizedDevices"))
        .transpose()?
        .unwrap_or_default();
    for device in devices {
        let item = device
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        let endpoint_ref = decoded_hex::<32>(item, "endpointIdentityRef")?;
        if previous_ref.is_some_and(|value| value >= endpoint_ref) {
            return Err(validation(ErrorCode::InvalidRepresentation));
        }
        previous_ref = Some(endpoint_ref);
        let identity_digest = decoded_hex::<32>(item, "identityStateDigest")?;
        let unchanged = prior_devices.iter().any(|prior| {
            prior.as_object().is_some_and(|prior| {
                prior.get("endpointIdentityRef") == item.get("endpointIdentityRef")
                    && prior.get("identityStateDigest") == item.get("identityStateDigest")
            })
        });
        if unchanged {
            continue;
        }
        if predecessor.is_none()
            && (text(item, "deviceStatus")? != "active"
                || item.get("admittedAuthorityEpoch").and_then(Value::as_u64) != Some(epoch))
        {
            return Err(validation(ErrorCode::AuthorizationFailed));
        }
        let endpoint = endpoint_states
            .iter()
            .find(|candidate| {
                candidate.endpoint_identity_ref == endpoint_ref
                    && candidate.identity_state_digest == identity_digest
            })
            .ok_or_else(|| validation(ErrorCode::AuthorizationFailed))?;
        let admitted = unsigned(item, "admittedAuthorityEpoch")?;
        let endpoint_keys = endpoint_key_values(endpoint);
        verify_signature_pair(
            provider,
            array(item, "possessionProof")?,
            &endpoint_keys,
            "device-possession",
            &device_possession_input(state, device)?,
        )?;
        match text(item, "deviceStatus")? {
            "active" if admitted <= epoch && !item.contains_key("revokedAuthorityEpoch") => {}
            "revoked"
                if item
                    .get("revokedAuthorityEpoch")
                    .and_then(Value::as_u64)
                    .is_some_and(|revoked| revoked >= admitted && revoked <= epoch) => {}
            _ => return Err(validation(ErrorCode::InvalidTransition)),
        }
    }
    if let Some(previous) = previous_record {
        let management_changed =
            record.get("managementSigningKeys") != previous.get("managementSigningKeys");
        let recovery_changed =
            record.get("recoverySigningKeys") != previous.get("recoverySigningKeys");
        if transition == "management" && management_changed {
            verify_replacement_possession(
                provider,
                state,
                record,
                management_changed,
                recovery_changed,
            )?;
        } else if transition == "management" && record.contains_key("possessionProof") {
            return Err(validation(ErrorCode::InvalidTransition));
        } else if transition == "recovery" {
            verify_replacement_possession(
                provider,
                state,
                record,
                management_changed,
                recovery_changed,
            )?;
        }
    }
    Ok(AcceptedUserAuthority {
        state: state.clone(),
        user_identity_ref: user_ref,
        authority_epoch: epoch,
        state_digest: digest,
    })
}

pub fn apply_user_authority_catch_up<P: DigestProvider + SignatureProvider>(
    provider: &P,
    accepted: Option<&AcceptedUserAuthority>,
    snapshots: &[Value],
    expected_protocol_line_id: [u8; 32],
    endpoint_states: &[EndpointStateKeys],
) -> Result<AcceptedUserAuthority, Error> {
    if snapshots.is_empty() || snapshots.len() > MAX_CHAIN_RECORDS as usize {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let mut current = accepted.cloned();
    let mut siblings = BTreeMap::<Option<[u8; 32]>, [u8; 32]>::new();
    for snapshot in snapshots {
        let record = snapshot
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        let parent = record
            .get("previousUserAuthorityStateDigest")
            .map(|_| decoded_hex::<32>(record, "previousUserAuthorityStateDigest"))
            .transpose()?;
        let digest = user_authority_state_digest(provider, snapshot)?;
        if siblings
            .insert(parent, digest)
            .is_some_and(|prior| prior != digest)
        {
            return Err(validation(ErrorCode::Conflict));
        }
        current = Some(validate_user_authority_state(
            provider,
            snapshot,
            current.as_ref().map(|value| &value.state),
            expected_protocol_line_id,
            endpoint_states,
        )?);
    }
    current.ok_or_else(|| validation(ErrorCode::BoundExceeded))
}

pub fn admit_protected_authority_payload<P: DigestProvider + SignatureProvider>(
    provider: &P,
    accepted: Option<&AcceptedUserAuthority>,
    session: &AuthenticatedAuthoritySession,
    state: &Value,
    expected_protocol_line_id: [u8; 32],
    endpoint_states: &[EndpointStateKeys],
) -> Result<AcceptedUserAuthority, Error> {
    if !session.authenticated {
        return Err(validation(ErrorCode::AuthenticationFailed));
    }
    let payload_digest = user_authority_state_digest(provider, state)?;
    let result = match accepted {
        Some(current) if current.state_digest == payload_digest => current.clone(),
        _ => validate_user_authority_state(
            provider,
            state,
            accepted.map(|current| &current.state),
            expected_protocol_line_id,
            endpoint_states,
        )?,
    };
    if payload_digest != session.authority_state_digest
        || result.state_digest != session.authority_state_digest
    {
        return Err(validation(ErrorCode::AuthenticationFailed));
    }
    if result
        .state
        .as_object()
        .map(|record| decoded_hex::<32>(record, "protocolLineId"))
        .transpose()?
        != Some(expected_protocol_line_id)
    {
        return Err(validation(ErrorCode::AuthorizationFailed));
    }
    let devices = result
        .state
        .as_object()
        .and_then(|value| value.get("authorizedDevices"))
        .and_then(Value::as_array)
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    let active = devices.iter().any(|device| {
        device.as_object().is_some_and(|value| {
            value.get("endpointIdentityRef").and_then(Value::as_str)
                == Some(hex_bytes(&session.endpoint_identity_ref).as_str())
                && value.get("identityStateDigest").and_then(Value::as_str)
                    == Some(hex_bytes(&session.identity_state_digest).as_str())
                && value.get("deviceStatus").and_then(Value::as_str) == Some("active")
        })
    });
    if !active {
        return Err(validation(ErrorCode::AuthorizationFailed));
    }
    Ok(result)
}

fn domain_input(domain: &[u8], input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + input.len());
    output.extend_from_slice(domain);
    output.extend_from_slice(input);
    output
}

fn authority_state_projection(record: &Map<String, Value>) -> Result<CborValue, Error> {
    let previous = record
        .get("previousUserAuthorityStateDigest")
        .map(|_| decoded_hex::<32>(record, "previousUserAuthorityStateDigest"))
        .transpose()?
        .map_or(CborValue::Null, |value| CborValue::Bytes(value.to_vec()));
    let possession = record.get("possessionProof").map_or_else(
        || Ok(CborValue::Null),
        |value| {
            replacement_proof_projection(
                value
                    .as_object()
                    .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?,
            )
        },
    )?;
    Ok(CborValue::Array(vec![
        CborValue::Text("UserAuthorityStateV1".to_owned()),
        CborValue::Bytes(decoded_hex::<32>(record, "protocolLineId")?.to_vec()),
        CborValue::Bytes(decoded_hex::<32>(record, "userIdentityRef")?.to_vec()),
        CborValue::Unsigned(unsigned(record, "authorityEpoch")?),
        previous,
        CborValue::Text(text(record, "authorityTransitionKind")?.to_owned()),
        authority_key_projection(array(record, "managementSigningKeys")?)?,
        authority_key_projection(array(record, "recoverySigningKeys")?)?,
        CborValue::Array(
            array(record, "authorizedDevices")?
                .iter()
                .map(device_projection)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        possession,
    ]))
}

fn authority_key_projection(values: &[Value]) -> Result<CborValue, Error> {
    Ok(CborValue::Array(
        values
            .iter()
            .map(|value| {
                let key = value
                    .as_object()
                    .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
                Ok(CborValue::Array(vec![
                    CborValue::Bytes(decoded_hex::<32>(key, "keyId")?.to_vec()),
                    CborValue::Text(text(key, "keyPurpose")?.to_owned()),
                    CborValue::Bytes(decoded_hex::<32>(key, "keyProfileId")?.to_vec()),
                    CborValue::Bytes(decode_hex_text(text(key, "publicKey")?)?),
                ]))
            })
            .collect::<Result<Vec<_>, Error>>()?,
    ))
}

fn device_projection(value: &Value) -> Result<CborValue, Error> {
    let device = value
        .as_object()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    let revoked = device
        .get("revokedAuthorityEpoch")
        .map_or(CborValue::Null, |value| {
            value
                .as_u64()
                .map(CborValue::Unsigned)
                .unwrap_or(CborValue::Null)
        });
    Ok(CborValue::Array(vec![
        CborValue::Bytes(decoded_hex::<32>(device, "endpointIdentityRef")?.to_vec()),
        CborValue::Bytes(decoded_hex::<32>(device, "identityStateDigest")?.to_vec()),
        CborValue::Text(text(device, "deviceStatus")?.to_owned()),
        CborValue::Unsigned(unsigned(device, "admittedAuthorityEpoch")?),
        revoked,
        signature_projection(array(device, "possessionProof")?)?,
    ]))
}

fn replacement_proof_projection(proof: &Map<String, Value>) -> Result<CborValue, Error> {
    let signatures = |name| {
        proof.get(name).map_or_else(
            || Ok(CborValue::Null),
            |value| {
                signature_projection(
                    value
                        .as_array()
                        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?,
                )
            },
        )
    };
    Ok(CborValue::Array(vec![
        signatures("managementSignatures")?,
        signatures("recoverySignatures")?,
    ]))
}

fn signature_projection(values: &[Value]) -> Result<CborValue, Error> {
    Ok(CborValue::Array(
        values
            .iter()
            .map(|value| {
                let signature = value
                    .as_object()
                    .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
                Ok(CborValue::Array(vec![
                    CborValue::Bytes(decoded_hex::<32>(signature, "keyProfileId")?.to_vec()),
                    CborValue::Bytes(decoded_hex::<32>(signature, "keyId")?.to_vec()),
                    CborValue::Text(text(signature, "signaturePurpose")?.to_owned()),
                    CborValue::Bytes(decode_hex_text(text(signature, "signatureValue")?)?),
                ]))
            })
            .collect::<Result<Vec<_>, Error>>()?,
    ))
}

fn validate_roster_transition(previous: &[Value], next: &[Value], epoch: u64) -> Result<(), Error> {
    let previous_by_ref = device_map(previous)?;
    let next_by_ref = device_map(next)?;
    for (endpoint, prior) in &previous_by_ref {
        let Some(current) = next_by_ref.get(endpoint) else {
            if text(prior, "deviceStatus")? == "active" {
                return Err(validation(ErrorCode::AuthorizationFailed));
            }
            continue;
        };
        if text(prior, "deviceStatus")? == "revoked" {
            if *prior != *current {
                return Err(validation(ErrorCode::AuthorizationFailed));
            }
            continue;
        }
        if text(current, "deviceStatus")? == "revoked" {
            if current.get("identityStateDigest") != prior.get("identityStateDigest")
                || current.get("admittedAuthorityEpoch") != prior.get("admittedAuthorityEpoch")
                || current.get("possessionProof") != prior.get("possessionProof")
                || current.get("revokedAuthorityEpoch").and_then(Value::as_u64) != Some(epoch)
            {
                return Err(validation(ErrorCode::AuthorizationFailed));
            }
        } else if current.get("identityStateDigest") == prior.get("identityStateDigest") {
            if current.get("admittedAuthorityEpoch") != prior.get("admittedAuthorityEpoch")
                || current.get("possessionProof") != prior.get("possessionProof")
            {
                return Err(validation(ErrorCode::AuthorizationFailed));
            }
        } else if current
            .get("admittedAuthorityEpoch")
            .and_then(Value::as_u64)
            != Some(epoch)
        {
            return Err(validation(ErrorCode::AuthorizationFailed));
        }
    }
    for (endpoint, current) in next_by_ref {
        if !previous_by_ref.contains_key(&endpoint)
            && (text(current, "deviceStatus")? != "active"
                || current
                    .get("admittedAuthorityEpoch")
                    .and_then(Value::as_u64)
                    != Some(epoch))
        {
            return Err(validation(ErrorCode::AuthorizationFailed));
        }
    }
    Ok(())
}

fn device_map(values: &[Value]) -> Result<BTreeMap<[u8; 32], &Map<String, Value>>, Error> {
    values
        .iter()
        .map(|value| {
            let device = value
                .as_object()
                .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
            Ok((decoded_hex::<32>(device, "endpointIdentityRef")?, device))
        })
        .collect()
}

fn verify_replacement_possession<P: SignatureProvider>(
    provider: &P,
    state: &Value,
    record: &Map<String, Value>,
    management_changed: bool,
    recovery_changed: bool,
) -> Result<(), Error> {
    if !management_changed && !recovery_changed {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    let proof = record
        .get("possessionProof")
        .and_then(Value::as_object)
        .ok_or_else(|| validation(ErrorCode::AuthorizationFailed))?;
    let input = replacement_possession_input(state)?;
    for (changed, field, keys, purpose) in [
        (
            management_changed,
            "managementSignatures",
            "managementSigningKeys",
            "replacement-management-possession",
        ),
        (
            recovery_changed,
            "recoverySignatures",
            "recoverySigningKeys",
            "replacement-recovery-possession",
        ),
    ] {
        if changed {
            verify_signature_pair(
                provider,
                proof
                    .get(field)
                    .and_then(Value::as_array)
                    .ok_or_else(|| validation(ErrorCode::AuthorizationFailed))?,
                array(record, keys)?,
                purpose,
                &input,
            )?;
        } else if proof.contains_key(field) {
            return Err(validation(ErrorCode::InvalidTransition));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuityFailure {
    Bound,
    Gap,
    Fork,
    Replay,
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainTip {
    pub endpoint: [u8; 32],
    pub epoch: u64,
    pub digest: [u8; 32],
}

pub fn validate_successor(
    current: Option<&ChainTip>,
    next: &ChainTip,
    predecessor: Option<&[u8; 32]>,
) -> Result<(), Error> {
    if next.epoch == 0
        || next.epoch > MAX_EPOCH
        || current.is_some_and(|tip| tip.epoch == 0 || tip.epoch >= MAX_EPOCH)
    {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    match current {
        None if next.epoch == 1 && predecessor.is_none() => Ok(()),
        Some(current)
            if next.endpoint == current.endpoint
                && next.epoch == current.epoch + 1
                && predecessor == Some(&current.digest) =>
        {
            Ok(())
        }
        Some(current) if next.epoch <= current.epoch => Err(validation(ErrorCode::Conflict)),
        _ => Err(validation(ErrorCode::InvalidTransition)),
    }
}

/// Validates the closed, non-cryptographic projection of a current Identity record.
/// Signature authenticity remains a caller-owned fact and is deliberately not inferred
/// from placeholder corpus bytes.
pub fn validate_definition_record(value: &Value) -> Result<(), Error> {
    let mut input_budget = 0_usize;
    validate_json_bounds(value, 0, &mut input_budget)?;
    if canonical_json(value)
        .map_err(|error| validation(error.code))?
        .len()
        > 65_536
    {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let record = value
        .as_object()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    match text(record, "recordType")? {
        "identityUpdate" => validate_identity_update(record),
        "affiliationUpdate" => validate_affiliation_update(record),
        "routeUpdate" => validate_route_update(record),
        "firstContact" => validate_first_contact(record),
        "discoveryInput" => validate_discovery(record),
        "transparencyBundle" => validate_transparency(record),
        "userAuthorityState" => validate_user_authority_record(record),
        "stationDescriptor" => validate_station_descriptor(record),
        _ => Err(validation(ErrorCode::UnknownField)),
    }
}

fn validate_user_authority_record(record: &Map<String, Value>) -> Result<(), Error> {
    closed(
        record,
        &[
            "recordType",
            "protocolLineId",
            "userIdentityRef",
            "authorityEpoch",
            "previousUserAuthorityStateDigest",
            "authorityTransitionKind",
            "managementSigningKeys",
            "recoverySigningKeys",
            "authorizedDevices",
            "possessionProof",
            "authoritySignatures",
        ],
        &[
            "protocolLineId",
            "userIdentityRef",
            "authorityEpoch",
            "authorityTransitionKind",
            "managementSigningKeys",
            "recoverySigningKeys",
            "authorizedDevices",
            "authoritySignatures",
        ],
    )?;
    hex_field(record, "protocolLineId", 32)?;
    hex_field(record, "userIdentityRef", 32)?;
    let epoch = unsigned(record, "authorityEpoch")?;
    let transition = text(record, "authorityTransitionKind")?;
    if (epoch == 0) != (transition == "genesis")
        || (epoch == 0) == record.contains_key("previousUserAuthorityStateDigest")
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    if let Some(value) = record.get("previousUserAuthorityStateDigest") {
        hex_value(value, 32)?;
    }
    validate_authority_keys(array(record, "managementSigningKeys")?, "management")?;
    validate_authority_keys(array(record, "recoverySigningKeys")?, "recovery")?;
    let devices = array(record, "authorizedDevices")?;
    if devices.is_empty() || devices.len() > 16 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let mut prior_endpoint: Option<[u8; 32]> = None;
    for device in devices {
        let item = device
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        closed(
            item,
            &[
                "endpointIdentityRef",
                "identityStateDigest",
                "deviceStatus",
                "admittedAuthorityEpoch",
                "revokedAuthorityEpoch",
                "possessionProof",
            ],
            &[
                "endpointIdentityRef",
                "identityStateDigest",
                "deviceStatus",
                "admittedAuthorityEpoch",
                "possessionProof",
            ],
        )?;
        let endpoint = decoded_hex::<32>(item, "endpointIdentityRef")?;
        if prior_endpoint.is_some_and(|prior| prior >= endpoint) {
            return Err(validation(ErrorCode::Conflict));
        }
        prior_endpoint = Some(endpoint);
        hex_field(item, "identityStateDigest", 32)?;
        let admitted = unsigned(item, "admittedAuthorityEpoch")?;
        if admitted > epoch {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        match text(item, "deviceStatus")? {
            "active" if !item.contains_key("revokedAuthorityEpoch") => {}
            "revoked" if item.contains_key("revokedAuthorityEpoch") => {
                let revoked = unsigned(item, "revokedAuthorityEpoch")?;
                if revoked < admitted || revoked > epoch {
                    return Err(validation(ErrorCode::InvalidTransition));
                }
            }
            _ => return Err(validation(ErrorCode::InvalidTransition)),
        }
        validate_signature_array(array(item, "possessionProof")?)?;
    }
    if let Some(proof) = record.get("possessionProof") {
        let proof = proof
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        closed(proof, &["managementSignatures", "recoverySignatures"], &[])?;
        if proof.is_empty() {
            return Err(validation(ErrorCode::InvalidRepresentation));
        }
        for field in ["managementSignatures", "recoverySignatures"] {
            if let Some(signatures) = proof.get(field) {
                validate_signature_array(
                    signatures
                        .as_array()
                        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?,
                )?;
            }
        }
    }
    validate_signature_array(array(record, "authoritySignatures")?)
}

fn validate_authority_keys(values: &[Value], purpose: &str) -> Result<(), Error> {
    if values.len() != 2 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let mut profiles = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let key = value
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        closed(
            key,
            &["keyId", "keyPurpose", "keyProfileId", "publicKey"],
            &["keyId", "keyPurpose", "keyProfileId", "publicKey"],
        )?;
        if text(key, "keyPurpose")? != purpose {
            return Err(validation(ErrorCode::AuthorizationFailed));
        }
        hex_field(key, "keyId", 32)?;
        validate_public_key(key)?;
        let expected_profile = if index == 0 {
            ED25519_PROFILE_ID
        } else {
            ML_DSA_65_PROFILE_ID
        };
        if text(key, "keyProfileId")? != expected_profile {
            return Err(validation(ErrorCode::AuthorizationFailed));
        }
        if !profiles.insert(text(key, "keyProfileId")?) || !ids.insert(text(key, "keyId")?) {
            return Err(validation(ErrorCode::Conflict));
        }
    }
    if profiles != std::collections::BTreeSet::from([ED25519_PROFILE_ID, ML_DSA_65_PROFILE_ID]) {
        return Err(validation(ErrorCode::AuthorizationFailed));
    }
    Ok(())
}

fn validate_signature_array(values: &[Value]) -> Result<(), Error> {
    if values.len() != 2 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let mut ids = std::collections::BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let signature = value
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        validate_signature(signature, None)?;
        let expected_profile = if index == 0 {
            ED25519_PROFILE_ID
        } else {
            ML_DSA_65_PROFILE_ID
        };
        if text(signature, "keyProfileId")? != expected_profile
            || !ids.insert(text(signature, "keyId")?)
        {
            return Err(validation(ErrorCode::AuthorizationFailed));
        }
    }
    Ok(())
}

fn endpoint_key_values(keys: &EndpointStateKeys) -> Vec<Value> {
    vec![
        serde_json::json!({"keyId":hex_bytes(&keys.ed25519_key_id),"keyPurpose":"device","keyProfileId":ED25519_PROFILE_ID,"publicKey":hex_bytes(&keys.ed25519_public)}),
        serde_json::json!({"keyId":hex_bytes(&keys.ml_dsa_65_key_id),"keyPurpose":"device","keyProfileId":ML_DSA_65_PROFILE_ID,"publicKey":hex_bytes(&keys.ml_dsa_65_public)}),
    ]
}

fn verify_signature_pair<P: SignatureProvider>(
    provider: &P,
    signatures: &[Value],
    keys: &[Value],
    purpose: &str,
    message: &[u8],
) -> Result<(), Error> {
    if signatures.len() != 2 || keys.len() != 2 {
        return Err(validation(ErrorCode::AuthorizationFailed));
    }
    for signature in signatures {
        let sig = signature
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        validate_signature(sig, Some(purpose))?;
        let key_id = text(sig, "keyId")?;
        let profile = text(sig, "keyProfileId")?;
        let key = keys
            .iter()
            .filter_map(Value::as_object)
            .find(|key| {
                key.get("keyId").and_then(Value::as_str) == Some(key_id)
                    && key.get("keyProfileId").and_then(Value::as_str) == Some(profile)
            })
            .ok_or_else(|| validation(ErrorCode::AuthorizationFailed))?;
        let public = decode_hex_text(text(key, "publicKey")?)?;
        let signature = decode_hex_text(text(sig, "signatureValue")?)?;
        match profile {
            ED25519_PROFILE_ID => provider
                .ed25519_verify_strict(
                    &public
                        .try_into()
                        .map_err(|_| validation(ErrorCode::InvalidRepresentation))?,
                    message,
                    &signature
                        .try_into()
                        .map_err(|_| validation(ErrorCode::InvalidRepresentation))?,
                )
                .map_err(|_| validation(ErrorCode::AuthenticationFailed))?,
            ML_DSA_65_PROFILE_ID => provider
                .ml_dsa_65_verify(&public, message, &signature)
                .map_err(|_| validation(ErrorCode::AuthenticationFailed))?,
            _ => return Err(validation(ErrorCode::UnknownField)),
        }
    }
    Ok(())
}

fn decoded_hex<const N: usize>(object: &Map<String, Value>, key: &str) -> Result<[u8; N], Error> {
    decode_hex_text(text(object, key)?)?
        .try_into()
        .map_err(|_| validation(ErrorCode::InvalidRepresentation))
}
fn decode_hex_text(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2) {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| validation(ErrorCode::InvalidRepresentation))
        })
        .collect()
}
fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_json_bounds(
    value: &Value,
    depth: usize,
    input_budget: &mut usize,
) -> Result<(), Error> {
    if depth > 16 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let local_bytes = match value {
        Value::String(value) => value.len(),
        Value::Object(values) => values.keys().map(String::len).sum(),
        _ => 1,
    };
    *input_budget = input_budget
        .checked_add(local_bytes)
        .filter(|bytes| *bytes <= 65_536)
        .ok_or_else(|| validation(ErrorCode::BoundExceeded))?;
    match value {
        Value::String(value) if value.len() > 8_192 => Err(validation(ErrorCode::BoundExceeded)),
        Value::Array(values) if values.len() > 64 => Err(validation(ErrorCode::BoundExceeded)),
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_json_bounds(value, depth + 1, input_budget)),
        Value::Object(values)
            if values.len() > 64 || values.keys().any(|key| key.len() > 4_096) =>
        {
            Err(validation(ErrorCode::BoundExceeded))
        }
        Value::Object(values) => values
            .values()
            .try_for_each(|value| validate_json_bounds(value, depth + 1, input_budget)),
        _ => Ok(()),
    }
}

pub fn validate_epoch_sequence<T: Eq>(
    epochs: &[u64],
    digests: Option<&[T]>,
) -> Result<(), ContinuityFailure> {
    if epochs.len() > MAX_CHAIN_RECORDS as usize || epochs.iter().any(|epoch| *epoch > MAX_EPOCH) {
        return Err(ContinuityFailure::Bound);
    }
    if epochs.first() != Some(&1) {
        return Err(ContinuityFailure::Rollback);
    }
    if digests.is_some_and(|values| values.len() != epochs.len()) {
        return Err(ContinuityFailure::Fork);
    }
    for index in 1..epochs.len() {
        let previous = epochs[index - 1];
        let next = epochs[index];
        if next == previous {
            let replay = digests.is_some_and(|values| values[index] == values[index - 1]);
            return Err(if replay {
                ContinuityFailure::Replay
            } else {
                ContinuityFailure::Fork
            });
        }
        if next < previous {
            return Err(ContinuityFailure::Rollback);
        }
        if previous.checked_add(1) != Some(next) {
            return Err(ContinuityFailure::Gap);
        }
    }
    Ok(())
}

fn validate_identity_update(record: &Map<String, Value>) -> Result<(), Error> {
    closed(
        record,
        &[
            "recordType",
            "protocolLineId",
            "endpointIdentityRef",
            "identityEpoch",
            "previousIdentityStateDigest",
            "transition",
            "stateDigest",
            "keyAuthorizations",
            "revokedKeyDigests",
            "recoveryProof",
            "continuityProof",
            "endpointSignature",
        ],
        &[
            "protocolLineId",
            "endpointIdentityRef",
            "identityEpoch",
            "transition",
            "stateDigest",
            "keyAuthorizations",
            "continuityProof",
            "endpointSignature",
        ],
    )?;
    hex_field(record, "protocolLineId", 32)?;
    hex_field(record, "endpointIdentityRef", 32)?;
    hex_field(record, "stateDigest", 32)?;
    let epoch = epoch(record, "identityEpoch")?;
    let transition = text(record, "transition")?;
    let predecessor = record.get("previousIdentityStateDigest");
    match transition {
        "genesis" if epoch == 1 && predecessor.is_none() => {
            if record.contains_key("revokedKeyDigests") || record.contains_key("recoveryProof") {
                return Err(validation(ErrorCode::InvalidTransition));
            }
        }
        "rotation" if epoch >= 2 && predecessor.is_some() => {}
        "revocation"
            if epoch >= 2
                && predecessor.is_some()
                && record
                    .get("revokedKeyDigests")
                    .and_then(Value::as_array)
                    .is_some_and(|values| !values.is_empty()) => {}
        "recovery"
            if epoch >= 2 && predecessor.is_some() && record.contains_key("recoveryProof") => {}
        _ => return Err(validation(ErrorCode::InvalidTransition)),
    }
    if let Some(value) = predecessor {
        hex_value(value, 32)?;
    }
    let keys = array(record, "keyAuthorizations")?;
    if keys.is_empty() || keys.len() > 4 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    reject_duplicates(keys)?;
    keys.iter().try_for_each(validate_key_authorization)?;
    if let Some(revoked) = optional_array(record, "revokedKeyDigests")? {
        if revoked.len() > 4 {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        reject_duplicates(revoked)?;
        revoked.iter().try_for_each(|value| hex_value(value, 32))?;
    }
    if let Some(recovery) = record.get("recoveryProof") {
        validate_recovery_proof(
            recovery
                .as_object()
                .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?,
        )?;
    }
    let proof = object(record, "continuityProof")?;
    validate_continuity_proof(proof, transition, predecessor)?;
    validate_signature(
        object(record, "endpointSignature")?,
        Some("endpoint-continuity"),
    )
}

fn validate_affiliation_update(record: &Map<String, Value>) -> Result<(), Error> {
    closed(
        record,
        &[
            "recordType",
            "protocolLineId",
            "endpointIdentityRef",
            "affiliationEpoch",
            "previousAffiliationUpdateDigest",
            "transition",
            "stationAffiliations",
            "stateDigest",
            "endpointSignature",
        ],
        &[
            "protocolLineId",
            "endpointIdentityRef",
            "affiliationEpoch",
            "transition",
            "stationAffiliations",
            "stateDigest",
            "endpointSignature",
        ],
    )?;
    hex_field(record, "protocolLineId", 32)?;
    hex_field(record, "endpointIdentityRef", 32)?;
    hex_field(record, "stateDigest", 32)?;
    let epoch = epoch(record, "affiliationEpoch")?;
    let predecessor = record.get("previousAffiliationUpdateDigest");
    let transition = text(record, "transition")?;
    if !matches!(
        transition,
        "genesis" | "migration" | "rotation" | "revocation" | "recovery"
    ) || (epoch == 1) != (transition == "genesis")
        || (epoch == 1) != predecessor.is_none()
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    if let Some(value) = predecessor {
        hex_value(value, 32)?;
    }
    let affiliations = array(record, "stationAffiliations")?;
    if affiliations.len() > 4 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    reject_duplicates(affiliations)?;
    for affiliation in affiliations {
        let item = affiliation
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        closed(
            item,
            &[
                "stationDescriptorDigest",
                "affiliationCommitment",
                "affiliationNonce",
                "affiliationNotAfter",
                "stationAffiliationSignature",
            ],
            &[
                "stationDescriptorDigest",
                "affiliationCommitment",
                "affiliationNonce",
                "affiliationNotAfter",
                "stationAffiliationSignature",
            ],
        )?;
        hex_field(item, "stationDescriptorDigest", 32)?;
        hex_field(item, "affiliationCommitment", 32)?;
        hex_field(item, "affiliationNonce", 32)?;
        unsigned(item, "affiliationNotAfter")?;
        validate_signature(
            object(item, "stationAffiliationSignature")?,
            Some("station-affiliation"),
        )?;
    }
    validate_signature(
        object(record, "endpointSignature")?,
        Some("endpoint-continuity"),
    )
}

fn validate_route_update(record: &Map<String, Value>) -> Result<(), Error> {
    closed(
        record,
        &[
            "recordType",
            "protocolLineId",
            "endpointIdentityRef",
            "peerEndpointIdentityRef",
            "routeEpoch",
            "previousRouteUpdateDigest",
            "transition",
            "affiliationStateDigest",
            "routeNotAfter",
            "routes",
            "endpointSignature",
        ],
        &[
            "protocolLineId",
            "endpointIdentityRef",
            "peerEndpointIdentityRef",
            "routeEpoch",
            "transition",
            "affiliationStateDigest",
            "routeNotAfter",
            "routes",
            "endpointSignature",
        ],
    )?;
    for field in [
        "protocolLineId",
        "endpointIdentityRef",
        "peerEndpointIdentityRef",
        "affiliationStateDigest",
    ] {
        hex_field(record, field, 32)?;
    }
    let epoch = epoch(record, "routeEpoch")?;
    let predecessor = record.get("previousRouteUpdateDigest");
    let transition = text(record, "transition")?;
    if !matches!(
        transition,
        "genesis" | "migration" | "rotation" | "revocation" | "recovery"
    ) || (epoch == 1) != (transition == "genesis")
        || (epoch == 1) != predecessor.is_none()
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    if let Some(value) = predecessor {
        hex_value(value, 32)?;
    }
    unsigned(record, "routeNotAfter")?;
    let routes = array(record, "routes")?;
    if routes.is_empty() || routes.len() > 4 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    reject_duplicates(routes)?;
    for route in routes {
        let route = route
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        closed(
            route,
            &[
                "stationDescriptorDigest",
                "affiliationCommitment",
                "transportProfileId",
                "handleClass",
                "deliveryHandle",
                "serviceUntil",
                "stationServiceSignature",
            ],
            &[
                "stationDescriptorDigest",
                "affiliationCommitment",
                "transportProfileId",
                "handleClass",
                "deliveryHandle",
                "serviceUntil",
                "stationServiceSignature",
            ],
        )?;
        for field in [
            "stationDescriptorDigest",
            "affiliationCommitment",
            "transportProfileId",
            "deliveryHandle",
        ] {
            hex_field(route, field, 32)?;
        }
        unsigned(route, "serviceUntil")?;
        if text(route, "handleClass")? != "async" {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        validate_signature(
            object(route, "stationServiceSignature")?,
            Some("station-route-service"),
        )?;
    }
    validate_signature(
        object(record, "endpointSignature")?,
        Some("endpoint-continuity"),
    )
}

fn validate_first_contact(record: &Map<String, Value>) -> Result<(), Error> {
    closed(
        record,
        &[
            "recordType",
            "handleClass",
            "deliveryHandle",
            "audienceDigest",
            "invitationBinding",
            "purpose",
            "singleUse",
            "expiresAt",
            "protectedInvitation",
            "peerVerificationState",
        ],
        &[
            "handleClass",
            "deliveryHandle",
            "audienceDigest",
            "invitationBinding",
            "purpose",
            "singleUse",
            "expiresAt",
            "protectedInvitation",
            "peerVerificationState",
        ],
    )?;
    if text(record, "handleClass")? != "firstContact"
        || text(record, "purpose")? != "firstContact"
        || record.get("singleUse") != Some(&Value::Bool(true))
        || text(record, "peerVerificationState")? != "unverified"
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    for field in ["deliveryHandle", "audienceDigest", "invitationBinding"] {
        hex_field(record, field, 32)?;
    }
    unsigned(record, "expiresAt")?;
    let invitation = object(record, "protectedInvitation")?;
    closed(
        invitation,
        &[
            "inviterEndpointIdentityRef",
            "inviteeEndpointIdentityRef",
            "invitationBinding",
            "purpose",
            "audienceDigest",
            "handshakeNonce",
        ],
        &[
            "inviterEndpointIdentityRef",
            "invitationBinding",
            "purpose",
            "audienceDigest",
        ],
    )?;
    for field in [
        "inviterEndpointIdentityRef",
        "invitationBinding",
        "audienceDigest",
    ] {
        hex_field(invitation, field, 32)?;
    }
    for field in ["inviteeEndpointIdentityRef", "handshakeNonce"] {
        if let Some(value) = invitation.get(field) {
            hex_value(value, 32)?;
        }
    }
    if invitation.get("invitationBinding") != record.get("invitationBinding")
        || invitation.get("audienceDigest") != record.get("audienceDigest")
        || invitation.get("purpose") != record.get("purpose")
        || text(invitation, "purpose")? != "firstContact"
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    Ok(())
}

fn validate_discovery(record: &Map<String, Value>) -> Result<(), Error> {
    closed(
        record,
        &[
            "recordType",
            "inputId",
            "sourceKind",
            "sourceRef",
            "subjectEndpointIdentityRef",
            "chainKind",
            "stateEpoch",
            "stateDigest",
            "statementDigest",
            "observedAt",
            "expiresAt",
            "sourceSignature",
            "authenticatedInputOnly",
        ],
        &[
            "inputId",
            "sourceKind",
            "sourceRef",
            "subjectEndpointIdentityRef",
            "chainKind",
            "stateEpoch",
            "stateDigest",
            "statementDigest",
            "observedAt",
            "expiresAt",
            "sourceSignature",
            "authenticatedInputOnly",
        ],
    )?;
    if !matches!(
        text(record, "sourceKind")?,
        "directory" | "witness" | "gossip" | "station"
    ) {
        return Err(validation(ErrorCode::UnknownField));
    }
    if !matches!(
        text(record, "chainKind")?,
        "identity" | "affiliation" | "route"
    ) || record.get("authenticatedInputOnly") != Some(&Value::Bool(true))
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    hex_field(record, "inputId", 16)?;
    for field in [
        "sourceRef",
        "subjectEndpointIdentityRef",
        "stateDigest",
        "statementDigest",
    ] {
        hex_field(record, field, 32)?;
    }
    epoch(record, "stateEpoch")?;
    unsigned(record, "observedAt")?;
    unsigned(record, "expiresAt")?;
    validate_signature(object(record, "sourceSignature")?, None)
}

fn validate_transparency(record: &Map<String, Value>) -> Result<(), Error> {
    closed(
        record,
        &[
            "recordType",
            "subjectEndpointIdentityRef",
            "chainKind",
            "stateEpoch",
            "stateDigest",
            "witnessInputs",
            "gossipInputs",
            "discoveryInputs",
            "stationSignatureInputs",
            "verificationInputs",
            "authority",
            "endpointRetainsContinuity",
            "splitView",
        ],
        &[
            "subjectEndpointIdentityRef",
            "chainKind",
            "stateEpoch",
            "stateDigest",
            "witnessInputs",
            "gossipInputs",
            "discoveryInputs",
            "stationSignatureInputs",
            "verificationInputs",
            "authority",
            "endpointRetainsContinuity",
        ],
    )?;
    if !matches!(
        text(record, "chainKind")?,
        "identity" | "affiliation" | "route"
    ) || text(record, "authority")? != "bounded-authenticated-input-only"
        || record.get("endpointRetainsContinuity") != Some(&Value::Bool(true))
        || record
            .get("splitView")
            .is_some_and(|value| !value.is_boolean())
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    hex_field(record, "subjectEndpointIdentityRef", 32)?;
    hex_field(record, "stateDigest", 32)?;
    epoch(record, "stateEpoch")?;
    for key in [
        "witnessInputs",
        "gossipInputs",
        "discoveryInputs",
        "stationSignatureInputs",
        "verificationInputs",
    ] {
        let inputs = array(record, key)?;
        if inputs.len() > 8 {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        reject_duplicates(inputs)?;
        inputs.iter().try_for_each(validate_authenticated_input)?;
    }
    Ok(())
}

fn validate_station_descriptor(record: &Map<String, Value>) -> Result<(), Error> {
    closed(
        record,
        &[
            "recordType",
            "stationId",
            "descriptorSequence",
            "previousDescriptorDigest",
            "notBefore",
            "notAfter",
            "listeners",
            "signingKeys",
            "certificationRefs",
            "signatures",
        ],
        &[
            "stationId",
            "descriptorSequence",
            "notBefore",
            "notAfter",
            "listeners",
            "signingKeys",
            "signatures",
        ],
    )?;
    hex_field(record, "stationId", 32)?;
    let sequence = epoch(record, "descriptorSequence")?;
    match (sequence, record.get("previousDescriptorDigest")) {
        (1, None) => {}
        (2.., Some(previous)) => hex_value(previous, 32)?,
        _ => return Err(validation(ErrorCode::InvalidTransition)),
    }
    let not_before = unsigned(record, "notBefore")?;
    let not_after = unsigned(record, "notAfter")?;
    if not_before >= not_after {
        return Err(validation(ErrorCode::InvalidTransition));
    }

    let listeners = array(record, "listeners")?;
    if listeners.is_empty() || listeners.len() > 4 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    reject_duplicates(listeners)?;
    for listener in listeners {
        let listener = listener
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        closed(
            listener,
            &["transportProfileId", "endpointUri"],
            &["transportProfileId", "endpointUri"],
        )?;
        hex_field(listener, "transportProfileId", 32)?;
        let endpoint = text(listener, "endpointUri")?;
        if endpoint.len() < 10
            || endpoint.len() > 128
            || !endpoint.starts_with("https://")
            || endpoint.contains('?')
            || endpoint.contains('#')
            || !endpoint.is_ascii()
        {
            return Err(validation(ErrorCode::InvalidRepresentation));
        }
    }

    let signing_keys = array(record, "signingKeys")?;
    if signing_keys.is_empty() || signing_keys.len() > 4 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    reject_duplicates(signing_keys)?;
    for key in signing_keys {
        let key = key
            .as_object()
            .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
        closed(
            key,
            &["keyProfileId", "keyId", "publicKey"],
            &["keyProfileId", "keyId", "publicKey"],
        )?;
        hex_field(key, "keyId", 32)?;
        validate_public_key(key)?;
    }

    if let Some(certifications) = optional_array(record, "certificationRefs")? {
        if certifications.is_empty() || certifications.len() > 4 {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        reject_duplicates(certifications)?;
        certifications
            .iter()
            .try_for_each(|value| hex_value(value, 32))?;
    }

    let signatures = array(record, "signatures")?;
    if signatures.is_empty() || signatures.len() > 4 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    reject_duplicates(signatures)?;
    signatures.iter().try_for_each(|signature| {
        validate_signature(
            signature
                .as_object()
                .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?,
            Some("station-descriptor"),
        )
    })
}

fn validate_key_authorization(value: &Value) -> Result<(), Error> {
    let value = value
        .as_object()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    closed(
        value,
        &[
            "keyId",
            "keyPurpose",
            "keyState",
            "keyProfileId",
            "publicKey",
            "validFromEpoch",
            "revokedAtEpoch",
        ],
        &[
            "keyId",
            "keyPurpose",
            "keyState",
            "keyProfileId",
            "publicKey",
            "validFromEpoch",
        ],
    )?;
    hex_field(value, "keyId", 32)?;
    validate_public_key(value)?;
    if !matches!(text(value, "keyPurpose")?, "identity" | "handshake")
        || !matches!(text(value, "keyState")?, "active" | "revoked" | "recovery")
    {
        return Err(validation(ErrorCode::UnknownField));
    }
    epoch(value, "validFromEpoch")?;
    if value.contains_key("revokedAtEpoch") {
        epoch(value, "revokedAtEpoch")?;
    }
    Ok(())
}

fn validate_recovery_proof(value: &Map<String, Value>) -> Result<(), Error> {
    closed(
        value,
        &["recoveryDigest", "witnesses"],
        &["recoveryDigest", "witnesses"],
    )?;
    hex_field(value, "recoveryDigest", 32)?;
    let witnesses = array(value, "witnesses")?;
    if witnesses.is_empty() || witnesses.len() > 4 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    reject_duplicates(witnesses)?;
    for witness in witnesses {
        validate_signature(
            witness
                .as_object()
                .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?,
            None,
        )?;
    }
    Ok(())
}

fn validate_continuity_proof(
    value: &Map<String, Value>,
    transition: &str,
    predecessor: Option<&Value>,
) -> Result<(), Error> {
    closed(
        value,
        &["proofKind", "predecessorStateDigest", "signature"],
        &["proofKind", "predecessorStateDigest", "signature"],
    )?;
    let proof_kind = text(value, "proofKind")?;
    if !matches!(
        proof_kind,
        "genesis" | "rotation" | "revocation" | "recovery" | "migration"
    ) || proof_kind != transition
        || match predecessor {
            None => value.get("predecessorStateDigest") != Some(&Value::Null),
            Some(predecessor) => value.get("predecessorStateDigest") != Some(predecessor),
        }
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    if let Some(predecessor) = predecessor {
        hex_value(predecessor, 32)?;
    }
    validate_signature(object(value, "signature")?, Some("endpoint-continuity"))
}

fn validate_authenticated_input(value: &Value) -> Result<(), Error> {
    let value = value
        .as_object()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    closed(
        value,
        &[
            "inputId",
            "inputKind",
            "sourceRef",
            "stateEpoch",
            "stateDigest",
            "statementDigest",
            "expiresAt",
            "signature",
            "authenticatedInputOnly",
        ],
        &[
            "inputId",
            "inputKind",
            "sourceRef",
            "stateEpoch",
            "stateDigest",
            "statementDigest",
            "expiresAt",
            "signature",
            "authenticatedInputOnly",
        ],
    )?;
    if !matches!(
        text(value, "inputKind")?,
        "witness" | "gossip" | "discovery" | "stationSignature" | "verificationRecord"
    ) || value.get("authenticatedInputOnly") != Some(&Value::Bool(true))
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    hex_field(value, "inputId", 16)?;
    for field in ["sourceRef", "stateDigest", "statementDigest"] {
        hex_field(value, field, 32)?;
    }
    epoch(value, "stateEpoch")?;
    unsigned(value, "expiresAt")?;
    validate_signature(object(value, "signature")?, None)
}

fn validate_signature(
    value: &Map<String, Value>,
    expected_purpose: Option<&str>,
) -> Result<(), Error> {
    closed(
        value,
        &[
            "keyProfileId",
            "keyId",
            "signaturePurpose",
            "signatureValue",
        ],
        &[
            "keyProfileId",
            "keyId",
            "signaturePurpose",
            "signatureValue",
        ],
    )?;
    hex_field(value, "keyId", 32)?;
    let purpose = text(value, "signaturePurpose")?;
    if !matches!(
        purpose,
        "endpoint-continuity"
            | "authority-genesis"
            | "authority-management"
            | "authority-recovery"
            | "device-possession"
            | "replacement-management-possession"
            | "replacement-recovery-possession"
            | "station-affiliation"
            | "station-route-service"
            | "witness"
            | "gossip"
            | "discovery"
            | "verification"
            | "station-descriptor"
    ) || expected_purpose.is_some_and(|expected| purpose != expected)
    {
        return Err(validation(ErrorCode::UnknownField));
    }
    let signature = value
        .get("signatureValue")
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    match text(value, "keyProfileId")? {
        ED25519_PROFILE_ID => hex_string_range(signature, 128, 128),
        ML_DSA_65_PROFILE_ID => hex_string_range(signature, 6_618, 6_618),
        _ => Err(validation(ErrorCode::UnknownField)),
    }
}

fn validate_public_key(value: &Map<String, Value>) -> Result<(), Error> {
    let public_key = value
        .get("publicKey")
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    match text(value, "keyProfileId")? {
        ED25519_PROFILE_ID => hex_string_range(public_key, 64, 64),
        ML_DSA_65_PROFILE_ID => hex_string_range(public_key, 3_904, 3_904),
        _ => Err(validation(ErrorCode::UnknownField)),
    }
}

fn closed(object: &Map<String, Value>, allowed: &[&str], required: &[&str]) -> Result<(), Error> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(validation(ErrorCode::UnknownField));
    }
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    Ok(())
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, Error> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))
}

fn unsigned(object: &Map<String, Value>, key: &str) -> Result<u64, Error> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))
}

fn epoch(object: &Map<String, Value>, key: &str) -> Result<u64, Error> {
    unsigned(object, key).and_then(|value| {
        if value == 0 {
            Err(validation(ErrorCode::InvalidRepresentation))
        } else {
            Ok(value)
        }
    })
}

fn array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], Error> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))
}

fn optional_array<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a [Value]>, Error> {
    object
        .get(key)
        .map(|value| {
            value
                .as_array()
                .map(Vec::as_slice)
                .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))
        })
        .transpose()
}

fn has_duplicates(values: &[Value]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[index + 1..].contains(value))
}

fn reject_duplicates(values: &[Value]) -> Result<(), Error> {
    if has_duplicates(values) {
        Err(validation(ErrorCode::InvalidRepresentation))
    } else {
        Ok(())
    }
}

fn object<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Map<String, Value>, Error> {
    object
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))
}

fn hex_field(object: &Map<String, Value>, key: &str, bytes: usize) -> Result<(), Error> {
    object
        .get(key)
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))
        .and_then(|value| hex_value(value, bytes))
}

fn hex_value(value: &Value, bytes: usize) -> Result<(), Error> {
    let value = value
        .as_str()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    Ok(())
}

fn hex_string_range(value: &Value, minimum: usize, maximum: usize) -> Result<(), Error> {
    let value = value
        .as_str()
        .ok_or_else(|| validation(ErrorCode::InvalidRepresentation))?;
    if !(minimum..=maximum).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    Ok(())
}

const fn validation(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}
