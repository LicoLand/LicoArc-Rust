use std::collections::{BTreeMap, BTreeSet};

use crate::{
    encoding::{self, CborValue},
    error::{Error, ErrorCode, Stage},
};

pub const MAX_RETRY_TRANSMISSIONS: u8 = 32;
pub const MAX_ROUTE_MIGRATIONS: u8 = 16;
pub const MAX_STATE_TRANSITIONS: u64 = 256;
pub const MAX_CONFIRMATION_IDS: usize = 32;
pub const MAX_ATTACHMENT_RETRANSMITTED_CHUNKS: u64 = 256;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const CLOSED_STATE_TAGS: &[&str] = &[
    "created",
    "in-flight",
    "ambiguous",
    "accepted",
    "effect-pending",
    "completed",
    "cancelled",
    "failed",
    "new",
    "pending-confirmation",
    "pending",
    "partial",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationStage {
    EndpointAccepted,
    EffectCompleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationOutcome {
    Succeeded,
    Rejected,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointConfirmation {
    pub confirmation_id: [u8; 16],
    pub confirmed_message_ids: Vec<[u8; 16]>,
    pub stage: ConfirmationStage,
    pub outcome: ConfirmationOutcome,
    pub failure_code: Option<u8>,
    pub result_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedSession {
    pub session_id: [u8; 16],
    pub sender_endpoint: [u8; 32],
    pub expected_sender_endpoint: [u8; 32],
    pub authenticated: bool,
    pub sender_authorized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalityState {
    Pending,
    Accepted,
    Completed,
    Rejected,
    Failed,
}

pub fn apply_endpoint_confirmation(
    current: FinalityState,
    logical_message_id: [u8; 16],
    confirmation: &EndpointConfirmation,
    session: &AuthorizedSession,
    expected_result_digest: Option<[u8; 32]>,
    attachment_complete: bool,
) -> Result<FinalityState, Error> {
    validate_confirmation_ids(&confirmation.confirmed_message_ids)?;
    if !session.authenticated {
        return Err(validation(ErrorCode::AuthenticationFailed));
    }
    if !session.sender_authorized || session.sender_endpoint != session.expected_sender_endpoint {
        return Err(validation(ErrorCode::AuthorizationFailed));
    }
    if confirmation
        .confirmed_message_ids
        .binary_search(&logical_message_id)
        .is_err()
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    let failure_expected = matches!(
        confirmation.outcome,
        ConfirmationOutcome::Rejected | ConfirmationOutcome::Failed
    );
    if failure_expected != confirmation.failure_code.is_some()
        || confirmation.failure_code.is_some_and(|code| code > 13)
        || (confirmation.outcome == ConfirmationOutcome::Succeeded
            && confirmation.failure_code.is_some())
    {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    if confirmation.stage == ConfirmationStage::EffectCompleted {
        if confirmation.outcome != ConfirmationOutcome::Succeeded {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        let Some(expected) = expected_result_digest else {
            return Err(validation(ErrorCode::InvalidTransition));
        };
        if confirmation.result_digest != Some(expected) {
            return Err(validation(ErrorCode::DigestMismatch));
        }
    } else if confirmation.result_digest.is_some() {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    if !attachment_complete {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    let next = match (confirmation.stage, confirmation.outcome) {
        (ConfirmationStage::EndpointAccepted, ConfirmationOutcome::Succeeded) => {
            FinalityState::Accepted
        }
        (ConfirmationStage::EffectCompleted, ConfirmationOutcome::Succeeded) => {
            FinalityState::Completed
        }
        (_, ConfirmationOutcome::Rejected) => FinalityState::Rejected,
        (_, ConfirmationOutcome::Failed) => FinalityState::Failed,
    };
    let rank = |state| match state {
        FinalityState::Pending => 0,
        FinalityState::Accepted => 1,
        FinalityState::Completed | FinalityState::Rejected | FinalityState::Failed => 2,
    };
    if current == next {
        return Ok(current);
    }
    if rank(next) <= rank(current)
        || matches!(
            current,
            FinalityState::Completed | FinalityState::Rejected | FinalityState::Failed
        )
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    Ok(next)
}
const EVENT_KINDS: &[&str] = &[
    "create",
    "send",
    "retry",
    "stationHint",
    "endpointAccepted",
    "effectCompleted",
    "cancel",
    "timeout",
    "routeChange",
    "attachmentState",
    "groupResult",
    "terminalFailure",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Pending,
    Accepted,
    EffectCompleted,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReliableState {
    pub intent_digest: [u8; 32],
    pub route_digest: [u8; 32],
    pub protected_packet_digest: [u8; 32],
    pub retries: u8,
    pub migrations: u8,
    pub transitions: u64,
    pub outcome: Outcome,
}

impl ReliableState {
    pub fn retry(
        &self,
        route: [u8; 32],
        intent: [u8; 32],
        protected_packet: [u8; 32],
    ) -> Result<Self, Error> {
        validate_counters(
            u64::from(self.retries),
            u64::from(self.migrations),
            self.transitions,
        )?;
        if matches!(self.outcome, Outcome::EffectCompleted | Outcome::Failed)
            || intent != self.intent_digest
            || (route == self.route_digest && protected_packet != self.protected_packet_digest)
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        let mut next = self.clone();
        if route == self.route_digest {
            next.retries = next
                .retries
                .checked_add(1)
                .filter(|v| *v <= MAX_RETRY_TRANSMISSIONS)
                .ok_or_else(|| validation(ErrorCode::BoundExceeded))?;
        } else {
            next.migrations = next
                .migrations
                .checked_add(1)
                .filter(|v| *v <= MAX_ROUTE_MIGRATIONS)
                .ok_or_else(|| validation(ErrorCode::BoundExceeded))?;
            next.route_digest = route;
        }
        next.protected_packet_digest = protected_packet;
        next.transitions = next
            .transitions
            .checked_add(1)
            .filter(|value| *value <= MAX_STATE_TRANSITIONS)
            .ok_or_else(|| validation(ErrorCode::BoundExceeded))?;
        Ok(next)
    }
}

pub fn validate_confirmation_ids(ids: &[[u8; 16]]) -> Result<(), Error> {
    if ids.is_empty() || ids.len() > MAX_CONFIRMATION_IDS {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    Ok(())
}

/// Validates the closed current `reliable-intent` runtime record.
pub fn validate_intent_record(value: &CborValue) -> Result<(), Error> {
    let values = closed_map(value, 0..=7, &[0, 1, 2, 3, 4, 5])?;
    fixed_bytes(values.get(&0), 16)?;
    fixed_bytes(values.get(&1), 32)?;
    ranged_bytes(values.get(&2), 1, 256)?;
    ranged_bytes(values.get(&3), 0, 262_144)?;
    bounded_unsigned(values.get(&4), u64::from(u32::MAX))?;
    fixed_bytes(values.get(&5), 32)?;
    optional_fixed_bytes(values.get(&6), 32)?;
    optional_fixed_bytes(values.get(&7), 16)
}

/// Validates the closed current `confirmation` runtime record and its
/// canonical bounded identity set.
pub fn validate_confirmation_record(value: &CborValue) -> Result<(), Error> {
    if encoding::encode(value)?.len() > 16_384 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let record = closed_map(value, 0..=5, &[0, 1, 2, 3])?;
    fixed_bytes(record.get(&0), 16)?;
    bounded_unsigned(record.get(&1), 1)?;
    bounded_unsigned(record.get(&2), 2)?;
    let Some(CborValue::Array(values)) = record.get(&3) else {
        return Err(validation(ErrorCode::InvalidRepresentation));
    };
    let ids = values
        .iter()
        .map(|value| match value {
            CborValue::Bytes(value) => value
                .as_slice()
                .try_into()
                .map_err(|_| validation(ErrorCode::InvalidRepresentation)),
            _ => Err(validation(ErrorCode::InvalidRepresentation)),
        })
        .collect::<Result<Vec<[u8; 16]>, Error>>()?;
    validate_confirmation_ids(&ids)?;
    optional_bounded_unsigned(record.get(&4), 13)?;
    optional_fixed_bytes(record.get(&5), 32)?;
    let stage = unsigned(record.get(&1))?;
    let outcome = unsigned(record.get(&2))?;
    let has_failure = record.contains_key(&4);
    let has_result = record.contains_key(&5);
    if has_failure != matches!(outcome, 1 | 2)
        || (outcome == 0 && has_failure)
        || has_result != (stage == 1 && outcome == 0)
    {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    Ok(())
}

/// Validates the closed current `state-snapshot` runtime record. Transition
/// authorization remains caller-owned and is deliberately not inferred here.
pub fn validate_snapshot_record(value: &CborValue) -> Result<(), Error> {
    encoding::encode(value)?;
    let values = closed_map(value, 0..=18, &[0, 1, 2, 3, 9])?;
    bounded_unsigned(values.get(&0), 3)?;
    bounded_unsigned(values.get(&1), 11)?;
    fixed_bytes(values.get(&2), 16)?;
    fixed_bytes(values.get(&3), 32)?;
    if values.contains_key(&4) {
        ranged_bytes(values.get(&4), 1, 256)?;
    }
    optional_unsigned(values.get(&5))?;
    optional_fixed_bytes(values.get(&6), 32)?;
    optional_bounded_unsigned(values.get(&7), u64::from(MAX_RETRY_TRANSMISSIONS))?;
    optional_bounded_unsigned(values.get(&8), u64::from(MAX_ROUTE_MIGRATIONS))?;
    bounded_unsigned(values.get(&9), MAX_STATE_TRANSITIONS)?;
    optional_bounded_unsigned(values.get(&10), 12)?;
    optional_fixed_bytes(values.get(&11), 32)?;
    optional_fixed_bytes(values.get(&12), 32)?;
    optional_fixed_bytes(values.get(&13), 16)?;
    optional_bounded_unsigned(values.get(&14), 32)?;
    optional_bounded_unsigned(values.get(&15), 64)?;
    if let Some(value) = values.get(&16) {
        validate_chunk_ranges(value)?;
    }
    if let Some(value) = values.get(&17) {
        validate_projection_results(value)?;
    }
    optional_fixed_bytes(values.get(&18), 32)
}

/// Validates the closed current `reliable-event` runtime record. Applying the
/// event still requires the caller's exact predecessor snapshot.
pub fn validate_event_record(value: &CborValue) -> Result<(), Error> {
    if encoding::encode(value)?.len() > 65_536 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let values = closed_map(value, 0..=14, &[0, 1, 2])?;
    bounded_unsigned(values.get(&0), 11)?;
    fixed_bytes(values.get(&1), 16)?;
    fixed_bytes(values.get(&2), 32)?;
    optional_unsigned(values.get(&3))?;
    if values.contains_key(&4) {
        ranged_bytes(values.get(&4), 1, 262_144)?;
    }
    optional_fixed_bytes(values.get(&5), 32)?;
    optional_fixed_bytes(values.get(&6), 32)?;
    optional_bounded_unsigned(values.get(&7), 12)?;
    optional_bounded_unsigned(values.get(&8), 3)?;
    optional_fixed_bytes(values.get(&9), 16)?;
    optional_fixed_bytes(values.get(&10), 32)?;
    optional_fixed_bytes(values.get(&11), 16)?;
    optional_bounded_unsigned(values.get(&12), 32)?;
    if let Some(value) = values.get(&13) {
        validate_chunk_ranges(value)?;
    }
    if let Some(value) = values.get(&14) {
        validate_projection_results(value)?;
    }
    Ok(())
}

fn validate_chunk_ranges(value: &CborValue) -> Result<(), Error> {
    let CborValue::Array(ranges) = value else {
        return Err(validation(ErrorCode::InvalidRepresentation));
    };
    if ranges.len() > 32 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let mut previous_end = None;
    let mut retransmitted_chunks = 0_u64;
    for range in ranges {
        let values = closed_map(range, 0..=1, &[0, 1])?;
        let start = unsigned(values.get(&0))?;
        let end = unsigned(values.get(&1))?;
        if start > MAX_SAFE_INTEGER
            || end > MAX_SAFE_INTEGER
            || start >= end
            || previous_end.is_some_and(|previous| start <= previous)
        {
            return Err(validation(ErrorCode::InvalidRepresentation));
        }
        retransmitted_chunks = retransmitted_chunks
            .checked_add(end - start)
            .filter(|count| *count <= MAX_ATTACHMENT_RETRANSMITTED_CHUNKS)
            .ok_or_else(|| validation(ErrorCode::BoundExceeded))?;
        previous_end = Some(end);
    }
    Ok(())
}

fn validate_projection_results(value: &CborValue) -> Result<(), Error> {
    let CborValue::Array(results) = value else {
        return Err(validation(ErrorCode::InvalidRepresentation));
    };
    if results.len() > 64 {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let mut previous_recipient = None;
    let mut projection_ids = BTreeSet::new();
    for result in results {
        let values = closed_map(result, 0..=4, &[0, 1, 2, 4])?;
        let id: [u8; 16] = match values.get(&0) {
            Some(CborValue::Bytes(value)) => value
                .as_slice()
                .try_into()
                .map_err(|_| validation(ErrorCode::InvalidRepresentation))?,
            _ => return Err(validation(ErrorCode::InvalidRepresentation)),
        };
        let recipient: [u8; 32] = match values.get(&1) {
            Some(CborValue::Bytes(value)) => value
                .as_slice()
                .try_into()
                .map_err(|_| validation(ErrorCode::InvalidRepresentation))?,
            _ => return Err(validation(ErrorCode::InvalidRepresentation)),
        };
        if !projection_ids.insert(id)
            || previous_recipient.is_some_and(|previous| previous >= recipient)
        {
            return Err(validation(ErrorCode::InvalidRepresentation));
        }
        previous_recipient = Some(recipient);
        bounded_unsigned(values.get(&2), 3)?;
        optional_bounded_unsigned(values.get(&3), 12)?;
        bounded_unsigned(values.get(&4), 1)?;
    }
    Ok(())
}

fn closed_map<'a>(
    value: &'a CborValue,
    allowed: std::ops::RangeInclusive<u64>,
    required: &[u64],
) -> Result<&'a BTreeMap<u64, CborValue>, Error> {
    let values = values_from(value)?;
    if values.keys().any(|key| !allowed.contains(key))
        || required.iter().any(|key| !values.contains_key(key))
    {
        return Err(validation(ErrorCode::UnknownField));
    }
    Ok(values)
}

fn values_from(value: &CborValue) -> Result<&BTreeMap<u64, CborValue>, Error> {
    match value {
        CborValue::Map(values) => Ok(values),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn unsigned(value: Option<&CborValue>) -> Result<u64, Error> {
    match value {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn bounded_unsigned(value: Option<&CborValue>, maximum: u64) -> Result<(), Error> {
    if unsigned(value)? > maximum {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    Ok(())
}

fn optional_unsigned(value: Option<&CborValue>) -> Result<(), Error> {
    if value.is_some() {
        unsigned(value)?;
    }
    Ok(())
}

fn optional_bounded_unsigned(value: Option<&CborValue>, maximum: u64) -> Result<(), Error> {
    if value.is_some() {
        bounded_unsigned(value, maximum)?;
    }
    Ok(())
}

fn ranged_bytes(value: Option<&CborValue>, minimum: usize, maximum: usize) -> Result<(), Error> {
    match value {
        Some(CborValue::Bytes(value)) if (minimum..=maximum).contains(&value.len()) => Ok(()),
        Some(CborValue::Bytes(_)) => Err(validation(ErrorCode::BoundExceeded)),
        _ => Err(validation(ErrorCode::InvalidRepresentation)),
    }
}

fn fixed_bytes(value: Option<&CborValue>, length: usize) -> Result<(), Error> {
    ranged_bytes(value, length, length)
}

fn optional_fixed_bytes(value: Option<&CborValue>, length: usize) -> Result<(), Error> {
    if value.is_some() {
        fixed_bytes(value, length)?;
    }
    Ok(())
}

pub fn validate_counters(retries: u64, migrations: u64, transitions: u64) -> Result<(), Error> {
    if retries > u64::from(MAX_RETRY_TRANSMISSIONS)
        || migrations > u64::from(MAX_ROUTE_MIGRATIONS)
        || transitions > MAX_STATE_TRANSITIONS
    {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    Ok(())
}

pub fn validate_route_successor(previous: u64, next: u64) -> Result<(), Error> {
    if previous > MAX_SAFE_INTEGER || next > MAX_SAFE_INTEGER {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    if next <= previous {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    Ok(())
}

pub fn validate_absorbing_state(current: &str, incoming_event: &str) -> Result<(), Error> {
    if !CLOSED_STATE_TAGS.contains(&current) || !EVENT_KINDS.contains(&incoming_event) {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    // An identical terminal replay cannot be established from names alone. A
    // caller using this narrow helper must therefore fail closed and use the
    // complete event/snapshot reducer to recognize an identical replay.
    if matches!(current, "completed" | "cancelled" | "failed") {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    Ok(())
}

pub fn validate_station_stage_authority(
    event_kind: &str,
    requested_stage: &str,
) -> Result<(), Error> {
    if !EVENT_KINDS.contains(&event_kind)
        || !matches!(
            requested_stage,
            "received" | "accepted" | "completed" | "terminal"
        )
    {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    if event_kind == "stationHint" && matches!(requested_stage, "accepted" | "completed") {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    Ok(())
}

pub fn validate_projection_outcome_successor(current: &str, incoming: &str) -> Result<(), Error> {
    let valid = |value: &str| matches!(value, "pending" | "delivered" | "rejected" | "failed");
    if !valid(current) || !valid(incoming) {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    if current != "pending" && current != incoming {
        return Err(validation(ErrorCode::Conflict));
    }
    Ok(())
}

const fn validation(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}
