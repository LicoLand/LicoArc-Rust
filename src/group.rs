use std::collections::BTreeSet;
use std::sync::Arc;

use crate::{
    encoding::{self, CborValue},
    error::{Error, ErrorCode, Stage},
    provider::DigestProvider,
    reliable::{
        AuthorizedSession, EndpointConfirmation, FinalityState, apply_endpoint_confirmation,
    },
};

pub const MAX_GROUP_MEMBERS: usize = 64;
pub const MAX_GROUP_PROJECTIONS: usize = 64;
pub const MAX_GROUP_PAYLOAD_BYTES: usize = 262_144;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MemberRole {
    Member,
    StateAuthority,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Member {
    pub endpoint: [u8; 32],
    pub role: MemberRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupOperation {
    Add(Member),
    Remove([u8; 32]),
    ChangeRole {
        endpoint: [u8; 32],
        role: MemberRole,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupState {
    pub group_id: [u8; 32],
    pub epoch: u64,
    pub previous_digest: Option<[u8; 32]>,
    pub members: Vec<Member>,
    pub transition_digest: [u8; 32],
}

#[derive(Clone, Eq, PartialEq)]
pub struct Projection {
    id: [u8; 16],
    message_id: [u8; 16],
    group_state_digest: [u8; 32],
    recipient: [u8; 32],
    payload: Arc<[u8]>,
}

impl std::fmt::Debug for Projection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Projection([REDACTED])")
    }
}

impl Projection {
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }

    #[must_use]
    pub const fn message_id(&self) -> &[u8; 16] {
        &self.message_id
    }

    #[must_use]
    pub const fn group_state_digest(&self) -> &[u8; 32] {
        &self.group_state_digest
    }

    #[must_use]
    pub const fn recipient(&self) -> &[u8; 32] {
        &self.recipient
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultOutcome {
    Pending,
    Delivered,
    Rejected,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultAuthority {
    EndpointConfirmation,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupResult {
    pub projection_id: [u8; 16],
    pub recipient: [u8; 32],
    pub outcome: ResultOutcome,
    pub failure_code: Option<u8>,
    pub authority: ResultAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateOutcome {
    Complete,
    Partial,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aggregate {
    pub outcome: AggregateOutcome,
    pub pending: usize,
    pub delivered: usize,
    pub rejected: usize,
    pub failed: usize,
}

pub fn apply_member_confirmation(
    projection: &Projection,
    current: FinalityState,
    confirmation: &EndpointConfirmation,
    session: &AuthorizedSession,
    expected_result_digest: Option<[u8; 32]>,
) -> Result<FinalityState, Error> {
    apply_endpoint_confirmation(
        current,
        projection.message_id,
        confirmation,
        session,
        expected_result_digest,
        true,
    )
}

impl GroupState {
    pub fn validate(&self) -> Result<(), Error> {
        if self.members.is_empty()
            || self.members.len() > MAX_GROUP_MEMBERS
            || self.epoch > 9_007_199_254_740_991
        {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        if (self.epoch == 0) != self.previous_digest.is_none() {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        if self
            .members
            .windows(2)
            .any(|pair| pair[0].endpoint >= pair[1].endpoint)
            || !self
                .members
                .iter()
                .any(|member| member.role == MemberRole::StateAuthority)
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        Ok(())
    }

    pub fn apply_transition(
        &self,
        digest_provider: &dyn DigestProvider,
        author: &[u8; 32],
        operation: GroupOperation,
    ) -> Result<Self, Error> {
        self.validate()?;
        if !self
            .members
            .iter()
            .any(|item| item.endpoint == *author && item.role == MemberRole::StateAuthority)
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        let mut members = self.members.clone();
        let operation_record = match operation {
            GroupOperation::Add(member) => {
                if members.len() == MAX_GROUP_MEMBERS
                    || members.iter().any(|item| item.endpoint == member.endpoint)
                {
                    return Err(validation(ErrorCode::InvalidTransition));
                }
                members.push(member.clone());
                CborValue::Map(std::collections::BTreeMap::from([
                    (0, CborValue::Unsigned(1)),
                    (1, CborValue::Bytes(member.endpoint.to_vec())),
                    (2, CborValue::Unsigned(role_value(member.role))),
                ]))
            }
            GroupOperation::Remove(endpoint) => {
                let before = members.len();
                members.retain(|member| member.endpoint != endpoint);
                if members.len() == before {
                    return Err(validation(ErrorCode::InvalidTransition));
                }
                CborValue::Map(std::collections::BTreeMap::from([
                    (0, CborValue::Unsigned(2)),
                    (1, CborValue::Bytes(endpoint.to_vec())),
                ]))
            }
            GroupOperation::ChangeRole { endpoint, role } => {
                let Some(member) = members
                    .iter_mut()
                    .find(|member| member.endpoint == endpoint)
                else {
                    return Err(validation(ErrorCode::InvalidTransition));
                };
                if member.role == role {
                    return Err(validation(ErrorCode::Conflict));
                }
                member.role = role;
                CborValue::Map(std::collections::BTreeMap::from([
                    (0, CborValue::Unsigned(3)),
                    (1, CborValue::Bytes(endpoint.to_vec())),
                    (2, CborValue::Unsigned(role_value(role))),
                ]))
            }
        };
        members.sort_by_key(|item| item.endpoint);
        let next_epoch = self
            .epoch
            .checked_add(1)
            .filter(|epoch| *epoch <= 9_007_199_254_740_991)
            .ok_or_else(|| validation(ErrorCode::BoundExceeded))?;
        let previous_digest = self.digest(digest_provider)?;
        let transition = CborValue::Map(std::collections::BTreeMap::from([
            (0, CborValue::Bytes(self.group_id.to_vec())),
            (1, CborValue::Bytes(previous_digest.to_vec())),
            (2, CborValue::Unsigned(next_epoch)),
            (3, CborValue::Bytes(author.to_vec())),
            (4, operation_record),
        ]));
        let next = Self {
            group_id: self.group_id,
            epoch: next_epoch,
            previous_digest: Some(previous_digest),
            members,
            transition_digest: transition_digest(digest_provider, &transition)?,
        };
        next.validate()?;
        Ok(next)
    }

    pub fn projections(
        &self,
        digest_provider: &dyn DigestProvider,
        message_id: [u8; 16],
        sender: &[u8; 32],
        payload: &[u8],
    ) -> Result<Vec<Projection>, Error> {
        self.validate()?;
        if payload.len() > MAX_GROUP_PAYLOAD_BYTES {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        if !self.members.iter().any(|item| item.endpoint == *sender) {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        let recipients: Vec<_> = self
            .members
            .iter()
            .filter(|member| member.endpoint != *sender)
            .collect();
        if recipients.len() > MAX_GROUP_PROJECTIONS {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        let state_digest = self.digest(digest_provider)?;
        let shared_payload: Arc<[u8]> = Arc::from(payload);
        let mut projection_prefix = Vec::with_capacity(
            b"LICOARC-GROUP-PROJECTION\0".len() + state_digest.len() + message_id.len(),
        );
        projection_prefix.extend_from_slice(b"LICOARC-GROUP-PROJECTION\0");
        projection_prefix.extend_from_slice(&state_digest);
        projection_prefix.extend_from_slice(&message_id);
        Ok(recipients
            .into_iter()
            .map(|member| {
                let mut input = projection_prefix.clone();
                input.extend_from_slice(&member.endpoint);
                let digest = digest_provider.sha256(&input);
                Projection {
                    id: digest[..16].try_into().expect("fixed digest prefix"),
                    message_id,
                    group_state_digest: state_digest,
                    recipient: member.endpoint,
                    payload: Arc::clone(&shared_payload),
                }
            })
            .collect())
    }

    pub fn digest(&self, digest_provider: &dyn DigestProvider) -> Result<[u8; 32], Error> {
        self.validate()?;
        let mut state = std::collections::BTreeMap::from([
            (0, CborValue::Bytes(self.group_id.to_vec())),
            (1, CborValue::Unsigned(self.epoch)),
            (
                3,
                CborValue::Array(
                    self.members
                        .iter()
                        .map(|member| {
                            CborValue::Map(std::collections::BTreeMap::from([
                                (0, CborValue::Bytes(member.endpoint.to_vec())),
                                (1, CborValue::Unsigned(role_value(member.role))),
                            ]))
                        })
                        .collect(),
                ),
            ),
            (4, CborValue::Bytes(self.transition_digest.to_vec())),
        ]);
        if let Some(previous) = self.previous_digest {
            state.insert(2, CborValue::Bytes(previous.to_vec()));
        }
        let encoded = encoding::encode(&CborValue::Map(state))?;
        let mut input = Vec::with_capacity(b"LICOARC-GROUP-STATE\0".len() + encoded.len());
        input.extend_from_slice(b"LICOARC-GROUP-STATE\0");
        input.extend_from_slice(&encoded);
        Ok(digest_provider.sha256(&input))
    }
}

const fn role_value(role: MemberRole) -> u64 {
    match role {
        MemberRole::Member => 0,
        MemberRole::StateAuthority => 1,
    }
}

pub fn validate_unique_results(ids: impl IntoIterator<Item = [u8; 16]>) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if seen.len() == MAX_GROUP_PROJECTIONS {
            return Err(validation(ErrorCode::BoundExceeded));
        }
        if !seen.insert(id) {
            return Err(validation(ErrorCode::InvalidRepresentation));
        }
    }
    Ok(())
}

pub fn aggregate_results(
    projections: &[Projection],
    results: &[GroupResult],
) -> Result<Aggregate, Error> {
    if projections.is_empty()
        || projections.len() > MAX_GROUP_PROJECTIONS
        || results.is_empty()
        || results.len() > MAX_GROUP_PROJECTIONS
    {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    if projections
        .windows(2)
        .any(|pair| pair[0].recipient >= pair[1].recipient)
        || results
            .windows(2)
            .any(|pair| pair[0].recipient >= pair[1].recipient)
    {
        return Err(validation(ErrorCode::InvalidRepresentation));
    }
    validate_unique_results(projections.iter().map(|projection| projection.id))?;
    validate_unique_results(results.iter().map(|result| result.projection_id))?;
    let expected: std::collections::BTreeMap<_, _> = projections
        .iter()
        .map(|projection| (projection.recipient, projection.id))
        .collect();
    for result in results {
        if expected.get(&result.recipient) != Some(&result.projection_id) {
            return Err(validation(ErrorCode::InvalidTransition));
        }
        let failure_expected = matches!(
            result.outcome,
            ResultOutcome::Rejected | ResultOutcome::Failed
        );
        if failure_expected != result.failure_code.is_some()
            || result.failure_code.is_some_and(|code| code > 12)
            || (result.outcome == ResultOutcome::Pending
                && result.authority != ResultAuthority::None)
            || (result.outcome == ResultOutcome::Delivered
                && result.authority != ResultAuthority::EndpointConfirmation)
        {
            return Err(validation(ErrorCode::InvalidRepresentation));
        }
    }
    let mut aggregate = Aggregate {
        outcome: AggregateOutcome::Partial,
        pending: projections.len() - results.len(),
        delivered: 0,
        rejected: 0,
        failed: 0,
    };
    for result in results {
        match result.outcome {
            ResultOutcome::Pending => aggregate.pending += 1,
            ResultOutcome::Delivered => aggregate.delivered += 1,
            ResultOutcome::Rejected => aggregate.rejected += 1,
            ResultOutcome::Failed => aggregate.failed += 1,
        }
    }
    aggregate.outcome = if aggregate.delivered == projections.len() {
        AggregateOutcome::Complete
    } else if aggregate.delivered == 0 && aggregate.pending == 0 {
        AggregateOutcome::Failed
    } else {
        AggregateOutcome::Partial
    };
    Ok(aggregate)
}

pub fn transition_digest(
    digest_provider: &dyn DigestProvider,
    canonical_transition: &CborValue,
) -> Result<[u8; 32], Error> {
    let encoded = encoding::encode(canonical_transition)?;
    let mut input = Vec::with_capacity(b"LICOARC-GROUP-TRANSITION\0".len() + encoded.len());
    input.extend_from_slice(b"LICOARC-GROUP-TRANSITION\0");
    input.extend_from_slice(&encoded);
    Ok(digest_provider.sha256(&input))
}

const fn validation(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}
