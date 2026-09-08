use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, ErrorCode, Stage};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const ROLE_COUNT: usize = 7;
const MAX_SIGNATURES_PER_ROLE: usize = 64;
const MAX_OBSERVATIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Role {
    Membership,
    Compatibility,
    Revocation,
    Distribution,
    Consistency,
    Recovery,
    Abuse,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Authorization {
    pub root: [u8; 16],
    pub key: [u8; 16],
    pub role: Role,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConsistencyObservation {
    pub observer_ref: [u8; 32],
    pub observed_version: u64,
    pub observed_digest: [u8; 32],
    pub statement_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryEvent {
    None,
    RootRotation,
    CompromiseRecovery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceState {
    pub network_ref: [u8; 32],
    pub bundle_epoch: u64,
    pub bundle_digest: Option<[u8; 32]>,
    pub role_versions: BTreeMap<Role, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceCandidate {
    pub network_ref: [u8; 32],
    pub bundle_epoch: u64,
    pub bundle_digest: [u8; 32],
    pub role_versions: BTreeMap<Role, u64>,
    pub expires_at: u64,
    pub authorizations: Vec<Authorization>,
    pub active_roots_only: bool,
    pub canonical_digest_valid: bool,
    pub distribution_consistent: bool,
    pub signature_scope_valid: bool,
    pub recovery_event: RecoveryEvent,
    pub recovery_predecessor: Option<[u8; 32]>,
    pub observations: Vec<ConsistencyObservation>,
    pub split_view: bool,
    pub endpoint_admission_local: bool,
    pub abuse_advisory_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Adoption {
    Commit(GovernanceState),
    Replay,
}

/// Requires four distinct signers from at least two independent roots for one role.
pub fn validate_role_threshold(role: Role, authorizations: &[Authorization]) -> Result<(), Error> {
    if authorizations.len() > ROLE_COUNT * MAX_SIGNATURES_PER_ROLE
        || authorizations
            .iter()
            .filter(|authorization| authorization.role == role)
            .count()
            > MAX_SIGNATURES_PER_ROLE
    {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    let matching: BTreeSet<_> = authorizations
        .iter()
        .filter(|entry| entry.role == role)
        .copied()
        .collect();
    let roots: BTreeMap<_, usize> = matching.iter().fold(BTreeMap::new(), |mut roots, entry| {
        *roots.entry(entry.root).or_default() += 1;
        roots
    });
    if matching.len() < 4
        || roots.len() < 2
        || roots.values().filter(|count| **count >= 2).count() < 2
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    Ok(())
}

/// Applies the non-cryptographic governance reducer after caller-owned signature
/// verification has produced scoped authorization facts.
pub fn evaluate_candidate(
    current: &GovernanceState,
    candidate: &GovernanceCandidate,
    now: u64,
) -> Result<Adoption, Error> {
    if current.bundle_epoch > MAX_SAFE_INTEGER
        || candidate.bundle_epoch > MAX_SAFE_INTEGER
        || candidate.expires_at > MAX_SAFE_INTEGER
        || now > MAX_SAFE_INTEGER
        || current.role_versions.len() > ROLE_COUNT
        || (current.bundle_epoch == 0) != current.role_versions.is_empty()
        || (current.bundle_epoch > 0 && current.role_versions.len() != ROLE_COUNT)
        || current
            .role_versions
            .values()
            .any(|version| *version == 0 || *version > MAX_SAFE_INTEGER)
        || candidate.role_versions.len() != ROLE_COUNT
        || candidate
            .role_versions
            .values()
            .any(|version| *version == 0 || *version > MAX_SAFE_INTEGER)
        || candidate.authorizations.len() > ROLE_COUNT * MAX_SIGNATURES_PER_ROLE
        || candidate.observations.len() > MAX_OBSERVATIONS
        || candidate
            .authorizations
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != candidate.authorizations.len()
        || candidate
            .observations
            .iter()
            .any(|observation| observation.observed_version > MAX_SAFE_INTEGER)
    {
        return Err(validation(ErrorCode::BoundExceeded));
    }
    if candidate.bundle_epoch == 0
        || (current.bundle_epoch == 0) != current.bundle_digest.is_none()
        || matches!(candidate.recovery_event, RecoveryEvent::None)
            != candidate.recovery_predecessor.is_none()
        || (!matches!(candidate.recovery_event, RecoveryEvent::None)
            && candidate.recovery_predecessor != current.bundle_digest)
        || candidate.network_ref != current.network_ref
        || !candidate.active_roots_only
        || !candidate.canonical_digest_valid
        || !candidate.distribution_consistent
        || !candidate.signature_scope_valid
        || !candidate.endpoint_admission_local
        || !candidate.abuse_advisory_only
        || candidate.split_view
        || candidate.expires_at <= now
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    for role in [
        Role::Membership,
        Role::Compatibility,
        Role::Revocation,
        Role::Distribution,
        Role::Consistency,
        Role::Recovery,
        Role::Abuse,
    ] {
        validate_role_threshold(role, &candidate.authorizations)?;
        let current_version = current
            .role_versions
            .get(&role)
            .copied()
            .unwrap_or_default();
        if candidate
            .role_versions
            .get(&role)
            .copied()
            .is_none_or(|version| version < current_version)
        {
            return Err(validation(ErrorCode::InvalidTransition));
        }
    }
    let observers: BTreeSet<_> = candidate
        .observations
        .iter()
        .map(|observation| observation.observer_ref)
        .collect();
    let statement_digests: BTreeSet<_> = candidate
        .observations
        .iter()
        .map(|observation| observation.statement_digest)
        .collect();
    if candidate.observations.len() < 2
        || observers.len() != candidate.observations.len()
        || statement_digests.len() != candidate.observations.len()
        || candidate.observations.iter().any(|observation| {
            observation.observed_version != candidate.bundle_epoch
                || observation.observed_digest != candidate.bundle_digest
        })
    {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    if candidate.bundle_epoch < current.bundle_epoch {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    if candidate.bundle_epoch == current.bundle_epoch {
        return if current.bundle_digest == Some(candidate.bundle_digest)
            && current.role_versions == candidate.role_versions
        {
            Ok(Adoption::Replay)
        } else {
            Err(validation(ErrorCode::Conflict))
        };
    }
    if current.bundle_epoch.checked_add(1) != Some(candidate.bundle_epoch) {
        return Err(validation(ErrorCode::InvalidTransition));
    }
    Ok(Adoption::Commit(GovernanceState {
        network_ref: candidate.network_ref,
        bundle_epoch: candidate.bundle_epoch,
        bundle_digest: Some(candidate.bundle_digest),
        role_versions: candidate.role_versions.clone(),
    }))
}

const fn validation(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}
