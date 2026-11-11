//! Versioned, secret-bearing checkpoint of one committed Endpoint snapshot.
//!
//! The Pairwise Protection definition requires a restart to restore the last
//! complete committed monotonic snapshot (`Restart restores the last complete
//! committed monotonic snapshot before any operation`), while the durable
//! storage layout stays implementation-local. The pinned SDK state
//! ([`EndpointState`]) is therefore made durable here, inside the
//! implementation that owns its meaning, instead of asking a caller to
//! reconstruct private ratchet internals.
//!
//! # What a checkpoint contains
//!
//! One complete committed snapshot: the state phase (including the hybrid
//! handshake secrets and the Double Ratchet chains, counters, and skipped
//! message keys), the committed pending-output set with its exact ids, and the
//! generation it was taken at — all bound to the admitted Protocol Line and
//! Protection Profile and authenticated with an HMAC-SHA-256 tag over the
//! canonical body under a caller-provided integrity key.
//!
//! # Secrecy
//!
//! A checkpoint is *secret-bearing*: it contains exactly the session material
//! the profile requires an Endpoint to preserve. It is not a key export — it
//! never contains caller custody material, which stays behind the opaque
//! purpose-specific handles — but it must be stored the way the same SDK
//! stores session secrets: as a private secret, never in a log, plan, or
//! diagnostic. [`EndpointCheckpoint`] redacts its `Debug` form and zeroizes its
//! bytes on drop, and its only reader is named `expose_secret_bytes`.
//!
//! # Refusals
//!
//! A checkpoint is refused, never silently approximated, when the state
//! carries an optional capability runtime (no canonical form is defined for
//! it yet), when a bound is exceeded, when the version is unknown, when the
//! authentication tag does not verify, or when the checkpoint belongs to
//! another Line or Profile. Restoring below the caller's committed
//! generation remains the caller's check; the SDK keeps returning
//! `state-rollback` for it.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    VerifiedProtocolLine,
    encoding::{self, CHECKPOINT_LIMITS, CborValue, WipedBytes, WipedValue},
    error::{Error, ErrorCode, Stage},
    protection::{Direction, MAX_ACTIVE_PREKEY_PAIRS},
    provider::Provider,
    state::{
        AtomicState, Commit, KeyCustody, MAX_PENDING_PAYLOAD_BYTES, MAX_PENDING_PLAINTEXT_BYTES,
        PendingId, PendingItem, PendingKind, Revision, Versioned,
    },
};

use super::{
    ActivePrekey, CheckpointLineage, Endpoint, EndpointState, Initiator, Phase, PrekeyBundle,
    Responder, Role, RuntimeLine, SessionAccept, bundle_value, decode_first_packet,
    encode_first_packet, ensure_live, transition_error, validate_prekey_shape, wire_bytes,
    wire_fixed, wire_uint,
};

const CHECKPOINT_VERSION: u64 = 1;
const CHECKPOINT_DOMAIN: &[u8] = b"LICOARC-V1/ENDPOINT-CHECKPOINT/SNAPSHOT\0";
/// Largest checkpoint accepted or produced, independent of the component
/// bounds it already enforces.
const MAX_CHECKPOINT_BYTES: usize = 40 * 1024 * 1024;
/// The pinned SDK commits at most this many pending items per endpoint commit.
const MAX_CHECKPOINT_PENDING: usize = 16;
/// The caller's endpoint identifier bound into every checkpoint: non-empty
/// and short enough to live inside a uuid/digest-shaped slot.
const MAX_CHECKPOINT_SCOPE: usize = 64;

fn valid_scope(scope: &[u8]) -> Result<&[u8], Error> {
    if scope.is_empty() || scope.len() > MAX_CHECKPOINT_SCOPE {
        return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
    }
    Ok(scope)
}

/// One opaque, secret-bearing checkpoint of a committed Endpoint snapshot.
///
/// The caller stores these bytes as a private secret — the same material class
/// as session keys — and presents them back through
/// [`decode_endpoint_checkpoint`]. The type never reveals its content except
/// through `expose_secret_bytes`, redacts its diagnostic form, and zeroizes on
/// drop.
pub struct EndpointCheckpoint {
    bytes: Vec<u8>,
}

impl EndpointCheckpoint {
    /// Accepts bytes a caller previously persisted.
    pub fn from_secret_bytes(mut bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
            bytes.zeroize();
            return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
        }
        Ok(Self { bytes })
    }

    /// The only way to read a checkpoint, so every such read is explicit and
    /// reviewable.
    #[must_use]
    pub fn expose_secret_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

impl fmt::Debug for EndpointCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EndpointCheckpoint([REDACTED])")
    }
}

impl Drop for EndpointCheckpoint {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// The caller-side integrity key that authenticates a checkpoint.
///
/// A checkpoint is authenticated, not merely checksummed: sealing and
/// decoding both require this key, so bytes modified in storage cannot be
/// re-sealed by whoever wrote them — a relabeled generation or patched
/// ratchet state fails verification instead of resuming. The caller holds
/// it with the same custody it gives session secrets; the SDK only ever
/// receives it as a parameter. The key redacts its `Debug` form and
/// zeroizes on drop.
pub struct CheckpointIntegrityKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl CheckpointIntegrityKey {
    /// Adopts caller-generated key material.
    #[must_use]
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Lends the key bytes to a caller-managed operation.
    ///
    /// The same contract `EndpointCheckpoint::expose_secret_bytes` states
    /// applies: the borrow is secret custody, so nothing derived from it may
    /// outlive the key or land anywhere a Debug form could reach.
    #[must_use]
    pub fn expose_secret_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for CheckpointIntegrityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointIntegrityKey([REDACTED])")
    }
}

/// One decoded snapshot, ready to become the caller's durable state.
pub struct EndpointRestore {
    state: EndpointState,
    generation: u64,
    pending: Vec<PendingItem>,
    line_id: [u8; 32],
    profile_id: [u8; 32],
}

impl EndpointRestore {
    /// Generation the checkpoint was taken at. The caller compares this with
    /// its own committed generation and refuses a mismatch.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Protocol Line the checkpoint was sealed against.
    #[must_use]
    pub const fn line_id(&self) -> &[u8; 32] {
        &self.line_id
    }

    /// Protection Profile the checkpoint was sealed against.
    #[must_use]
    pub const fn profile_id(&self) -> &[u8; 32] {
        &self.profile_id
    }

    #[must_use]
    pub const fn state(&self) -> &EndpointState {
        &self.state
    }

    #[must_use]
    pub fn pending(&self) -> &[PendingItem] {
        &self.pending
    }

    /// Converts the restored snapshot into the exact `Versioned` value the
    /// caller's `AtomicState::load` must return.
    ///
    /// Ownership of the state and pending payloads transfers to the returned
    /// value; a restore that is never converted wipes its pending payloads on
    /// drop.
    pub fn into_versioned(mut self) -> Result<Versioned<EndpointState>, Error> {
        let mut pending = PendingGuard(std::mem::take(&mut self.pending));
        let state = std::mem::replace(&mut self.state, EndpointState::initiator());
        if self.generation == 0 {
            if !pending.0.is_empty() {
                return Err(Error::terminal(
                    ErrorCode::InvalidRepresentation,
                    Stage::Validation,
                ));
            }
            return Ok(Versioned::initial(state));
        }
        let expected = Revision::from_value(self.generation - 1)?;
        Commit::bounded(state, Vec::new(), pending.take(), 0, MAX_CHECKPOINT_PENDING)?
            .into_versioned(expected)
    }
}

impl Drop for EndpointRestore {
    /// A restore that never reached `into_versioned` still relinquishes its
    /// pending payloads: they are wiped rather than freed back to the heap.
    fn drop(&mut self) {
        for item in &mut self.pending {
            item.wipe();
        }
    }
}

impl fmt::Debug for EndpointRestore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointRestore")
            .field("generation", &self.generation)
            .field("state", &self.state)
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl<R: Role, P: Provider, C: KeyCustody, S: AtomicState<EndpointState>> Endpoint<R, P, C, S> {
    /// Captures one complete committed snapshot as a secret-bearing checkpoint.
    ///
    /// Cadence and retention are the caller's cost decision: each call
    /// produces one full snapshot bounded by the profile limits (the
    /// skipped-key, prekey and pending ceilings dominate its size), so the
    /// caller checkpoints on durability boundaries — after commits it cannot
    /// recompute — rather than per record, and retains the latest snapshot
    /// with its generation floor instead of a history.
    ///
    /// `scope` is the caller's stable endpoint identifier — an opaque
    /// 1-to-64-byte value (an endpoint uuid or account digest) authenticated
    /// with the snapshot. [`decode_endpoint_checkpoint`] requires the same
    /// scope, so a blob transplanted from another endpoint sharing the
    /// integrity key and Line/Profile is refused.
    pub fn checkpoint(
        &self,
        integrity: &CheckpointIntegrityKey,
        scope: &[u8],
    ) -> Result<EndpointCheckpoint, Error> {
        let current = self.store.load()?;
        encode_checkpoint(
            &self.provider,
            self.line.protocol_line_id(),
            self.line.protection_profile_id(),
            current.revision().value(),
            current.state(),
            current.pending(),
            scope,
            integrity,
        )
    }
}

impl<P: Provider, C: KeyCustody, S: AtomicState<EndpointState>> Endpoint<Initiator, P, C, S> {
    /// Resumes a restored initiator snapshot from the caller's durable store.
    ///
    /// The store must already hold the snapshot ([`EndpointRestore`] written
    /// through the caller's own commit path), and the restored phase must be an
    /// initiator phase; anything else is `invalid-transition`.
    /// `minimum_generation` is the caller's independently persisted
    /// high-water mark: resuming below it is `state-rollback`, so an
    /// authentic-but-stale checkpoint cannot rewind the ratchet. A snapshot
    /// checkpointed under a different Line or Profile is refused outright.
    pub fn resume(
        line: VerifiedProtocolLine,
        provider: P,
        custody: C,
        store: S,
        minimum_generation: u64,
    ) -> Result<Self, Error> {
        let current = store.load()?;
        ensure_live(current.state())?;
        if current.revision().value() < minimum_generation {
            return Err(Error::terminal(ErrorCode::StateRollback, Stage::Validation));
        }
        if let Some(lineage) = current.state().lineage
            && (lineage.line_id != *line.protocol_line_id()
                || lineage.profile_id != *line.protection_profile_id())
        {
            return Err(Error::terminal(
                ErrorCode::ContentIdentityMismatch,
                Stage::Validation,
            ));
        }
        let allowed = match &current.state().phase {
            Phase::InitiatorNew | Phase::InitiatorAwaiting { .. } => true,
            Phase::Established { session, .. } => {
                session.send_direction() == Direction::InitiatorToResponder
            }
            Phase::ResponderReady { .. } | Phase::Deleted { .. } => false,
        };
        if !allowed {
            return Err(transition_error());
        }
        Ok(Self {
            line: RuntimeLine::from_verified(&line),
            provider,
            custody,
            store,
            role: PhantomData,
        })
    }
}

impl<P: Provider, C: KeyCustody, S: AtomicState<EndpointState>> Endpoint<Responder, P, C, S> {
    /// Resumes a restored responder snapshot from the caller's durable store.
    ///
    /// `minimum_generation` is the caller's independently persisted
    /// high-water mark: resuming below it is `state-rollback`, so an
    /// authentic-but-stale checkpoint cannot rewind the ratchet. A snapshot
    /// checkpointed under a different Line or Profile is refused outright.
    pub fn resume(
        line: VerifiedProtocolLine,
        provider: P,
        custody: C,
        store: S,
        minimum_generation: u64,
    ) -> Result<Self, Error> {
        let current = store.load()?;
        ensure_live(current.state())?;
        if current.revision().value() < minimum_generation {
            return Err(Error::terminal(ErrorCode::StateRollback, Stage::Validation));
        }
        if let Some(lineage) = current.state().lineage
            && (lineage.line_id != *line.protocol_line_id()
                || lineage.profile_id != *line.protection_profile_id())
        {
            return Err(Error::terminal(
                ErrorCode::ContentIdentityMismatch,
                Stage::Validation,
            ));
        }
        let allowed = match &current.state().phase {
            Phase::ResponderReady { .. } => true,
            Phase::Established { session, .. } => {
                session.send_direction() == Direction::ResponderToInitiator
            }
            Phase::InitiatorNew | Phase::InitiatorAwaiting { .. } | Phase::Deleted { .. } => false,
        };
        if !allowed {
            return Err(transition_error());
        }
        Ok(Self {
            line: RuntimeLine::from_verified(&line),
            provider,
            custody,
            store,
            role: PhantomData,
        })
    }
}

/// Decodes and validates one checkpoint against the admitted Line.
///
/// Every failure is terminal and leaves nothing reachable: unknown version,
/// wrong Line/Profile, digest mismatch, malformed or over-bound content, or an
/// unsupported capability runtime. Decoding restores any committed phase —
/// including a deleted one — for inspection; refusing it is [`Endpoint::resume`]'s
/// job, which rejects deleted snapshots together with rollback and
/// Line/Profile mismatches.
/// `scope` must be the same caller endpoint identifier the checkpoint was
/// sealed with; a blob transplanted from another endpoint is refused as a
/// content-identity mismatch.
pub fn decode_endpoint_checkpoint<P: Provider>(
    provider: &P,
    line: &VerifiedProtocolLine,
    checkpoint: &EndpointCheckpoint,
    integrity: &CheckpointIntegrityKey,
    scope: &[u8],
) -> Result<EndpointRestore, Error> {
    let scope = valid_scope(scope)?;
    let decoded = WipedValue(encoding::decode_at(
        checkpoint.expose_secret_bytes(),
        &CHECKPOINT_LIMITS,
    )?);
    let CborValue::Map(map) = &decoded.0 else {
        return Err(invalid_representation());
    };
    if map.len() != 8 {
        return Err(Error::terminal(ErrorCode::UnknownField, Stage::Validation));
    }
    let version = match map.get(&0) {
        Some(CborValue::Unsigned(version)) => *version,
        _ => return Err(invalid_representation()),
    };
    if version != CHECKPOINT_VERSION {
        return Err(Error::terminal(
            ErrorCode::UnsupportedDefinition,
            Stage::Representation,
        ));
    }
    let line_id = wire_fixed::<32>(map, 1)?;
    let profile_id = wire_fixed::<32>(map, 2)?;
    if line_id != *line.protocol_line_id() || profile_id != *line.protection_profile_id() {
        return Err(Error::terminal(
            ErrorCode::ContentIdentityMismatch,
            Stage::Validation,
        ));
    }
    let generation = match map.get(&3) {
        Some(CborValue::Unsigned(generation)) => *generation,
        _ => return Err(invalid_representation()),
    };
    // Re-encode the canonical body and verify the seal before anything
    // reaches the caller.
    let body = WipedValue(CborValue::Map(BTreeMap::from([
        (0, CborValue::Unsigned(version)),
        (1, CborValue::Bytes(line_id.to_vec())),
        (2, CborValue::Bytes(profile_id.to_vec())),
        (3, CborValue::Unsigned(generation)),
        (4, map.get(&4).cloned().ok_or_else(invalid_representation)?),
        (5, map.get(&5).cloned().ok_or_else(invalid_representation)?),
        (6, map.get(&6).cloned().ok_or_else(invalid_representation)?),
    ])));
    let encoded = WipedBytes(encoding::encode_at(&body.0, &CHECKPOINT_LIMITS)?);
    let tag = wire_fixed::<32>(map, 7)?;
    let mut tag_input = WipedBytes(Vec::with_capacity(CHECKPOINT_DOMAIN.len() + encoded.len()));
    tag_input.extend_from_slice(CHECKPOINT_DOMAIN);
    tag_input.extend_from_slice(&encoded);
    provider
        .hmac_sha256_verify(&integrity.bytes[..], &tag_input, &tag)
        .map_err(|_| Error::terminal(ErrorCode::DigestMismatch, Stage::Validation))?;
    // The scope is authenticated content: the transplanted-blob check is a
    // plain content comparison, not another MAC.
    let sealed_scope = match map.get(&6) {
        Some(CborValue::Bytes(value)) if value.len() <= MAX_CHECKPOINT_SCOPE => value.as_slice(),
        _ => return Err(invalid_representation()),
    };
    if sealed_scope != scope {
        return Err(Error::terminal(
            ErrorCode::ContentIdentityMismatch,
            Stage::Validation,
        ));
    }
    Revision::from_value(generation)?;
    let mut state = decode_phase(map.get(&4))?;
    // The verified Line/Profile pair travels with the restored state so a
    // later `resume` under another Line is refused.
    state.lineage = Some(CheckpointLineage {
        line_id,
        profile_id,
    });
    let pending = decode_pending(map, 5)?;
    Ok(EndpointRestore {
        state,
        generation,
        pending,
        line_id,
        profile_id,
    })
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn encode_checkpoint<P: Provider>(
    provider: &P,
    line_id: &[u8; 32],
    profile_id: &[u8; 32],
    generation: u64,
    state: &EndpointState,
    pending: &[PendingItem],
    scope: &[u8],
    integrity: &CheckpointIntegrityKey,
) -> Result<EndpointCheckpoint, Error> {
    if pending.len() > MAX_CHECKPOINT_PENDING {
        return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
    }
    let scope = valid_scope(scope)?;
    let mut body = WipedValue(CborValue::Map(BTreeMap::from([
        (0, CborValue::Unsigned(CHECKPOINT_VERSION)),
        (1, CborValue::Bytes(line_id.to_vec())),
        (2, CborValue::Bytes(profile_id.to_vec())),
        (3, CborValue::Unsigned(generation)),
        (4, encode_phase(state)?),
        (
            5,
            CborValue::Array(pending.iter().map(pending_value).collect()),
        ),
        (6, CborValue::Bytes(scope.to_vec())),
    ])));
    let encoded = WipedBytes(encoding::encode_at(&body.0, &CHECKPOINT_LIMITS)?);
    if encoded.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
    }
    let mut tag_input = WipedBytes(Vec::with_capacity(CHECKPOINT_DOMAIN.len() + encoded.len()));
    tag_input.extend_from_slice(CHECKPOINT_DOMAIN);
    tag_input.extend_from_slice(&encoded);
    let tag = provider.hmac_sha256(&integrity.bytes[..], &tag_input)?;
    // The sealed form is the body's own map plus the tag entry, so the
    // secret-bearing subtrees are moved, not copied into a second tree.
    let mut sealed = WipedValue(body.take());
    sealed.insert(7, CborValue::Bytes(tag.to_vec()));
    let mut bytes = WipedBytes(encoding::encode_at(&sealed.0, &CHECKPOINT_LIMITS)?);
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
    }
    Ok(EndpointCheckpoint {
        bytes: std::mem::take(&mut *bytes),
    })
}

fn pending_value(item: &PendingItem) -> CborValue {
    let (kind, payload) = match item.kind() {
        PendingKind::Packet(payload) => (0_u64, payload),
        PendingKind::Effect(payload) => (1, payload),
        PendingKind::Plaintext(payload) => (2, payload),
    };
    CborValue::Map(BTreeMap::from([
        (0, CborValue::Unsigned(kind)),
        (1, CborValue::Bytes(payload.clone())),
        (
            2,
            CborValue::Bytes(item.id().token().to_be_bytes().to_vec()),
        ),
    ]))
}

fn encode_phase(state: &EndpointState) -> Result<CborValue, Error> {
    let mut payload = WipedValue::map();
    let tag = match &state.phase {
        Phase::InitiatorNew => 0,
        Phase::InitiatorAwaiting {
            first_packet,
            transcript_digest,
            session_context,
            hybrid,
            ratchet,
        } => {
            payload.insert(0, CborValue::Bytes(encode_first_packet(first_packet)?));
            payload.insert(1, CborValue::Bytes(transcript_digest.to_vec()));
            payload.insert(2, CborValue::Bytes(session_context.to_vec()));
            payload.insert(3, CborValue::Bytes(hybrid.encode_checkpoint()?));
            payload.insert(4, CborValue::Bytes(ratchet.encode_checkpoint()?));
            1
        }
        Phase::ResponderReady { high_water, active } => {
            let mut entries: Vec<(&u64, &ActivePrekey)> = active.iter().collect();
            entries.sort_by_key(|(sequence, _)| **sequence);
            if entries.len() > MAX_ACTIVE_PREKEY_PAIRS {
                return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
            }
            let entries = CborValue::Array(
                entries
                    .into_iter()
                    .map(|(sequence, prekey)| {
                        CborValue::Map(BTreeMap::from([
                            (0, CborValue::Unsigned(*sequence)),
                            (1, bundle_value(&prekey.bundle)),
                            (
                                2,
                                CborValue::Bytes(
                                    prekey.x25519_private.custody_token().to_be_bytes().to_vec(),
                                ),
                            ),
                            (
                                3,
                                CborValue::Bytes(
                                    prekey.ml_kem_private.custody_token().to_be_bytes().to_vec(),
                                ),
                            ),
                        ]))
                    })
                    .collect(),
            );
            payload.insert(0, CborValue::Unsigned(*high_water));
            payload.insert(1, entries);
            2
        }
        Phase::Established {
            session,
            replay_digest,
            retry_accept,
            prekey_high_water,
            capabilities,
        } => {
            if capabilities.is_some() {
                // No canonical form is defined for the optional capability
                // runtime yet, so a checkpoint carrying one is refused.
                return Err(Error::terminal(
                    ErrorCode::UnsupportedDefinition,
                    Stage::Representation,
                ));
            }
            payload.insert(0, CborValue::Bytes(session.encode_checkpoint()?));
            payload.insert(1, optional_digest_value(replay_digest));
            payload.insert(
                2,
                retry_accept.as_ref().map_or(CborValue::Null, |accept| {
                    CborValue::Bytes(accept_bytes(accept))
                }),
            );
            payload.insert(3, optional_uint_value(*prekey_high_water));
            payload.insert(4, CborValue::Null);
            3
        }
        Phase::Deleted { prekey_high_water } => {
            payload.insert(0, optional_uint_value(*prekey_high_water));
            4
        }
    };
    Ok(CborValue::Map(BTreeMap::from([
        (0, CborValue::Unsigned(tag)),
        (1, payload.take()),
    ])))
}

fn optional_digest_value(value: &Option<[u8; 32]>) -> CborValue {
    match value {
        Some(value) => CborValue::Bytes(value.to_vec()),
        None => CborValue::Null,
    }
}

fn optional_uint_value(value: Option<u64>) -> CborValue {
    match value {
        Some(value) => CborValue::Unsigned(value),
        None => CborValue::Null,
    }
}

fn accept_bytes(accept: &SessionAccept) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(221);
    bytes.extend_from_slice(&accept.transcript_digest);
    bytes.extend_from_slice(&accept.session_context_digest);
    bytes.extend_from_slice(&accept.initiator_user_authority_state_digest);
    bytes.extend_from_slice(&accept.responder_identity_state_digest);
    bytes.extend_from_slice(&accept.responder_user_authority_state_digest);
    bytes.extend_from_slice(&accept.pair_sequence.to_be_bytes());
    bytes.extend_from_slice(&accept.mac);
    bytes
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

fn decode_phase(value: Option<&CborValue>) -> Result<EndpointState, Error> {
    let Some(CborValue::Map(phase)) = value else {
        return Err(invalid_representation());
    };
    if phase.len() != 2 {
        return Err(Error::terminal(ErrorCode::UnknownField, Stage::Validation));
    }
    let tag = match phase.get(&0) {
        Some(CborValue::Unsigned(tag)) => *tag,
        _ => return Err(invalid_representation()),
    };
    let Some(CborValue::Map(payload)) = phase.get(&1) else {
        return Err(invalid_representation());
    };
    let required = |labels: &[u64]| -> Result<(), Error> {
        if payload.len() != labels.len() || !labels.iter().all(|label| payload.contains_key(label))
        {
            return Err(Error::terminal(ErrorCode::UnknownField, Stage::Validation));
        }
        Ok(())
    };
    let decoded = match tag {
        0 => {
            required(&[])?;
            Phase::InitiatorNew
        }
        1 => {
            required(&[0, 1, 2, 3, 4])?;
            let hybrid = WipedBytes(payload_bytes(payload, 3)?);
            let ratchet = WipedBytes(payload_bytes(payload, 4)?);
            Phase::InitiatorAwaiting {
                first_packet: Box::new(decode_first_packet(&payload_bytes(payload, 0)?)?),
                transcript_digest: payload_fixed::<32>(payload, 1)?,
                session_context: payload_fixed::<32>(payload, 2)?,
                hybrid: crate::protection::HybridSecrets::decode_checkpoint(&hybrid)?,
                ratchet: Box::new(crate::protection::RatchetState::decode_checkpoint(
                    &ratchet,
                )?),
            }
        }
        2 => {
            required(&[0, 1])?;
            let high_water = payload_uint(payload, 0)?;
            let Some(CborValue::Array(entries)) = payload.get(&1) else {
                return Err(invalid_representation());
            };
            if entries.len() > MAX_ACTIVE_PREKEY_PAIRS {
                return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
            }
            let mut active = std::collections::HashMap::with_capacity(entries.len());
            for entry in entries {
                let CborValue::Map(record) = entry else {
                    return Err(invalid_representation());
                };
                if record.len() != 4 {
                    return Err(Error::terminal(ErrorCode::UnknownField, Stage::Validation));
                }
                let sequence = match record.get(&0) {
                    Some(CborValue::Unsigned(sequence)) => *sequence,
                    _ => return Err(invalid_representation()),
                };
                let bundle = decode_bundle(record.get(&1))?;
                let x25519_private =
                    crate::state::SecretHandle::from_custody_token(token(record.get(&2))?);
                let ml_kem_private =
                    crate::state::SecretHandle::from_custody_token(token(record.get(&3))?);
                if active
                    .insert(
                        sequence,
                        ActivePrekey {
                            bundle,
                            x25519_private,
                            ml_kem_private,
                        },
                    )
                    .is_some()
                {
                    return Err(invalid_representation());
                }
            }
            Phase::ResponderReady { high_water, active }
        }
        3 => {
            required(&[0, 1, 2, 3, 4])?;
            let session_bytes = WipedBytes(payload_bytes(payload, 0)?);
            let session = Box::new(crate::protection::RatchetState::decode_checkpoint(
                &session_bytes,
            )?);
            let replay_digest = match payload.get(&1) {
                Some(CborValue::Null) => None,
                Some(CborValue::Bytes(bytes)) => Some(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid_representation())?,
                ),
                _ => return Err(invalid_representation()),
            };
            let retry_accept = match payload.get(&2) {
                Some(CborValue::Null) => None,
                Some(CborValue::Bytes(bytes)) => Some(decode_accept(bytes)?),
                _ => return Err(invalid_representation()),
            };
            let prekey_high_water = match payload.get(&3) {
                Some(CborValue::Null) => None,
                Some(CborValue::Unsigned(value)) => Some(*value),
                _ => return Err(invalid_representation()),
            };
            if !matches!(payload.get(&4), Some(CborValue::Null)) {
                return Err(Error::terminal(
                    ErrorCode::UnsupportedDefinition,
                    Stage::Representation,
                ));
            }
            Phase::Established {
                session,
                replay_digest,
                retry_accept,
                prekey_high_water,
                capabilities: None,
            }
        }
        4 => {
            required(&[0])?;
            Phase::Deleted {
                prekey_high_water: match payload.get(&0) {
                    Some(CborValue::Null) => None,
                    Some(CborValue::Unsigned(value)) => Some(*value),
                    _ => return Err(invalid_representation()),
                },
            }
        }
        _ => {
            return Err(Error::terminal(
                ErrorCode::UnsupportedDefinition,
                Stage::Representation,
            ));
        }
    };
    Ok(EndpointState {
        phase: decoded,
        lineage: None,
    })
}

/// Accumulates pending items across a fallible decode: every collected
/// payload is wiped unless the caller takes ownership on success.
struct PendingGuard(Vec<PendingItem>);

impl PendingGuard {
    fn take(&mut self) -> Vec<PendingItem> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        for item in &mut self.0 {
            item.wipe();
        }
    }
}

fn decode_pending(map: &BTreeMap<u64, CborValue>, label: u64) -> Result<Vec<PendingItem>, Error> {
    let Some(CborValue::Array(entries)) = map.get(&label) else {
        return Err(invalid_representation());
    };
    if entries.len() > MAX_CHECKPOINT_PENDING {
        return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
    }
    let mut ids = std::collections::HashSet::with_capacity(entries.len());
    let mut pending = PendingGuard(Vec::with_capacity(entries.len()));
    for entry in entries {
        let CborValue::Map(record) = entry else {
            return Err(invalid_representation());
        };
        if record.len() != 3 {
            return Err(Error::terminal(ErrorCode::UnknownField, Stage::Validation));
        }
        let kind = match record.get(&0) {
            Some(CborValue::Unsigned(0)) => 0_u64,
            Some(CborValue::Unsigned(1)) => 1,
            Some(CborValue::Unsigned(2)) => 2,
            _ => return Err(invalid_representation()),
        };
        let mut payload = WipedBytes(match record.get(&1) {
            Some(CborValue::Bytes(payload)) => payload.clone(),
            _ => return Err(invalid_representation()),
        });
        // The bound is checked against the guard so a refusal wipes the copy;
        // the constructors below cannot fail on bounds afterwards.
        let maximum = match kind {
            2 => MAX_PENDING_PLAINTEXT_BYTES,
            _ => MAX_PENDING_PAYLOAD_BYTES,
        };
        if payload.len() > maximum {
            return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
        }
        let id = PendingId::from_token(token(record.get(&2))?);
        if !ids.insert(id.token()) {
            return Err(Error::terminal(ErrorCode::UnknownField, Stage::Validation));
        }
        let payload = payload.take();
        let item = match kind {
            0 => PendingItem::packet(id, payload)?,
            1 => PendingItem::effect(id, payload)?,
            _ => PendingItem::plaintext(id, payload)?,
        };
        pending.0.push(item);
    }
    Ok(pending.take())
}

fn decode_bundle(value: Option<&CborValue>) -> Result<PrekeyBundle, Error> {
    let Some(CborValue::Map(map)) = value else {
        return Err(invalid_representation());
    };
    if map.len() != 12 {
        return Err(Error::terminal(ErrorCode::UnknownField, Stage::Validation));
    }
    let bundle = PrekeyBundle {
        protocol_line_id: wire_fixed(map, 0)?,
        protection_profile_id: wire_fixed(map, 1)?,
        responder_identity_state_digest: wire_fixed(map, 2)?,
        ed25519_key_id: wire_fixed(map, 3)?,
        ml_dsa_65_key_id: wire_fixed(map, 4)?,
        pair_sequence: wire_uint(map, 5)?,
        x25519_public: wire_fixed(map, 6)?,
        ml_kem_768_public: wire_bytes(map, 7, 1184)?.to_vec(),
        valid_from: wire_uint(map, 8)?,
        valid_until: wire_uint(map, 9)?,
        ed25519_signature: wire_fixed(map, 10)?,
        ml_dsa_65_signature: wire_bytes(map, 11, 3309)?.to_vec(),
    };
    validate_prekey_shape(&bundle)?;
    Ok(bundle)
}

fn decode_accept(bytes: &[u8]) -> Result<SessionAccept, Error> {
    if bytes.len() > crate::protection::MAX_SESSION_ACCEPT_BYTES {
        return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
    }
    let accept = SessionAccept {
        transcript_digest: bytes
            .get(0..32)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(invalid_representation)?,
        session_context_digest: bytes
            .get(32..64)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(invalid_representation)?,
        initiator_user_authority_state_digest: bytes
            .get(64..96)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(invalid_representation)?,
        responder_identity_state_digest: bytes
            .get(96..128)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(invalid_representation)?,
        responder_user_authority_state_digest: bytes
            .get(128..160)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(invalid_representation)?,
        pair_sequence: u64::from_be_bytes(
            bytes
                .get(160..168)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(invalid_representation)?,
        ),
        mac: bytes
            .get(168..200)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(invalid_representation)?,
    };
    if bytes.len() != 200 {
        return Err(invalid_representation());
    }
    Ok(accept)
}

fn payload_bytes(payload: &BTreeMap<u64, CborValue>, label: u64) -> Result<Vec<u8>, Error> {
    match payload.get(&label) {
        Some(CborValue::Bytes(bytes)) => Ok(bytes.clone()),
        _ => Err(invalid_representation()),
    }
}

fn payload_fixed<const N: usize>(
    payload: &BTreeMap<u64, CborValue>,
    label: u64,
) -> Result<[u8; N], Error> {
    payload_bytes(payload, label)?
        .try_into()
        .map_err(|_| invalid_representation())
}

fn payload_uint(payload: &BTreeMap<u64, CborValue>, label: u64) -> Result<u64, Error> {
    match payload.get(&label) {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        _ => Err(invalid_representation()),
    }
}

fn token(value: Option<&CborValue>) -> Result<u128, Error> {
    let Some(CborValue::Bytes(bytes)) = value else {
        return Err(invalid_representation());
    };
    let token: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_representation())?;
    Ok(u128::from_be_bytes(token))
}

const fn invalid_representation() -> Error {
    Error::terminal(ErrorCode::InvalidRepresentation, Stage::Validation)
}
