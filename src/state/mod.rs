//! Caller-owned durable state, key custody, carrier, and effect contracts.

use core::{fmt, marker::PhantomData};
use std::collections::HashSet;

use crate::error::{Error, ErrorCode, Stage};

/// Largest integer that the authority permits for persisted generations.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Largest content-bearing item that can cross a post-commit delivery boundary.
pub const MAX_PENDING_PAYLOAD_BYTES: usize = 524_288;
pub const MAX_PENDING_PLAINTEXT_BYTES: usize = 524_224;

#[derive(Eq, Hash, PartialEq)]
pub enum Ed25519Signing {}
#[derive(Eq, Hash, PartialEq)]
pub enum MlDsa65Signing {}
#[derive(Eq, Hash, PartialEq)]
pub enum X25519Private {}
#[derive(Eq, Hash, PartialEq)]
pub enum MlKem768Private {}
#[derive(Eq, Hash, PartialEq)]
pub enum MlKemEncapsulationEntropy {}

/// Opaque, purpose-typed custody reference. It is intentionally non-Copy,
/// non-serializable and redacted.
///
/// ```compile_fail
/// use licoarc::state::{SecretHandle, X25519Private};
/// let _ = SecretHandle::<X25519Private> { id: 1, purpose: core::marker::PhantomData };
/// ```
///
/// ```compile_fail
/// use licoarc::state::{SecretHandle, X25519Private};
/// fn requires_copy<T: Copy>() {}
/// requires_copy::<SecretHandle<X25519Private>>();
/// ```
///
/// ```compile_fail
/// use licoarc::state::{SecretHandle, X25519Private};
/// use serde::Serialize;
/// fn requires_serialize<T: Serialize>() {}
/// requires_serialize::<SecretHandle<X25519Private>>();
/// ```
#[derive(Eq, Hash, PartialEq)]
pub struct SecretHandle<P> {
    id: u128,
    purpose: PhantomData<fn() -> P>,
}

impl<P> SecretHandle<P> {
    /// Issues an adopted handle from a caller-owned, nonsecret custody token.
    #[must_use]
    pub const fn from_custody_token(id: u128) -> Self {
        Self {
            id,
            purpose: PhantomData,
        }
    }

    /// Returns the nonsecret token used by the caller's coupled state/custody backend.
    #[must_use]
    pub const fn custody_token(&self) -> u128 {
        self.id
    }
}

impl<P> Clone for SecretHandle<P> {
    fn clone(&self) -> Self {
        Self::from_custody_token(self.id)
    }
}

impl<P> fmt::Debug for SecretHandle<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretHandle([REDACTED])")
    }
}

/// Opaque tentative reference. It remains non-Copy and non-serializable so a
/// caller must preserve its lifecycle in the coupled custody backend.
///
/// ```compile_fail
/// use licoarc::state::{StagedSecretHandle, X25519Private};
/// fn requires_copy<T: Copy>() {}
/// requires_copy::<StagedSecretHandle<X25519Private>>();
/// ```
///
/// ```compile_fail
/// use licoarc::state::{StagedSecretHandle, X25519Private};
/// use serde::Serialize;
/// fn requires_serialize<T: Serialize>() {}
/// requires_serialize::<StagedSecretHandle<X25519Private>>();
/// ```
#[derive(Eq, Hash, PartialEq)]
pub struct StagedSecretHandle<P> {
    token: u128,
    purpose: PhantomData<fn() -> P>,
}

impl<P> StagedSecretHandle<P> {
    /// Issues a tentative handle from a caller-owned, nonsecret custody token.
    #[must_use]
    pub const fn from_custody_token(token: u128) -> Self {
        Self {
            token,
            purpose: PhantomData,
        }
    }

    #[must_use]
    pub const fn custody_token(&self) -> u128 {
        self.token
    }

    #[must_use]
    pub const fn adopted_handle(&self) -> SecretHandle<P> {
        SecretHandle::from_custody_token(self.token)
    }
}

impl<P> Clone for StagedSecretHandle<P> {
    fn clone(&self) -> Self {
        Self::from_custody_token(self.token)
    }
}

impl<P> fmt::Debug for StagedSecretHandle<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StagedSecretHandle([REDACTED])")
    }
}

#[derive(Clone, Copy)]
pub enum CustodyRef<'a, P> {
    Adopted(&'a SecretHandle<P>),
    Staged(&'a StagedSecretHandle<P>),
}

impl<P> CustodyRef<'_, P> {
    #[must_use]
    pub const fn custody_token(self) -> u128 {
        match self {
            Self::Adopted(handle) => handle.custody_token(),
            Self::Staged(handle) => handle.custody_token(),
        }
    }
}

impl<P> fmt::Debug for CustodyRef<'_, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CustodyRef([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum KeyMutation {
    AdoptX25519(StagedSecretHandle<X25519Private>),
    AdoptMlKem768(StagedSecretHandle<MlKem768Private>),
    DeleteX25519(SecretHandle<X25519Private>),
    DeleteMlKem768(SecretHandle<MlKem768Private>),
    DeleteMlKemEncapsulationEntropy(SecretHandle<MlKemEncapsulationEntropy>),
}

impl fmt::Debug for KeyMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyMutation([REDACTED])")
    }
}

/// Performs only the fixed private operations below. Implementations must look
/// up every token in caller-owned custody and verify its purpose, lifecycle
/// (staged or adopted), and permission for the requested operation. The marker
/// type alone is not proof that a token is authorized.
pub trait KeyCustody {
    fn ed25519_public(&self, handle: &SecretHandle<Ed25519Signing>) -> Result<[u8; 32], Error>;
    fn ed25519_sign(
        &self,
        handle: &SecretHandle<Ed25519Signing>,
        message: &[u8],
    ) -> Result<[u8; 64], Error>;
    fn ml_dsa_65_public(&self, handle: &SecretHandle<MlDsa65Signing>) -> Result<Vec<u8>, Error>;
    fn ml_dsa_65_sign(
        &self,
        handle: &SecretHandle<MlDsa65Signing>,
        message: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn x25519_public(&self, handle: CustodyRef<'_, X25519Private>) -> Result<[u8; 32], Error>;
    fn x25519(
        &self,
        handle: CustodyRef<'_, X25519Private>,
        public: &[u8; 32],
    ) -> Result<[u8; 32], Error>;
    fn ml_kem_768_public(&self, handle: CustodyRef<'_, MlKem768Private>) -> Result<Vec<u8>, Error>;
    fn ml_kem_768_encapsulate(
        &self,
        public: &[u8],
        entropy: &SecretHandle<MlKemEncapsulationEntropy>,
    ) -> Result<(Vec<u8>, [u8; 32]), Error>;
    fn ml_kem_768_decapsulate(
        &self,
        handle: &SecretHandle<MlKem768Private>,
        ciphertext: &[u8],
    ) -> Result<[u8; 32], Error>;
    /// Makes a definitely uncommitted tentative object logically unreachable.
    /// This does not claim physical erasure of provider media.
    fn abort_x25519(&mut self, staged: &StagedSecretHandle<X25519Private>);
    /// Makes a definitely uncommitted tentative object logically unreachable.
    /// This does not claim physical erasure of provider media.
    fn abort_ml_kem_768(&mut self, staged: &StagedSecretHandle<MlKem768Private>);
}

pub trait TrustFacts {
    fn identity_key(
        &self,
        identity_state_digest: &[u8; 32],
        purpose: &'static str,
        profile: &[u8; 32],
    ) -> Result<Vec<u8>, Error>;
}

pub trait Clock {
    fn now_unix_seconds(&self) -> Result<u64, Error>;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Revision(u64);

impl Revision {
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    pub fn successor(self) -> Result<Self, Error> {
        if self.0 >= MAX_SAFE_INTEGER {
            return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Commit));
        }
        Ok(Self(self.0 + 1))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Versioned<S> {
    revision: Revision,
    state: S,
    pending: Vec<PendingItem>,
}

impl<S> fmt::Debug for Versioned<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Versioned")
            .field("revision", &self.revision)
            .field("state", &"[REDACTED]")
            .finish()
    }
}

impl<S> Versioned<S> {
    #[must_use]
    pub const fn initial(state: S) -> Self {
        Self {
            revision: Revision::initial(),
            state,
            pending: Vec::new(),
        }
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn state(&self) -> &S {
        &self.state
    }

    /// Content-opaque work that was committed with this exact revision and
    /// has not yet been settled by its caller-owned boundary.
    #[must_use]
    pub fn pending(&self) -> &[PendingItem] {
        &self.pending
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingId(u128);

impl PendingId {
    #[must_use]
    pub const fn from_token(token: u128) -> Self {
        Self(token)
    }
}

impl fmt::Debug for PendingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingId([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum PendingKind {
    Packet(Vec<u8>),
    Effect(Vec<u8>),
    Plaintext(Vec<u8>),
}

impl fmt::Debug for PendingKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingKind([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PendingItem {
    id: PendingId,
    kind: PendingKind,
}

impl PendingItem {
    pub fn packet(id: PendingId, packet: Vec<u8>) -> Result<Self, Error> {
        Self::bounded(id, PendingKind::Packet(packet))
    }

    pub fn effect(id: PendingId, effect: Vec<u8>) -> Result<Self, Error> {
        Self::bounded(id, PendingKind::Effect(effect))
    }

    pub fn plaintext(id: PendingId, plaintext: Vec<u8>) -> Result<Self, Error> {
        Self::bounded(id, PendingKind::Plaintext(plaintext))
    }

    fn bounded(id: PendingId, kind: PendingKind) -> Result<Self, Error> {
        let (length, maximum) = match &kind {
            PendingKind::Packet(value) | PendingKind::Effect(value) => {
                (value.len(), MAX_PENDING_PAYLOAD_BYTES)
            }
            PendingKind::Plaintext(value) => (value.len(), MAX_PENDING_PLAINTEXT_BYTES),
        };
        if length > maximum {
            return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
        }
        Ok(Self { id, kind })
    }

    #[must_use]
    pub const fn id(&self) -> PendingId {
        self.id
    }

    #[must_use]
    pub const fn kind(&self) -> &PendingKind {
        &self.kind
    }
}

impl fmt::Debug for PendingItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingItem")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Commit<S> {
    next_state: S,
    key_mutations: Vec<KeyMutation>,
    pending: Vec<PendingItem>,
}

impl<S> Commit<S> {
    pub fn bounded(
        next_state: S,
        key_mutations: Vec<KeyMutation>,
        pending: Vec<PendingItem>,
        maximum_mutations: usize,
        maximum_pending: usize,
    ) -> Result<Self, Error> {
        if key_mutations.len() > maximum_mutations || pending.len() > maximum_pending {
            return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
        }
        let mut pending_ids = HashSet::with_capacity(pending.len());
        let duplicate_pending = pending.iter().any(|item| !pending_ids.insert(item.id));
        let mut mutation_tokens = HashSet::with_capacity(key_mutations.len());
        let duplicate_mutation = key_mutations.iter().any(|mutation| {
            let token = match mutation {
                KeyMutation::AdoptX25519(staged) => staged.custody_token(),
                KeyMutation::AdoptMlKem768(staged) => staged.custody_token(),
                KeyMutation::DeleteX25519(handle) => handle.custody_token(),
                KeyMutation::DeleteMlKem768(handle) => handle.custody_token(),
                KeyMutation::DeleteMlKemEncapsulationEntropy(handle) => handle.custody_token(),
            };
            !mutation_tokens.insert(token)
        });
        if duplicate_pending || duplicate_mutation {
            return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
        }
        Ok(Self {
            next_state,
            key_mutations,
            pending,
        })
    }

    #[must_use]
    pub const fn next_state(&self) -> &S {
        &self.next_state
    }

    #[must_use]
    pub fn key_mutations(&self) -> &[KeyMutation] {
        &self.key_mutations
    }

    #[must_use]
    pub fn pending(&self) -> &[PendingItem] {
        &self.pending
    }

    /// Converts a store-validated commit into its next complete snapshot.
    pub fn into_versioned(self, expected: Revision) -> Result<Versioned<S>, Error> {
        Ok(Versioned {
            revision: expected.successor()?,
            state: self.next_state,
            pending: self.pending,
        })
    }
}

impl<S> fmt::Debug for Commit<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Commit")
            .field("next_state", &"[REDACTED]")
            .field("key_mutations", &self.key_mutations)
            .field("pending", &self.pending)
            .finish()
    }
}

pub trait AtomicState<S> {
    fn load(&self) -> Result<Versioned<S>, Error>;
    /// Applies the complete snapshot and all handle adoptions/deletions in one
    /// transaction owned by the caller's coupled state/custody backend, then
    /// advances exactly one revision, or applies nothing. Implementations must
    /// validate every mutation token's purpose and lifecycle and must not retry
    /// internally. A backend unable to provide this old-or-new result does not
    /// satisfy this contract.
    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: Commit<S>,
    ) -> Result<Revision, Error>;
    /// Atomically removes exactly one pending item from `revision`, preserving
    /// the complete state and every other pending item, and advances once.
    fn settle(&mut self, revision: Revision, pending: PendingId) -> Result<Revision, Error>;
}

pub trait PacketCarrier {
    fn send(&mut self, packet: &[u8]) -> Result<(), Error>;
}

pub trait ApplicationEffects {
    fn apply(&mut self, effect: &[u8]) -> Result<(), Error>;
}

pub trait PlaintextReceiver {
    fn release(&mut self, plaintext: &[u8]) -> Result<(), Error>;
}

/// Delivers one already-committed pending item and settles it only after the
/// caller-owned boundary reports success. Failure leaves it durably pending.
pub fn drive_pending<S, A, C, E>(
    store: &mut A,
    revision: Revision,
    item: &PendingItem,
    carrier: &mut C,
    effects: &mut E,
) -> Result<Revision, Error>
where
    S: Clone,
    A: AtomicState<S>,
    C: PacketCarrier,
    E: ApplicationEffects,
{
    let current = store.load()?;
    if current.revision() != revision {
        return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
    }
    if !current.pending().iter().any(|candidate| candidate == item) {
        return Err(Error::terminal(ErrorCode::InvalidTransition, Stage::Commit));
    }
    match item.kind() {
        PendingKind::Packet(packet) => carrier.send(packet)?,
        PendingKind::Effect(effect) => effects.apply(effect)?,
        PendingKind::Plaintext(_) => {
            return Err(Error::terminal(ErrorCode::InvalidTransition, Stage::Commit));
        }
    }
    store.settle(revision, item.id())
}

/// Releases one plaintext that is already part of a durable receive commit,
/// then settles its pending record. A release or settlement failure leaves the
/// record pending so the caller can fence an uncertain delivery or re-drive a
/// known failed delivery explicitly.
pub fn release_plaintext<S, A, R>(
    store: &mut A,
    revision: Revision,
    item: &PendingItem,
    receiver: &mut R,
) -> Result<Revision, Error>
where
    S: Clone,
    A: AtomicState<S>,
    R: PlaintextReceiver,
{
    let current = store.load()?;
    if current.revision() != revision {
        return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
    }
    if !current.pending().iter().any(|candidate| candidate == item) {
        return Err(Error::terminal(ErrorCode::InvalidTransition, Stage::Commit));
    }
    let PendingKind::Plaintext(plaintext) = item.kind() else {
        return Err(Error::terminal(ErrorCode::InvalidTransition, Stage::Commit));
    };
    receiver.release(plaintext)?;
    store.settle(revision, item.id())
}

/// Rejects rollback and impossible future snapshots during caller-owned
/// restart without mutating durable state.
pub fn validate_restart(persisted: Revision, current: Revision) -> Result<(), Error> {
    if persisted < current {
        return Err(Error::terminal(ErrorCode::StateRollback, Stage::Validation));
    }
    if persisted > current {
        return Err(Error::terminal(
            ErrorCode::InvalidTransition,
            Stage::Validation,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PENDING_PAYLOAD_BYTES, MAX_PENDING_PLAINTEXT_BYTES, MAX_SAFE_INTEGER, PendingId,
        PendingItem, Revision,
    };
    use crate::error::ErrorCode;

    #[test]
    fn revision_and_pending_payload_bounds_are_closed() {
        assert_eq!(
            Revision(MAX_SAFE_INTEGER - 1).successor().unwrap().value(),
            MAX_SAFE_INTEGER
        );
        assert_eq!(
            Revision(MAX_SAFE_INTEGER).successor().unwrap_err().code,
            ErrorCode::BoundExceeded
        );
        assert!(
            PendingItem::packet(PendingId::from_token(1), vec![0; MAX_PENDING_PAYLOAD_BYTES])
                .is_ok()
        );
        assert!(
            PendingItem::packet(
                PendingId::from_token(2),
                vec![0; MAX_PENDING_PAYLOAD_BYTES + 1]
            )
            .is_err()
        );
        assert!(
            PendingItem::plaintext(
                PendingId::from_token(3),
                vec![0; MAX_PENDING_PLAINTEXT_BYTES]
            )
            .is_ok()
        );
        assert!(
            PendingItem::plaintext(
                PendingId::from_token(4),
                vec![0; MAX_PENDING_PLAINTEXT_BYTES + 1]
            )
            .is_err()
        );
    }
}
