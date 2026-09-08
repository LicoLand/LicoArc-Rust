//! Sealed two-role Endpoint facade.

use core::{fmt, marker::PhantomData};
use std::collections::HashMap;

use crate::{
    VerifiedProtocolLine,
    encoding::{self, CborValue},
    error::{Error, ErrorCode, Stage},
    governance::{self, Adoption, GovernanceCandidate, GovernanceState},
    group::{GroupOperation, GroupState, Projection},
    identity::{self, ChainTip},
    messaging::Message,
    protection::{HybridSecrets, MAX_ACTIVE_PREKEY_PAIRS, RatchetState},
    provider::Provider,
    reliable::{self, AuthorizedSession, EndpointConfirmation, FinalityState, ReliableState},
    state::{
        ApplicationEffects, AtomicState, Clock, Commit, CustodyRef, Ed25519Signing, KeyCustody,
        KeyMutation, MlDsa65Signing, MlKem768Private, MlKemEncapsulationEntropy, PacketCarrier,
        PendingId, PendingItem, PendingKind, PlaintextReceiver, SecretHandle, StagedSecretHandle,
        TrustFacts, Versioned, X25519Private, drive_pending, release_plaintext,
    },
    transport::{self, TransportOutcome, TransportRequest},
};

mod sealed {
    pub trait Role {}
}

/// Closed role marker; downstream crates cannot add a third Endpoint role.
///
/// ```compile_fail
/// struct ThirdRole;
/// impl licoarc::endpoint::Role for ThirdRole {}
/// ```
pub trait Role: sealed::Role {}

#[derive(Debug)]
pub struct Initiator;
#[derive(Debug)]
pub struct Responder;
impl sealed::Role for Initiator {}
impl sealed::Role for Responder {}
impl Role for Initiator {}
impl Role for Responder {}

#[derive(Clone, Eq, PartialEq)]
pub struct IdentitySigningHandles {
    pub ed25519: SecretHandle<Ed25519Signing>,
    pub ml_dsa_65: SecretHandle<MlDsa65Signing>,
}

/// Identity material admitted through the caller-owned trust boundary and
/// bound to one verified protection profile. Its constructor is deliberately
/// not exposed.
#[derive(Clone, Eq, PartialEq)]
pub struct TrustedIdentity {
    identity: IdentityPublic,
    protection_profile_id: [u8; 32],
}

impl fmt::Debug for TrustedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedIdentity([REDACTED])")
    }
}

impl TrustedIdentity {
    pub fn resolve(
        line: &VerifiedProtocolLine,
        trust: &impl TrustFacts,
        identity: IdentityPublic,
    ) -> Result<Self, Error> {
        validate_identity_shape(&identity)?;
        let profile = line.protection_profile_id();
        let facts = [
            (
                "ed25519-key-id",
                identity.ed25519_key_id.as_slice(),
                32_usize,
            ),
            (
                "ed25519-public",
                identity.ed25519_public.as_slice(),
                32_usize,
            ),
            (
                "ml-dsa-65-key-id",
                identity.ml_dsa_65_key_id.as_slice(),
                32_usize,
            ),
            (
                "ml-dsa-65-public",
                identity.ml_dsa_65_public.as_slice(),
                crate::provider::ML_DSA_65_PUBLIC_KEY_BYTES,
            ),
        ];
        for (purpose, expected, length) in facts {
            let trusted = trust.identity_key(&identity.state_digest, purpose, profile)?;
            if trusted.len() != length || trusted.as_slice() != expected {
                return Err(handshake_error());
            }
        }
        Ok(Self {
            identity,
            protection_profile_id: *profile,
        })
    }

    fn for_line<'a>(&'a self, line: &RuntimeLine) -> Result<&'a IdentityPublic, Error> {
        if self.protection_profile_id != *line.protection_profile_id() {
            return Err(handshake_error());
        }
        Ok(&self.identity)
    }
}

#[derive(Clone, Copy)]
struct RuntimeLine {
    protocol_line_id: [u8; 32],
    protection_profile_id: [u8; 32],
}

impl RuntimeLine {
    fn from_verified(line: &VerifiedProtocolLine) -> Self {
        Self {
            protocol_line_id: *line.protocol_line_id(),
            protection_profile_id: *line.protection_profile_id(),
        }
    }

    const fn protocol_line_id(&self) -> &[u8; 32] {
        &self.protocol_line_id
    }

    const fn protection_profile_id(&self) -> &[u8; 32] {
        &self.protection_profile_id
    }
}

impl fmt::Debug for RuntimeLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeLine([REDACTED])")
    }
}

impl fmt::Debug for IdentitySigningHandles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentitySigningHandles([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct IdentityPublic {
    pub state_digest: [u8; 32],
    pub ed25519_key_id: [u8; 32],
    pub ed25519_public: [u8; 32],
    pub ml_dsa_65_key_id: [u8; 32],
    pub ml_dsa_65_public: Vec<u8>,
}

impl fmt::Debug for IdentityPublic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityPublic([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PrekeyBundle {
    pub protocol_line_id: [u8; 32],
    pub protection_profile_id: [u8; 32],
    pub responder_identity_state_digest: [u8; 32],
    pub ed25519_key_id: [u8; 32],
    pub ml_dsa_65_key_id: [u8; 32],
    pub pair_sequence: u64,
    pub x25519_public: [u8; 32],
    pub ml_kem_768_public: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub ed25519_signature: [u8; 64],
    pub ml_dsa_65_signature: Vec<u8>,
}

impl fmt::Debug for PrekeyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrekeyBundle([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FirstPacket {
    pub protocol_line_id: [u8; 32],
    pub protection_profile_id: [u8; 32],
    pub initiator_identity_state_digest: [u8; 32],
    pub initiator_user_authority_state_digest: [u8; 32],
    pub responder_identity_state_digest: [u8; 32],
    pub responder_user_authority_state_digest: [u8; 32],
    pub prekey: PrekeyBundle,
    pub initiator_x25519_public: [u8; 32],
    pub ml_kem_768_ciphertext: Vec<u8>,
    pub initiator_ed25519_key_id: [u8; 32],
    pub initiator_ml_dsa_65_key_id: [u8; 32],
    pub initiator_ed25519_signature: [u8; 64],
    pub initiator_ml_dsa_65_signature: Vec<u8>,
    pub client_confirm_ciphertext: [u8; 36],
    pub client_confirm_tag: [u8; 16],
}

impl fmt::Debug for FirstPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstPacket([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SessionAccept {
    pub transcript_digest: [u8; 32],
    pub session_context_digest: [u8; 32],
    pub initiator_user_authority_state_digest: [u8; 32],
    pub responder_identity_state_digest: [u8; 32],
    pub responder_user_authority_state_digest: [u8; 32],
    pub pair_sequence: u64,
    pub mac: [u8; 32],
}

impl fmt::Debug for SessionAccept {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionAccept([REDACTED])")
    }
}

/// Caller-supplied starting state for the non-protection capability reducers.
/// It becomes reachable only through the Endpoint's revisioned state commit.
#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityRuntime {
    governance: GovernanceState,
    identity: Option<ChainTip>,
    reliable: ReliableState,
    group: GroupState,
    last_message_id: Option<[u8; 16]>,
    last_transport_outcome: Option<TransportOutcome>,
}

impl fmt::Debug for CapabilityRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityRuntime([REDACTED])")
    }
}

impl CapabilityRuntime {
    pub fn new(
        governance: GovernanceState,
        identity: Option<ChainTip>,
        reliable: ReliableState,
        group: GroupState,
    ) -> Result<Self, Error> {
        group.validate()?;
        reliable::validate_counters(
            u64::from(reliable.retries),
            u64::from(reliable.migrations),
            reliable.transitions,
        )?;
        Ok(Self {
            governance,
            identity,
            reliable,
            group,
            last_message_id: None,
            last_transport_outcome: None,
        })
    }
}

/// One all-capability operation. Validation and reducer work is tentative until
/// the Endpoint's single compare-and-swap succeeds.
pub struct CompleteCapabilityFlow<'a> {
    pub governance: &'a GovernanceCandidate,
    pub identity: ChainTip,
    pub identity_predecessor: Option<[u8; 32]>,
    pub message: &'a Message,
    pub reliable_route_digest: [u8; 32],
    pub group_author: [u8; 32],
    pub group_operation: GroupOperation,
    pub group_message_id: [u8; 16],
    pub group_payload: &'a [u8],
    pub confirmation: &'a EndpointConfirmation,
    pub confirmation_session: &'a AuthorizedSession,
    pub current_finality: FinalityState,
    pub expected_result_digest: Option<[u8; 32]>,
    pub attachment_complete: bool,
    pub transport_request: &'a TransportRequest<'a>,
    pub transport_status: u16,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CapabilityReceipt {
    pub protected_packet: Vec<u8>,
    pub projections: Vec<Projection>,
    pub transport_outcome: TransportOutcome,
}

impl fmt::Debug for CapabilityReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityReceipt([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ActivePrekey {
    bundle: PrekeyBundle,
    x25519_private: SecretHandle<X25519Private>,
    ml_kem_private: SecretHandle<MlKem768Private>,
}

impl fmt::Debug for ActivePrekey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivePrekey")
            .field("pair_sequence", &self.bundle.pair_sequence)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EndpointState {
    phase: Phase,
}

#[derive(Clone, Eq, PartialEq)]
enum Phase {
    InitiatorNew,
    InitiatorAwaiting {
        first_packet: Box<FirstPacket>,
        transcript_digest: [u8; 32],
        session_context: [u8; 32],
        hybrid: HybridSecrets,
        ratchet: Box<RatchetState>,
    },
    ResponderReady {
        high_water: u64,
        active: HashMap<u64, ActivePrekey>,
    },
    Established {
        session: Box<RatchetState>,
        replay_digest: Option<[u8; 32]>,
        retry_accept: Option<SessionAccept>,
        prekey_high_water: Option<u64>,
        capabilities: Option<Box<CapabilityRuntime>>,
    },
    Deleted {
        prekey_high_water: Option<u64>,
    },
}

impl fmt::Debug for EndpointState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match &self.phase {
            Phase::InitiatorNew => "initiator-new",
            Phase::InitiatorAwaiting { .. } => "initiator-awaiting",
            Phase::ResponderReady { .. } => "responder-ready",
            Phase::Established { .. } => "established",
            Phase::Deleted { .. } => "deleted",
        };
        formatter
            .debug_struct("EndpointState")
            .field("phase", &phase)
            .finish()
    }
}

impl EndpointState {
    #[must_use]
    pub const fn initiator() -> Self {
        Self {
            phase: Phase::InitiatorNew,
        }
    }

    #[must_use]
    pub fn responder() -> Self {
        Self {
            phase: Phase::ResponderReady {
                high_water: 0,
                active: HashMap::new(),
            },
        }
    }
}

pub struct Endpoint<R: Role, P, C, S> {
    line: RuntimeLine,
    provider: P,
    custody: C,
    store: S,
    role: PhantomData<fn() -> R>,
}

impl<R: Role, P, C, S> fmt::Debug for Endpoint<R, P, C, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Endpoint([REDACTED])")
    }
}

impl<R: Role, P, C, S> Endpoint<R, P, C, S> {
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }
}

impl<P: Provider, C: KeyCustody, S: AtomicState<EndpointState>> Endpoint<Responder, P, C, S> {
    pub fn responder(
        line: VerifiedProtocolLine,
        provider: P,
        custody: C,
        store: S,
    ) -> Result<Self, Error> {
        let current = store.load()?;
        ensure_live(current.state())?;
        if !matches!(current.state().phase, Phase::ResponderReady { .. }) {
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

    #[allow(clippy::too_many_arguments)]
    pub fn admit_prekey(
        &mut self,
        identity: &IdentityPublic,
        signing: &IdentitySigningHandles,
        pair_sequence: u64,
        x25519_private: StagedSecretHandle<X25519Private>,
        ml_kem_private: StagedSecretHandle<MlKem768Private>,
        valid_from: u64,
        valid_until: u64,
    ) -> Result<PrekeyBundle, Error> {
        let mut commit_attempted = false;
        let result = (|| {
            let current = self.store.load()?;
            ensure_live(current.state())?;
            if valid_from >= valid_until
                || valid_until
                    .checked_sub(valid_from)
                    .is_none_or(|span| span > 604_800)
                || valid_until > crate::state::MAX_SAFE_INTEGER
                || pair_sequence == 0
                || pair_sequence > 9_007_199_254_740_991
            {
                return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
            }
            validate_identity_shape(identity)?;
            verify_local_signing(&self.custody, identity, signing)?;
            let Phase::ResponderReady { high_water, active } = &current.state().phase else {
                return Err(transition_error());
            };
            if pair_sequence <= *high_water || active.len() >= MAX_ACTIVE_PREKEY_PAIRS {
                return Err(Error::terminal(
                    ErrorCode::PrekeyConsumed,
                    Stage::Validation,
                ));
            }
            let mut bundle = PrekeyBundle {
                protocol_line_id: *self.line.protocol_line_id(),
                protection_profile_id: *self.line.protection_profile_id(),
                responder_identity_state_digest: identity.state_digest,
                ed25519_key_id: identity.ed25519_key_id,
                ml_dsa_65_key_id: identity.ml_dsa_65_key_id,
                pair_sequence,
                x25519_public: self
                    .custody
                    .x25519_public(CustodyRef::Staged(&x25519_private))
                    .map_err(|_| provider_error())?,
                ml_kem_768_public: self
                    .custody
                    .ml_kem_768_public(CustodyRef::Staged(&ml_kem_private))
                    .map_err(|_| provider_error())?,
                valid_from,
                valid_until,
                ed25519_signature: [0; 64],
                ml_dsa_65_signature: Vec::new(),
            };
            let signature_input = bundle_signature_input(&bundle)?;
            bundle.ed25519_signature = self
                .custody
                .ed25519_sign(&signing.ed25519, &signature_input)
                .map_err(|_| provider_error())?;
            bundle.ml_dsa_65_signature = self
                .custody
                .ml_dsa_65_sign(&signing.ml_dsa_65, &signature_input)
                .map_err(|_| provider_error())?;
            let mut next_active = active.clone();
            next_active.insert(
                pair_sequence,
                ActivePrekey {
                    bundle: bundle.clone(),
                    x25519_private: x25519_private.adopted_handle(),
                    ml_kem_private: ml_kem_private.adopted_handle(),
                },
            );
            let next = EndpointState {
                phase: Phase::ResponderReady {
                    high_water: pair_sequence,
                    active: next_active,
                },
            };
            commit_attempted = true;
            commit_with_mutations(
                &mut self.store,
                &current,
                next,
                vec![
                    KeyMutation::AdoptX25519(x25519_private.clone()),
                    KeyMutation::AdoptMlKem768(ml_kem_private.clone()),
                ],
            )?;
            Ok(bundle)
        })();
        if let Err(error) = result
            && (!commit_attempted || !error.retryable)
        {
            self.custody.abort_x25519(&x25519_private);
            self.custody.abort_ml_kem_768(&ml_kem_private);
        }
        result
    }

    pub fn accept_first_packet(
        &mut self,
        initiator_identity: &TrustedIdentity,
        responder_identity: &IdentityPublic,
        responder_user_authority_state_digest: [u8; 32],
        packet: &FirstPacket,
        clock: &impl Clock,
    ) -> Result<SessionAccept, Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        validate_identity_shape(responder_identity)?;
        validate_first_packet_shape(packet)?;
        let now = clock.now_unix_seconds()?;
        let initiator_identity = initiator_identity.for_line(&self.line)?;
        if let Phase::Established {
            replay_digest: Some(digest),
            retry_accept: Some(accept),
            ..
        } = &current.state().phase
        {
            if *digest == first_packet_digest(&self.provider, packet)? {
                return Ok(accept.clone());
            }
            return Err(Error::terminal(
                ErrorCode::PrekeyConsumed,
                Stage::Validation,
            ));
        }
        let Phase::ResponderReady { high_water, active } = &current.state().phase else {
            return Err(transition_error());
        };
        let prekey = active
            .get(&packet.prekey.pair_sequence)
            .ok_or_else(|| Error::terminal(ErrorCode::PrekeyConsumed, Stage::Validation))?;
        if packet.prekey != prekey.bundle
            || packet.protocol_line_id != *self.line.protocol_line_id()
            || packet.protection_profile_id != *self.line.protection_profile_id()
            || packet.responder_identity_state_digest != responder_identity.state_digest
            || packet.responder_user_authority_state_digest != responder_user_authority_state_digest
            || now < prekey.bundle.valid_from
            || now >= prekey.bundle.valid_until
            || packet.prekey.pair_sequence > *high_water
        {
            return Err(handshake_error());
        }
        verify_bundle(&self.provider, responder_identity, &packet.prekey)?;
        let core = handshake_core(&self.provider, packet)?;
        verify_handshake_authentication(&self.provider, initiator_identity, packet)?;
        let x = self
            .custody
            .x25519(
                CustodyRef::Adopted(&prekey.x25519_private),
                &packet.initiator_x25519_public,
            )
            .map_err(|_| handshake_error())?;
        let kem = self
            .custody
            .ml_kem_768_decapsulate(&prekey.ml_kem_private, &packet.ml_kem_768_ciphertext)
            .map_err(|_| handshake_error())?;
        let prekey_digest = prekey_transcript_digest(&self.provider, packet)?;
        let hybrid = HybridSecrets::derive(&self.provider, &x, &kem, &prekey_digest, &core)
            .map_err(|_| handshake_error())?;
        hybrid.verify_client_confirmation(
            &self.provider,
            &core,
            &[
                packet.client_confirm_ciphertext.as_slice(),
                packet.client_confirm_tag.as_slice(),
            ]
            .concat(),
        )?;
        let transcript = first_packet_digest(&self.provider, packet)?;
        let context = session_context(&self.provider, &self.line, &transcript, packet)?;
        let ratchet = RatchetState::responder(
            &self.provider,
            &hybrid,
            context,
            prekey.x25519_private.clone(),
            prekey.bundle.x25519_public,
            packet.initiator_x25519_public,
        )?;
        let mut accept = SessionAccept {
            transcript_digest: transcript,
            session_context_digest: context,
            initiator_user_authority_state_digest: packet.initiator_user_authority_state_digest,
            responder_identity_state_digest: responder_identity.state_digest,
            responder_user_authority_state_digest,
            pair_sequence: packet.prekey.pair_sequence,
            mac: [0; 32],
        };
        accept.mac = hybrid.session_accept_mac(&self.provider, &accept_unsigned(&accept)?)?;
        let digest = first_packet_digest(&self.provider, packet)?;
        let next = EndpointState {
            phase: Phase::Established {
                session: Box::new(ratchet),
                replay_digest: Some(digest),
                retry_accept: Some(accept.clone()),
                prekey_high_water: Some(*high_water),
                capabilities: None,
            },
        };
        let mut mutations = Vec::with_capacity(active.len().saturating_mul(2));
        for candidate in active.values() {
            mutations.push(KeyMutation::DeleteMlKem768(
                candidate.ml_kem_private.clone(),
            ));
            if candidate.bundle.pair_sequence != packet.prekey.pair_sequence {
                mutations.push(KeyMutation::DeleteX25519(candidate.x25519_private.clone()));
            }
        }
        commit_with_mutations(&mut self.store, &current, next, mutations).map_err(|error| {
            if error.code == ErrorCode::Conflict {
                Error::terminal(ErrorCode::PrekeyConsumed, Stage::Commit)
            } else {
                error
            }
        })?;
        Ok(accept)
    }
}

impl<P: Provider, C: KeyCustody, S: AtomicState<EndpointState>> Endpoint<Initiator, P, C, S> {
    pub fn initiator(
        line: VerifiedProtocolLine,
        provider: P,
        custody: C,
        store: S,
    ) -> Result<Self, Error> {
        let current = store.load()?;
        ensure_live(current.state())?;
        if !matches!(current.state().phase, Phase::InitiatorNew) {
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

    #[allow(clippy::too_many_arguments)]
    pub fn create_first_packet(
        &mut self,
        initiator_identity: &IdentityPublic,
        responder_identity: &TrustedIdentity,
        initiator_user_authority_state_digest: [u8; 32],
        responder_user_authority_state_digest: [u8; 32],
        signing: &IdentitySigningHandles,
        prekey: PrekeyBundle,
        clock: &impl Clock,
        x25519_private: StagedSecretHandle<X25519Private>,
        ml_kem_entropy: SecretHandle<MlKemEncapsulationEntropy>,
    ) -> Result<FirstPacket, Error> {
        let mut commit_attempted = false;
        let result = (|| {
            let current = self.store.load()?;
            ensure_live(current.state())?;
            validate_identity_shape(initiator_identity)?;
            validate_prekey_shape(&prekey)?;
            let now = clock.now_unix_seconds()?;
            let responder_identity = responder_identity.for_line(&self.line)?;
            if let Phase::InitiatorAwaiting { first_packet, .. } = &current.state().phase {
                self.custody.abort_x25519(&x25519_private);
                return Ok(first_packet.as_ref().clone());
            }
            if !matches!(current.state().phase, Phase::InitiatorNew)
                || now < prekey.valid_from
                || now >= prekey.valid_until
                || prekey.protocol_line_id != *self.line.protocol_line_id()
                || prekey.protection_profile_id != *self.line.protection_profile_id()
            {
                return Err(handshake_error());
            }
            verify_local_signing(&self.custody, initiator_identity, signing)?;
            verify_bundle(&self.provider, responder_identity, &prekey)?;
            let (ciphertext, kem) = self
                .custody
                .ml_kem_768_encapsulate(&prekey.ml_kem_768_public, &ml_kem_entropy)
                .map_err(|_| handshake_error())?;
            let x_public = self
                .custody
                .x25519_public(CustodyRef::Staged(&x25519_private))
                .map_err(|_| handshake_error())?;
            let x = self
                .custody
                .x25519(CustodyRef::Staged(&x25519_private), &prekey.x25519_public)
                .map_err(|_| handshake_error())?;
            let mut packet = FirstPacket {
                protocol_line_id: *self.line.protocol_line_id(),
                protection_profile_id: *self.line.protection_profile_id(),
                initiator_identity_state_digest: initiator_identity.state_digest,
                initiator_user_authority_state_digest,
                responder_identity_state_digest: responder_identity.state_digest,
                responder_user_authority_state_digest,
                prekey,
                initiator_x25519_public: x_public,
                ml_kem_768_ciphertext: ciphertext,
                initiator_ed25519_key_id: initiator_identity.ed25519_key_id,
                initiator_ml_dsa_65_key_id: initiator_identity.ml_dsa_65_key_id,
                initiator_ed25519_signature: [0; 64],
                initiator_ml_dsa_65_signature: Vec::new(),
                client_confirm_ciphertext: [0; 36],
                client_confirm_tag: [0; 16],
            };
            let core = handshake_core(&self.provider, &packet)?;
            let input = [b"LICOARC-V1/HANDSHAKE/INITIATOR-SIGN\0".as_slice(), &core].concat();
            packet.initiator_ed25519_signature = self
                .custody
                .ed25519_sign(&signing.ed25519, &input)
                .map_err(|_| handshake_error())?;
            packet.initiator_ml_dsa_65_signature = self
                .custody
                .ml_dsa_65_sign(&signing.ml_dsa_65, &input)
                .map_err(|_| handshake_error())?;
            let prekey_digest = prekey_transcript_digest(&self.provider, &packet)?;
            let hybrid = HybridSecrets::derive(&self.provider, &x, &kem, &prekey_digest, &core)?;
            let confirmation = hybrid.client_confirmation(&self.provider, &core)?;
            if confirmation.len() != 52 {
                return Err(handshake_error());
            }
            packet
                .client_confirm_ciphertext
                .copy_from_slice(&confirmation[..36]);
            packet
                .client_confirm_tag
                .copy_from_slice(&confirmation[36..]);
            let transcript = first_packet_digest(&self.provider, &packet)?;
            let context = session_context(&self.provider, &self.line, &transcript, &packet)?;
            let ratchet = RatchetState::initiator(
                &self.provider,
                &hybrid,
                context,
                x25519_private.adopted_handle(),
                x_public,
                packet.prekey.x25519_public,
            )?;
            let next = EndpointState {
                phase: Phase::InitiatorAwaiting {
                    first_packet: Box::new(packet.clone()),
                    transcript_digest: transcript,
                    session_context: context,
                    hybrid,
                    ratchet: Box::new(ratchet),
                },
            };
            commit_attempted = true;
            commit_with_mutations(
                &mut self.store,
                &current,
                next,
                vec![
                    KeyMutation::AdoptX25519(x25519_private.clone()),
                    KeyMutation::DeleteMlKemEncapsulationEntropy(ml_kem_entropy.clone()),
                ],
            )?;
            Ok(packet)
        })();
        if let Err(error) = result
            && (!commit_attempted || !error.retryable)
        {
            self.custody.abort_x25519(&x25519_private);
        }
        result
    }

    pub fn verify_session_accept(&mut self, accept: &SessionAccept) -> Result<(), Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        let Phase::InitiatorAwaiting {
            first_packet,
            transcript_digest,
            session_context,
            hybrid,
            ratchet,
            ..
        } = &current.state().phase
        else {
            return Err(transition_error());
        };
        if accept.transcript_digest != *transcript_digest
            || accept.session_context_digest != *session_context
            || accept.initiator_user_authority_state_digest
                != first_packet.initiator_user_authority_state_digest
            || accept.responder_user_authority_state_digest
                != first_packet.responder_user_authority_state_digest
        {
            return Err(handshake_error());
        }
        hybrid.verify_session_accept_mac(&self.provider, &accept_unsigned(accept)?, &accept.mac)?;
        let next = EndpointState {
            phase: Phase::Established {
                session: Box::new(ratchet.as_ref().clone()),
                replay_digest: None,
                retry_accept: None,
                prekey_high_water: None,
                capabilities: None,
            },
        };
        commit(&mut self.store, &current, next)?;
        Ok(())
    }
}

impl<R: Role, P: Provider, C: KeyCustody, S: AtomicState<EndpointState>> Endpoint<R, P, C, S> {
    /// Returns the bounded, already-durable delivery work for the current
    /// revision. Items are content-opaque in diagnostics and remain pending
    /// until an explicit dispatch settles them.
    pub fn pending_items(&self) -> Result<Vec<PendingItem>, Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        Ok(current.pending().to_vec())
    }

    /// Makes exactly one carrier or application-effect attempt for a durable
    /// item and atomically settles it only after the boundary reports success.
    pub fn dispatch_pending<T: PacketCarrier, E: ApplicationEffects>(
        &mut self,
        id: PendingId,
        carrier: &mut T,
        effects: &mut E,
    ) -> Result<(), Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        let item = current
            .pending()
            .iter()
            .find(|item| item.id() == id)
            .cloned()
            .ok_or_else(transition_error)?;
        drive_pending(&mut self.store, current.revision(), &item, carrier, effects)?;
        Ok(())
    }

    /// Releases exactly one durable plaintext and settles it after the
    /// caller-owned receiver succeeds.
    pub fn release_pending_plaintext<T: PlaintextReceiver>(
        &mut self,
        id: PendingId,
        receiver: &mut T,
    ) -> Result<(), Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        let item = current
            .pending()
            .iter()
            .find(|item| item.id() == id)
            .cloned()
            .ok_or_else(transition_error)?;
        release_plaintext(&mut self.store, current.revision(), &item, receiver)?;
        Ok(())
    }

    pub fn send_record(
        &mut self,
        plaintext: &[u8],
        bootstrap_private: Option<StagedSecretHandle<X25519Private>>,
    ) -> Result<PendingId, Error> {
        let mut commit_attempted = false;
        let result = (|| {
            let current = self.store.load()?;
            ensure_live(current.state())?;
            let Phase::Established {
                session,
                replay_digest,
                retry_accept,
                prekey_high_water,
                capabilities,
            } = &current.state().phase
            else {
                return Err(transition_error());
            };
            let mut ratchet = session.as_ref().clone();
            if current
                .pending()
                .iter()
                .any(|item| matches!(item.kind(), PendingKind::Packet(_)))
            {
                return Err(transition_error());
            }
            let replaced = ratchet.local_private_handle().clone();
            if let Some(private) = bootstrap_private.as_ref() {
                ratchet = ratchet.bootstrap_responder(&self.provider, &self.custody, private)?;
            }
            let (next_ratchet, packet) = ratchet.send(&self.provider, plaintext)?;
            let pending = pending_id(&self.provider, b"record-send", &packet);
            let next = EndpointState {
                phase: Phase::Established {
                    session: Box::new(next_ratchet),
                    replay_digest: *replay_digest,
                    retry_accept: retry_accept.clone(),
                    prekey_high_water: *prekey_high_water,
                    capabilities: capabilities.clone(),
                },
            };
            let mutations = bootstrap_private.as_ref().map_or_else(Vec::new, |staged| {
                vec![
                    KeyMutation::AdoptX25519(staged.clone()),
                    KeyMutation::DeleteX25519(replaced),
                ]
            });
            let pending_item = PendingItem::packet(pending, packet)?;
            commit_attempted = true;
            commit_with_pending_and_mutations(
                &mut self.store,
                &current,
                next,
                mutations,
                vec![pending_item],
            )?;
            Ok(pending)
        })();
        if let Err(error) = result
            && (!commit_attempted || !error.retryable)
            && let Some(staged) = bootstrap_private.as_ref()
        {
            self.custody.abort_x25519(staged);
        }
        result
    }

    pub fn retry_record(&self) -> Result<PendingId, Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        let Phase::Established { .. } = &current.state().phase else {
            return Err(transition_error());
        };
        current
            .pending()
            .iter()
            .find_map(|item| match item.kind() {
                PendingKind::Packet(_) => Some(item.id()),
                PendingKind::Effect(_) | PendingKind::Plaintext(_) => None,
            })
            .ok_or_else(transition_error)
    }

    pub fn receive_record(
        &mut self,
        packet: &[u8],
        fresh_private: Option<StagedSecretHandle<X25519Private>>,
    ) -> Result<PendingId, Error> {
        let mut commit_attempted = false;
        let mut staged_settled = false;
        let result = (|| {
            let current = self.store.load()?;
            ensure_live(current.state())?;
            let Phase::Established {
                session,
                replay_digest,
                retry_accept,
                prekey_high_water,
                capabilities,
                ..
            } = &current.state().phase
            else {
                return Err(transition_error());
            };
            if current
                .pending()
                .iter()
                .any(|item| matches!(item.kind(), PendingKind::Plaintext(_)))
            {
                return Err(transition_error());
            }
            let replaced = session.local_private_handle().clone();
            let (ratchet, plaintext) = session.receive(
                &self.provider,
                &self.custody,
                packet,
                fresh_private.as_ref(),
            )?;
            let rotated =
                ratchet.local_private_handle().custody_token() != replaced.custody_token();
            let pending = pending_id(&self.provider, b"record-receive", packet);
            let next = EndpointState {
                phase: Phase::Established {
                    session: Box::new(ratchet),
                    replay_digest: *replay_digest,
                    retry_accept: retry_accept.clone(),
                    prekey_high_water: *prekey_high_water,
                    capabilities: capabilities.clone(),
                },
            };
            let mutations = if rotated {
                let staged = fresh_private.as_ref().ok_or_else(transition_error)?;
                vec![
                    KeyMutation::AdoptX25519(staged.clone()),
                    KeyMutation::DeleteX25519(replaced),
                ]
            } else {
                if let Some(staged) = fresh_private.as_ref() {
                    self.custody.abort_x25519(staged);
                    staged_settled = true;
                }
                Vec::new()
            };
            let pending_item = PendingItem::plaintext(pending, plaintext)?;
            commit_attempted = true;
            commit_with_pending_and_mutations(
                &mut self.store,
                &current,
                next,
                mutations,
                vec![pending_item],
            )?;
            Ok(pending)
        })();
        if let Err(error) = result
            && !staged_settled
            && (!commit_attempted || !error.retryable)
            && let Some(staged) = fresh_private.as_ref()
        {
            self.custody.abort_x25519(staged);
        }
        result
    }

    /// Installs the bounded non-protection state that subsequent complete
    /// capability operations evolve. Re-initialization is rejected.
    pub fn bootstrap_capabilities(&mut self, runtime: CapabilityRuntime) -> Result<(), Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        let Phase::Established {
            session,
            replay_digest,
            retry_accept,
            prekey_high_water,
            capabilities,
        } = &current.state().phase
        else {
            return Err(transition_error());
        };
        if capabilities.is_some() {
            return Err(transition_error());
        }
        let next = EndpointState {
            phase: Phase::Established {
                session: session.clone(),
                replay_digest: *replay_digest,
                retry_accept: retry_accept.clone(),
                prekey_high_water: *prekey_high_water,
                capabilities: Some(Box::new(runtime)),
            },
        };
        commit(&mut self.store, &current, next)
    }

    /// Applies Governance, Identity, opaque Messaging, Reliable, Group,
    /// confirmation, Transport and Pairwise Protection through one revisioned
    /// Endpoint commit. The protected packet and projections are released only
    /// after the compare-and-swap succeeds; Transport validation performs no I/O.
    pub fn apply_complete_capability_flow(
        &mut self,
        flow: CompleteCapabilityFlow<'_>,
        clock: &impl Clock,
    ) -> Result<CapabilityReceipt, Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        let now = clock.now_unix_seconds()?;
        let Phase::Established {
            session,
            replay_digest,
            retry_accept,
            prekey_high_water,
            capabilities: Some(capabilities),
        } = &current.state().phase
        else {
            return Err(transition_error());
        };
        let ratchet = session.as_ref();
        if current
            .pending()
            .iter()
            .any(|item| matches!(item.kind(), PendingKind::Packet(_)))
            || capabilities.last_message_id == Some(flow.message.id)
        {
            return Err(transition_error());
        }

        let governance =
            match governance::evaluate_candidate(&capabilities.governance, flow.governance, now)? {
                Adoption::Commit(state) => state,
                Adoption::Replay => capabilities.governance.clone(),
            };
        identity::validate_successor(
            capabilities.identity.as_ref(),
            &flow.identity,
            flow.identity_predecessor.as_ref(),
        )?;
        let encoded_message = flow.message.encode()?;
        let (ratchet, protected_packet) = ratchet.send(&self.provider, &encoded_message)?;
        let protected_packet_digest = self.provider.sha256(&protected_packet);
        let reliable = capabilities.reliable.retry(
            flow.reliable_route_digest,
            capabilities.reliable.intent_digest,
            protected_packet_digest,
        )?;
        let group = capabilities.group.apply_transition(
            &self.provider,
            &flow.group_author,
            flow.group_operation,
        )?;
        let projections = group.projections(
            &self.provider,
            flow.group_message_id,
            &flow.group_author,
            flow.group_payload,
        )?;
        let _finality = reliable::apply_endpoint_confirmation(
            flow.current_finality,
            flow.message.id,
            flow.confirmation,
            flow.confirmation_session,
            flow.expected_result_digest,
            flow.attachment_complete,
        )?;
        transport::validate_endpoint_request(flow.transport_request)?;
        let transport_outcome = transport::classify_status(flow.transport_status)?;

        let next_runtime = CapabilityRuntime {
            governance,
            identity: Some(flow.identity),
            reliable,
            group,
            last_message_id: Some(flow.message.id),
            last_transport_outcome: Some(transport_outcome),
        };
        let next = EndpointState {
            phase: Phase::Established {
                session: Box::new(ratchet),
                replay_digest: *replay_digest,
                retry_accept: retry_accept.clone(),
                prekey_high_water: *prekey_high_water,
                capabilities: Some(Box::new(next_runtime)),
            },
        };
        let effect = capability_effect(&projections, flow.group_payload, transport_outcome)?;
        commit_with_pending(
            &mut self.store,
            &current,
            next,
            vec![
                PendingItem::packet(
                    pending_id(&self.provider, b"capability-send", &protected_packet),
                    protected_packet.clone(),
                )?,
                PendingItem::effect(
                    pending_id(&self.provider, b"capability-effect", &effect),
                    effect,
                )?,
            ],
        )?;
        Ok(CapabilityReceipt {
            protected_packet,
            projections,
            transport_outcome,
        })
    }

    pub fn delete_session(&mut self) -> Result<(), Error> {
        let current = self.store.load()?;
        if matches!(current.state().phase, Phase::Deleted { .. }) {
            return Err(Error::terminal(ErrorCode::Deleted, Stage::Validation));
        }
        let (prekey_high_water, mutations) = match &current.state().phase {
            Phase::ResponderReady { high_water, active } => {
                let mut mutations = Vec::with_capacity(active.len().saturating_mul(2));
                for prekey in active.values() {
                    mutations.push(KeyMutation::DeleteX25519(prekey.x25519_private.clone()));
                    mutations.push(KeyMutation::DeleteMlKem768(prekey.ml_kem_private.clone()));
                }
                (Some(*high_water), mutations)
            }
            Phase::Established {
                prekey_high_water,
                session,
                ..
            } => (
                *prekey_high_water,
                vec![KeyMutation::DeleteX25519(
                    session.local_private_handle().clone(),
                )],
            ),
            Phase::InitiatorAwaiting { ratchet, .. } => (
                None,
                vec![KeyMutation::DeleteX25519(
                    ratchet.local_private_handle().clone(),
                )],
            ),
            Phase::InitiatorNew => (None, Vec::new()),
            Phase::Deleted { prekey_high_water } => (*prekey_high_water, Vec::new()),
        };
        commit_replacing_pending(
            &mut self.store,
            &current,
            EndpointState {
                phase: Phase::Deleted { prekey_high_water },
            },
            mutations,
            Vec::new(),
        )?;
        Ok(())
    }

    pub fn restart(&self, persisted_generation: u64) -> Result<(), Error> {
        let current = self.store.load()?;
        ensure_live(current.state())?;
        if persisted_generation < current.revision().value() {
            return Err(Error::terminal(ErrorCode::StateRollback, Stage::Validation));
        }
        if persisted_generation > current.revision().value() {
            return Err(Error::terminal(
                ErrorCode::InvalidTransition,
                Stage::Validation,
            ));
        }
        Ok(())
    }
}

fn commit<S: AtomicState<EndpointState>>(
    store: &mut S,
    current: &Versioned<EndpointState>,
    next: EndpointState,
) -> Result<(), Error> {
    commit_with_pending_and_mutations(store, current, next, Vec::new(), Vec::new())
}

fn commit_with_mutations<S: AtomicState<EndpointState>>(
    store: &mut S,
    current: &Versioned<EndpointState>,
    next: EndpointState,
    mutations: Vec<KeyMutation>,
) -> Result<(), Error> {
    commit_with_pending_and_mutations(store, current, next, mutations, Vec::new())
}

fn commit_with_pending<S: AtomicState<EndpointState>>(
    store: &mut S,
    current: &Versioned<EndpointState>,
    next: EndpointState,
    new_pending: Vec<PendingItem>,
) -> Result<(), Error> {
    commit_with_pending_and_mutations(store, current, next, Vec::new(), new_pending)
}

fn commit_with_pending_and_mutations<S: AtomicState<EndpointState>>(
    store: &mut S,
    current: &Versioned<EndpointState>,
    next: EndpointState,
    mutations: Vec<KeyMutation>,
    new_pending: Vec<PendingItem>,
) -> Result<(), Error> {
    let mut pending = current.pending().to_vec();
    pending.extend(new_pending);
    commit_replacing_pending(store, current, next, mutations, pending)
}

fn commit_replacing_pending<S: AtomicState<EndpointState>>(
    store: &mut S,
    current: &Versioned<EndpointState>,
    next: EndpointState,
    mutations: Vec<KeyMutation>,
    pending: Vec<PendingItem>,
) -> Result<(), Error> {
    const MAX_ENDPOINT_KEY_MUTATIONS: usize = MAX_ACTIVE_PREKEY_PAIRS * 2;
    let planned_state = next.clone();
    let planned_pending = pending.clone();
    let expected = current.revision();
    let successor = expected.successor()?;
    let commit = Commit::bounded(next, mutations, pending, MAX_ENDPOINT_KEY_MUTATIONS, 16)?;
    match store.compare_and_swap(expected, commit) {
        Ok(revision) if revision == successor => Ok(()),
        Ok(_) => Err(Error::retryable(ErrorCode::ProviderFailure, Stage::Commit)),
        Err(error) => match store.load() {
            Ok(observed)
                if observed.revision() == successor
                    && observed.state() == &planned_state
                    && observed.pending() == planned_pending =>
            {
                Ok(())
            }
            Ok(observed)
                if observed.revision() == expected
                    && observed.state() == current.state()
                    && observed.pending() == current.pending() =>
            {
                let code = if error.code == ErrorCode::Conflict {
                    ErrorCode::Conflict
                } else {
                    error.code
                };
                Err(Error::terminal(code, Stage::Commit))
            }
            Ok(observed) if observed.revision() == successor => {
                Err(Error::retryable(ErrorCode::Conflict, Stage::Commit))
            }
            Ok(_) | Err(_) => Err(Error::retryable(ErrorCode::ProviderFailure, Stage::Commit)),
        },
    }
}

fn ensure_live(state: &EndpointState) -> Result<(), Error> {
    if matches!(state.phase, Phase::Deleted { .. }) {
        return Err(Error::terminal(ErrorCode::Deleted, Stage::Validation));
    }
    Ok(())
}

fn pending_id<P: Provider>(provider: &P, kind: &[u8], bytes: &[u8]) -> PendingId {
    let digest = provider.sha256(&[b"LICOARC-V1/PENDING-ID\0".as_slice(), kind, bytes].concat());
    PendingId::from_token(u128::from_be_bytes(
        digest[..16].try_into().expect("fixed digest prefix"),
    ))
}

fn capability_effect(
    projections: &[Projection],
    payload: &[u8],
    outcome: TransportOutcome,
) -> Result<Vec<u8>, Error> {
    let projection_records = projections
        .iter()
        .map(|projection| {
            CborValue::Array(vec![
                CborValue::Bytes(projection.id().to_vec()),
                CborValue::Bytes(projection.message_id().to_vec()),
                CborValue::Bytes(projection.group_state_digest().to_vec()),
                CborValue::Bytes(projection.recipient().to_vec()),
            ])
        })
        .collect();
    let outcome = match outcome {
        TransportOutcome::Accepted => 0,
        TransportOutcome::Rejected => 1,
        TransportOutcome::Transient => 2,
        TransportOutcome::Ambiguous => 3,
    };
    encoding::encode(&CborValue::Map(std::collections::BTreeMap::from([
        (0, CborValue::Array(projection_records)),
        (1, CborValue::Bytes(payload.to_vec())),
        (2, CborValue::Unsigned(outcome)),
    ])))
}

fn verify_bundle<P: Provider>(
    provider: &P,
    identity: &IdentityPublic,
    bundle: &PrekeyBundle,
) -> Result<(), Error> {
    validate_identity_shape(identity)?;
    validate_prekey_shape(bundle)?;
    if bundle.responder_identity_state_digest != identity.state_digest
        || bundle.ed25519_key_id != identity.ed25519_key_id
        || bundle.ml_dsa_65_key_id != identity.ml_dsa_65_key_id
    {
        return Err(handshake_error());
    }
    verify_dual(
        provider,
        identity,
        &bundle_signature_input(bundle)?,
        &bundle.ed25519_signature,
        &bundle.ml_dsa_65_signature,
    )
}

fn validate_identity_shape(identity: &IdentityPublic) -> Result<(), Error> {
    if identity.ml_dsa_65_public.len() != crate::provider::ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(handshake_error());
    }
    Ok(())
}

fn validate_prekey_shape(bundle: &PrekeyBundle) -> Result<(), Error> {
    if bundle.pair_sequence == 0
        || bundle.pair_sequence > crate::state::MAX_SAFE_INTEGER
        || bundle.valid_until > crate::state::MAX_SAFE_INTEGER
        || bundle.valid_from >= bundle.valid_until
        || bundle
            .valid_until
            .checked_sub(bundle.valid_from)
            .is_none_or(|span| span > 604_800)
        || bundle.ml_kem_768_public.len() != crate::provider::ML_KEM_768_PUBLIC_KEY_BYTES
        || bundle.ml_dsa_65_signature.len() != crate::provider::ML_DSA_65_SIGNATURE_BYTES
    {
        return Err(handshake_error());
    }
    Ok(())
}

fn validate_first_packet_shape(packet: &FirstPacket) -> Result<(), Error> {
    validate_prekey_shape(&packet.prekey)?;
    if packet.protocol_line_id != packet.prekey.protocol_line_id
        || packet.protection_profile_id != packet.prekey.protection_profile_id
        || packet.responder_identity_state_digest != packet.prekey.responder_identity_state_digest
    {
        return Err(handshake_error());
    }
    if packet.ml_kem_768_ciphertext.len() != crate::provider::ML_KEM_768_CIPHERTEXT_BYTES
        || packet.initiator_ml_dsa_65_signature.len() != crate::provider::ML_DSA_65_SIGNATURE_BYTES
    {
        return Err(handshake_error());
    }
    Ok(())
}

fn verify_local_signing<C: KeyCustody>(
    custody: &C,
    identity: &IdentityPublic,
    signing: &IdentitySigningHandles,
) -> Result<(), Error> {
    if custody
        .ed25519_public(&signing.ed25519)
        .map_err(|_| handshake_error())?
        != identity.ed25519_public
        || custody
            .ml_dsa_65_public(&signing.ml_dsa_65)
            .map_err(|_| handshake_error())?
            != identity.ml_dsa_65_public
    {
        return Err(handshake_error());
    }
    Ok(())
}

const fn provider_error() -> Error {
    Error::terminal(ErrorCode::ProviderFailure, Stage::Provider)
}

fn verify_dual<P: Provider>(
    provider: &P,
    identity: &IdentityPublic,
    input: &[u8],
    ed: &[u8; 64],
    ml: &[u8],
) -> Result<(), Error> {
    provider
        .ed25519_verify_strict(&identity.ed25519_public, input, ed)
        .map_err(|_| handshake_error())?;
    provider
        .ml_dsa_65_verify(&identity.ml_dsa_65_public, input, ml)
        .map_err(|_| handshake_error())
}

fn bundle_signature_input(bundle: &PrekeyBundle) -> Result<Vec<u8>, Error> {
    Ok([
        b"LICOARC-V1/PREKEY-BUNDLE/SIGN\0".as_slice(),
        &bundle_unsigned(bundle)?,
    ]
    .concat())
}

fn bundle_unsigned_value(bundle: &PrekeyBundle) -> CborValue {
    CborValue::Map(std::collections::BTreeMap::from([
        (0, CborValue::Bytes(bundle.protocol_line_id.to_vec())),
        (1, CborValue::Bytes(bundle.protection_profile_id.to_vec())),
        (
            2,
            CborValue::Bytes(bundle.responder_identity_state_digest.to_vec()),
        ),
        (3, CborValue::Bytes(bundle.ed25519_key_id.to_vec())),
        (4, CborValue::Bytes(bundle.ml_dsa_65_key_id.to_vec())),
        (5, CborValue::Unsigned(bundle.pair_sequence)),
        (6, CborValue::Bytes(bundle.x25519_public.to_vec())),
        (7, CborValue::Bytes(bundle.ml_kem_768_public.clone())),
        (8, CborValue::Unsigned(bundle.valid_from)),
        (9, CborValue::Unsigned(bundle.valid_until)),
    ]))
}

fn bundle_unsigned(bundle: &PrekeyBundle) -> Result<Vec<u8>, Error> {
    encoding::encode(&bundle_unsigned_value(bundle))
}

fn bundle_value(bundle: &PrekeyBundle) -> CborValue {
    let CborValue::Map(mut map) = bundle_unsigned_value(bundle) else {
        unreachable!()
    };
    map.insert(10, CborValue::Bytes(bundle.ed25519_signature.to_vec()));
    map.insert(11, CborValue::Bytes(bundle.ml_dsa_65_signature.clone()));
    CborValue::Map(map)
}

fn first_packet_value(packet: &FirstPacket) -> CborValue {
    CborValue::Map(std::collections::BTreeMap::from([
        (0, CborValue::Bytes(packet.protocol_line_id.to_vec())),
        (1, CborValue::Bytes(packet.protection_profile_id.to_vec())),
        (
            2,
            CborValue::Bytes(packet.initiator_identity_state_digest.to_vec()),
        ),
        (
            3,
            CborValue::Bytes(packet.initiator_user_authority_state_digest.to_vec()),
        ),
        (
            4,
            CborValue::Bytes(packet.responder_identity_state_digest.to_vec()),
        ),
        (
            5,
            CborValue::Bytes(packet.responder_user_authority_state_digest.to_vec()),
        ),
        (6, bundle_value(&packet.prekey)),
        (7, CborValue::Bytes(packet.initiator_x25519_public.to_vec())),
        (8, CborValue::Bytes(packet.ml_kem_768_ciphertext.clone())),
        (
            9,
            CborValue::Bytes(packet.initiator_ed25519_key_id.to_vec()),
        ),
        (
            10,
            CborValue::Bytes(packet.initiator_ml_dsa_65_key_id.to_vec()),
        ),
        (
            11,
            CborValue::Bytes(packet.initiator_ed25519_signature.to_vec()),
        ),
        (
            12,
            CborValue::Bytes(packet.initiator_ml_dsa_65_signature.clone()),
        ),
        (
            13,
            CborValue::Bytes(packet.client_confirm_ciphertext.to_vec()),
        ),
        (14, CborValue::Bytes(packet.client_confirm_tag.to_vec())),
    ]))
}

pub fn encode_first_packet(packet: &FirstPacket) -> Result<Vec<u8>, Error> {
    validate_first_packet_shape(packet)?;
    let encoded = encoding::encode(&first_packet_value(packet))?;
    if encoded.len() > crate::protection::MAX_FIRST_PACKET_BYTES {
        return Err(handshake_error());
    }
    Ok(encoded)
}

pub fn decode_first_packet(bytes: &[u8]) -> Result<FirstPacket, Error> {
    if bytes.len() > crate::protection::MAX_FIRST_PACKET_BYTES {
        return Err(handshake_error());
    }
    let CborValue::Map(m) = encoding::decode(bytes)? else {
        return Err(handshake_error());
    };
    if m.len() != 15 {
        return Err(handshake_error());
    }
    let Some(CborValue::Map(p)) = m.get(&6) else {
        return Err(handshake_error());
    };
    if p.len() != 12 {
        return Err(handshake_error());
    }
    let packet = FirstPacket {
        protocol_line_id: wire_fixed(&m, 0)?,
        protection_profile_id: wire_fixed(&m, 1)?,
        initiator_identity_state_digest: wire_fixed(&m, 2)?,
        initiator_user_authority_state_digest: wire_fixed(&m, 3)?,
        responder_identity_state_digest: wire_fixed(&m, 4)?,
        responder_user_authority_state_digest: wire_fixed(&m, 5)?,
        prekey: PrekeyBundle {
            protocol_line_id: wire_fixed(p, 0)?,
            protection_profile_id: wire_fixed(p, 1)?,
            responder_identity_state_digest: wire_fixed(p, 2)?,
            ed25519_key_id: wire_fixed(p, 3)?,
            ml_dsa_65_key_id: wire_fixed(p, 4)?,
            pair_sequence: wire_uint(p, 5)?,
            x25519_public: wire_fixed(p, 6)?,
            ml_kem_768_public: wire_bytes(p, 7, 1184)?.to_vec(),
            valid_from: wire_uint(p, 8)?,
            valid_until: wire_uint(p, 9)?,
            ed25519_signature: wire_fixed(p, 10)?,
            ml_dsa_65_signature: wire_bytes(p, 11, 3309)?.to_vec(),
        },
        initiator_x25519_public: wire_fixed(&m, 7)?,
        ml_kem_768_ciphertext: wire_bytes(&m, 8, 1088)?.to_vec(),
        initiator_ed25519_key_id: wire_fixed(&m, 9)?,
        initiator_ml_dsa_65_key_id: wire_fixed(&m, 10)?,
        initiator_ed25519_signature: wire_fixed(&m, 11)?,
        initiator_ml_dsa_65_signature: wire_bytes(&m, 12, 3309)?.to_vec(),
        client_confirm_ciphertext: wire_fixed(&m, 13)?,
        client_confirm_tag: wire_fixed(&m, 14)?,
    };
    validate_first_packet_shape(&packet)?;
    Ok(packet)
}

fn wire_bytes(
    map: &std::collections::BTreeMap<u64, CborValue>,
    label: u64,
    length: usize,
) -> Result<&[u8], Error> {
    match map.get(&label) {
        Some(CborValue::Bytes(value)) if value.len() == length => Ok(value),
        _ => Err(handshake_error()),
    }
}
fn wire_fixed<const N: usize>(
    map: &std::collections::BTreeMap<u64, CborValue>,
    label: u64,
) -> Result<[u8; N], Error> {
    wire_bytes(map, label, N)?
        .try_into()
        .map_err(|_| handshake_error())
}
fn wire_uint(map: &std::collections::BTreeMap<u64, CborValue>, label: u64) -> Result<u64, Error> {
    match map.get(&label) {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        _ => Err(handshake_error()),
    }
}

fn prekey_transcript_digest<P: Provider>(
    provider: &P,
    packet: &FirstPacket,
) -> Result<[u8; 32], Error> {
    let encoded = encoding::encode(&CborValue::Array(vec![
        CborValue::Bytes(packet.protocol_line_id.to_vec()),
        CborValue::Bytes(packet.protection_profile_id.to_vec()),
        CborValue::Bytes(packet.initiator_identity_state_digest.to_vec()),
        CborValue::Bytes(packet.initiator_ed25519_key_id.to_vec()),
        CborValue::Bytes(packet.initiator_ml_dsa_65_key_id.to_vec()),
        bundle_unsigned_value(&packet.prekey),
    ]))?;
    Ok(provider.sha256(
        &[
            b"LICOARC-V1/PREKEY-TRANSCRIPT/DIGEST\0".as_slice(),
            &encoded,
        ]
        .concat(),
    ))
}

fn handshake_core<P: Provider>(provider: &P, packet: &FirstPacket) -> Result<[u8; 32], Error> {
    let encoded = encoding::encode(&CborValue::Array(vec![
        CborValue::Bytes(prekey_transcript_digest(provider, packet)?.to_vec()),
        CborValue::Bytes(packet.protocol_line_id.to_vec()),
        CborValue::Bytes(packet.protection_profile_id.to_vec()),
        CborValue::Bytes(packet.initiator_identity_state_digest.to_vec()),
        CborValue::Bytes(packet.initiator_user_authority_state_digest.to_vec()),
        CborValue::Bytes(packet.responder_identity_state_digest.to_vec()),
        CborValue::Bytes(packet.responder_user_authority_state_digest.to_vec()),
        CborValue::Bytes(packet.initiator_ed25519_key_id.to_vec()),
        CborValue::Bytes(packet.initiator_ml_dsa_65_key_id.to_vec()),
        CborValue::Bytes(packet.initiator_x25519_public.to_vec()),
        CborValue::Bytes(packet.ml_kem_768_ciphertext.clone()),
    ]))?;
    Ok(provider.sha256(
        &[
            b"LICOARC-V1/HANDSHAKE-TRANSCRIPT/DIGEST\0".as_slice(),
            &encoded,
        ]
        .concat(),
    ))
}

pub(crate) fn verify_handshake_authentication<P: Provider>(
    provider: &P,
    identity: &IdentityPublic,
    packet: &FirstPacket,
) -> Result<(), Error> {
    validate_identity_shape(identity)?;
    validate_first_packet_shape(packet)?;
    if packet.initiator_identity_state_digest != identity.state_digest
        || packet.initiator_ed25519_key_id != identity.ed25519_key_id
        || packet.initiator_ml_dsa_65_key_id != identity.ml_dsa_65_key_id
    {
        return Err(handshake_error());
    }
    let input = [
        b"LICOARC-V1/HANDSHAKE/INITIATOR-SIGN\0".as_slice(),
        &handshake_core(provider, packet)?,
    ]
    .concat();
    verify_dual(
        provider,
        identity,
        &input,
        &packet.initiator_ed25519_signature,
        &packet.initiator_ml_dsa_65_signature,
    )
}

fn first_packet_digest<P: Provider>(provider: &P, packet: &FirstPacket) -> Result<[u8; 32], Error> {
    Ok(provider.sha256(
        &[
            b"LICOARC-V1/HANDSHAKE-TRANSCRIPT/DIGEST\0".as_slice(),
            &encode_first_packet(packet)?,
        ]
        .concat(),
    ))
}

fn session_context<P: Provider>(
    provider: &P,
    line: &RuntimeLine,
    transcript: &[u8; 32],
    packet: &FirstPacket,
) -> Result<[u8; 32], Error> {
    let encoded = encoding::encode(&CborValue::Array(vec![
        CborValue::Bytes(line.protocol_line_id().to_vec()),
        CborValue::Bytes(line.protection_profile_id().to_vec()),
        CborValue::Bytes(transcript.to_vec()),
        CborValue::Bytes(packet.initiator_identity_state_digest.to_vec()),
        CborValue::Bytes(packet.initiator_user_authority_state_digest.to_vec()),
        CborValue::Bytes(packet.responder_identity_state_digest.to_vec()),
        CborValue::Bytes(packet.responder_user_authority_state_digest.to_vec()),
        CborValue::Unsigned(packet.prekey.pair_sequence),
    ]))?;
    Ok(provider.sha256(&[b"LICOARC-V1/SESSION/CONTEXT\0".as_slice(), &encoded].concat()))
}

fn accept_unsigned(accept: &SessionAccept) -> Result<Vec<u8>, Error> {
    let encoded = encoding::encode(&CborValue::Map(std::collections::BTreeMap::from([
        (0, CborValue::Bytes(accept.transcript_digest.to_vec())),
        (1, CborValue::Bytes(accept.session_context_digest.to_vec())),
        (
            2,
            CborValue::Bytes(accept.initiator_user_authority_state_digest.to_vec()),
        ),
        (
            3,
            CborValue::Bytes(accept.responder_identity_state_digest.to_vec()),
        ),
        (
            4,
            CborValue::Bytes(accept.responder_user_authority_state_digest.to_vec()),
        ),
        (5, CborValue::Unsigned(accept.pair_sequence)),
    ])))?;
    if encoded
        .len()
        .checked_add(35)
        .is_none_or(|length| length > crate::protection::MAX_SESSION_ACCEPT_BYTES)
    {
        return Err(Error::terminal(ErrorCode::BoundExceeded, Stage::Validation));
    }
    Ok(encoded)
}

const fn transition_error() -> Error {
    Error::terminal(ErrorCode::InvalidTransition, Stage::Validation)
}
const fn handshake_error() -> Error {
    Error::terminal(ErrorCode::HandshakeRejected, Stage::Validation)
}
