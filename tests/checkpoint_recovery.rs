//! Checkpoint recovery: one committed Endpoint snapshot survives a process
//! boundary and continues its ratchet.
//!
//! These cases are synthetic end to end: caller-owned custody is an in-memory
//! map, the durable state is an in-memory store, keys and payloads are fixed
//! markers, and the admitted Line comes from the explicit read-only authority
//! bundle named by `LICOARC_AUTHORITY_BUNDLE`. No real key, endpoint, user
//! database, or operational material is involved.

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use licoarc::{
    AuthorityBundle, Error, ErrorCode, Stage,
    encoding::{self, CborValue},
    endpoint::{
        CheckpointIntegrityKey, Endpoint, EndpointCheckpoint, EndpointState, IdentityPublic,
        IdentitySigningHandles, Initiator, Responder, TrustedIdentity, decode_endpoint_checkpoint,
    },
    provider::{
        AgreementProvider, DigestProvider, KdfProvider, RustCryptoProvider, SignatureProvider,
    },
    state::{
        ApplicationEffects, AtomicState, Clock, Commit, CustodyRef, Ed25519Signing, KeyCustody,
        KeyMutation, MlDsa65Signing, MlKem768Private, MlKemEncapsulationEntropy, PacketCarrier,
        PendingId, PlaintextReceiver, Revision, SecretHandle, StagedSecretHandle, TrustFacts,
        Versioned, X25519Private,
    },
};

// ---------------------------------------------------------------------------
// Synthetic caller-owned custody and durable state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Eq, PartialEq)]
enum Lifecycle {
    Staged,
    Adopted,
}

#[derive(Clone)]
enum Material {
    Ed25519([u8; 32]),
    MlDsa65([u8; 32]),
    X25519([u8; 32]),
    MlKem768([u8; 64]),
    MlKemEntropy([u8; 32]),
}

#[derive(Clone, Default)]
struct TestCustody {
    provider: RustCryptoProvider,
    keys: Rc<RefCell<HashMap<u128, (Lifecycle, Material)>>>,
}

impl TestCustody {
    fn insert(&self, token: u128, lifecycle: Lifecycle, material: Material) {
        assert!(
            self.keys
                .borrow_mut()
                .insert(token, (lifecycle, material))
                .is_none(),
            "synthetic custody tokens are unique"
        );
    }

    fn signing_handles(&self, marker: u8) -> IdentitySigningHandles {
        let ed25519 = u128::from(marker) << 8;
        let ml_dsa_65 = ed25519 + 1;
        self.insert(ed25519, Lifecycle::Adopted, Material::Ed25519([marker; 32]));
        self.insert(
            ml_dsa_65,
            Lifecycle::Adopted,
            Material::MlDsa65([marker.wrapping_add(1); 32]),
        );
        IdentitySigningHandles {
            ed25519: SecretHandle::from_custody_token(ed25519),
            ml_dsa_65: SecretHandle::from_custody_token(ml_dsa_65),
        }
    }

    fn stage_x25519(&self, token: u128, private: [u8; 32]) -> StagedSecretHandle<X25519Private> {
        self.insert(token, Lifecycle::Staged, Material::X25519(private));
        StagedSecretHandle::from_custody_token(token)
    }

    fn stage_ml_kem_768(
        &self,
        token: u128,
        private: [u8; 64],
    ) -> StagedSecretHandle<MlKem768Private> {
        self.insert(token, Lifecycle::Staged, Material::MlKem768(private));
        StagedSecretHandle::from_custody_token(token)
    }

    fn entropy(&self, token: u128, entropy: [u8; 32]) -> SecretHandle<MlKemEncapsulationEntropy> {
        self.insert(token, Lifecycle::Adopted, Material::MlKemEntropy(entropy));
        SecretHandle::from_custody_token(token)
    }

    fn lookup(&self, token: u128, expected: Lifecycle) -> Result<Material, Error> {
        let keys = self.keys.borrow();
        let (lifecycle, material) = keys.get(&token).ok_or_else(missing)?;
        if *lifecycle != expected {
            return Err(missing());
        }
        Ok(material.clone())
    }

    fn referenced(&self, handle: CustodyRef<'_, X25519Private>) -> Result<Material, Error> {
        match handle {
            CustodyRef::Adopted(handle) => self.lookup(handle.custody_token(), Lifecycle::Adopted),
            CustodyRef::Staged(handle) => self.lookup(handle.custody_token(), Lifecycle::Staged),
        }
    }

    fn referenced_ml_kem(
        &self,
        handle: CustodyRef<'_, MlKem768Private>,
    ) -> Result<Material, Error> {
        match handle {
            CustodyRef::Adopted(handle) => self.lookup(handle.custody_token(), Lifecycle::Adopted),
            CustodyRef::Staged(handle) => self.lookup(handle.custody_token(), Lifecycle::Staged),
        }
    }

    fn validate_mutation(&self, mutation: &KeyMutation) -> Result<(), Error> {
        let valid = match mutation {
            KeyMutation::AdoptX25519(handle) => {
                matches!(
                    self.lookup(handle.custody_token(), Lifecycle::Staged),
                    Ok(Material::X25519(_))
                )
            }
            KeyMutation::AdoptMlKem768(handle) => matches!(
                self.lookup(handle.custody_token(), Lifecycle::Staged),
                Ok(Material::MlKem768(_))
            ),
            KeyMutation::DeleteX25519(handle) => matches!(
                self.lookup(handle.custody_token(), Lifecycle::Adopted),
                Ok(Material::X25519(_))
            ),
            KeyMutation::DeleteMlKem768(handle) => matches!(
                self.lookup(handle.custody_token(), Lifecycle::Adopted),
                Ok(Material::MlKem768(_))
            ),
            KeyMutation::DeleteMlKemEncapsulationEntropy(handle) => matches!(
                self.lookup(handle.custody_token(), Lifecycle::Adopted),
                Ok(Material::MlKemEntropy(_))
            ),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::terminal(ErrorCode::ProviderFailure, Stage::Commit))
        }
    }

    fn apply_mutation(&self, mutation: &KeyMutation) -> Result<(), Error> {
        self.validate_mutation(mutation)?;
        let token = match mutation {
            KeyMutation::AdoptX25519(handle) => handle.custody_token(),
            KeyMutation::AdoptMlKem768(handle) => handle.custody_token(),
            KeyMutation::DeleteX25519(handle) => handle.custody_token(),
            KeyMutation::DeleteMlKem768(handle) => handle.custody_token(),
            KeyMutation::DeleteMlKemEncapsulationEntropy(handle) => handle.custody_token(),
        };
        match mutation {
            KeyMutation::AdoptX25519(_) | KeyMutation::AdoptMlKem768(_) => {
                self.keys
                    .borrow_mut()
                    .get_mut(&token)
                    .expect("validated staged handle")
                    .0 = Lifecycle::Adopted;
            }
            _ => {
                self.keys.borrow_mut().remove(&token);
            }
        }
        Ok(())
    }
}

fn missing() -> Error {
    Error::terminal(ErrorCode::ProviderFailure, Stage::Provider)
}

impl KeyCustody for TestCustody {
    fn ed25519_public(&self, handle: &SecretHandle<Ed25519Signing>) -> Result<[u8; 32], Error> {
        let Material::Ed25519(private) = self.lookup(handle.custody_token(), Lifecycle::Adopted)?
        else {
            return Err(missing());
        };
        Ok(SignatureProvider::ed25519_public(&self.provider, &private))
    }

    fn ed25519_sign(
        &self,
        handle: &SecretHandle<Ed25519Signing>,
        message: &[u8],
    ) -> Result<[u8; 64], Error> {
        let Material::Ed25519(private) = self.lookup(handle.custody_token(), Lifecycle::Adopted)?
        else {
            return Err(missing());
        };
        Ok(SignatureProvider::ed25519_sign(
            &self.provider,
            &private,
            message,
        ))
    }

    fn ml_dsa_65_public(&self, handle: &SecretHandle<MlDsa65Signing>) -> Result<Vec<u8>, Error> {
        let Material::MlDsa65(private) = self.lookup(handle.custody_token(), Lifecycle::Adopted)?
        else {
            return Err(missing());
        };
        Ok(SignatureProvider::ml_dsa_65_public(
            &self.provider,
            &private,
        ))
    }

    fn ml_dsa_65_sign(
        &self,
        handle: &SecretHandle<MlDsa65Signing>,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let Material::MlDsa65(private) = self.lookup(handle.custody_token(), Lifecycle::Adopted)?
        else {
            return Err(missing());
        };
        Ok(SignatureProvider::ml_dsa_65_sign(
            &self.provider,
            &private,
            message,
        ))
    }

    fn x25519_public(&self, handle: CustodyRef<'_, X25519Private>) -> Result<[u8; 32], Error> {
        let Material::X25519(private) = self.referenced(handle)? else {
            return Err(missing());
        };
        Ok(AgreementProvider::x25519_public(&self.provider, &private))
    }

    fn x25519(
        &self,
        handle: CustodyRef<'_, X25519Private>,
        public: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        let Material::X25519(private) = self.referenced(handle)? else {
            return Err(missing());
        };
        AgreementProvider::x25519(&self.provider, &private, public)
    }

    fn ml_kem_768_public(&self, handle: CustodyRef<'_, MlKem768Private>) -> Result<Vec<u8>, Error> {
        let Material::MlKem768(private) = self.referenced_ml_kem(handle)? else {
            return Err(missing());
        };
        Ok(AgreementProvider::ml_kem_768_public(
            &self.provider,
            &private,
        ))
    }

    fn ml_kem_768_encapsulate(
        &self,
        public: &[u8],
        entropy: &SecretHandle<MlKemEncapsulationEntropy>,
    ) -> Result<(Vec<u8>, [u8; 32]), Error> {
        let Material::MlKemEntropy(entropy) =
            self.lookup(entropy.custody_token(), Lifecycle::Adopted)?
        else {
            return Err(missing());
        };
        AgreementProvider::ml_kem_768_encapsulate(&self.provider, public, &entropy)
    }

    fn ml_kem_768_decapsulate(
        &self,
        handle: &SecretHandle<MlKem768Private>,
        ciphertext: &[u8],
    ) -> Result<[u8; 32], Error> {
        let Material::MlKem768(private) =
            self.lookup(handle.custody_token(), Lifecycle::Adopted)?
        else {
            return Err(missing());
        };
        AgreementProvider::ml_kem_768_decapsulate(&self.provider, &private, ciphertext)
    }

    fn abort_x25519(&mut self, staged: &StagedSecretHandle<X25519Private>) {
        self.keys.borrow_mut().remove(&staged.custody_token());
    }

    fn abort_ml_kem_768(&mut self, staged: &StagedSecretHandle<MlKem768Private>) {
        self.keys.borrow_mut().remove(&staged.custody_token());
    }
}

/// A caller-owned durable store. Cloning shares the committed value, so a test
/// can keep an inspector while the Endpoint owns its own handle.
#[derive(Clone)]
struct Store {
    value: Rc<RefCell<Versioned<EndpointState>>>,
    custody: TestCustody,
}

impl Store {
    fn new(state: EndpointState, custody: &TestCustody) -> Self {
        Self {
            value: Rc::new(RefCell::new(Versioned::initial(state))),
            custody: custody.clone(),
        }
    }

    fn from_versioned(value: Versioned<EndpointState>, custody: &TestCustody) -> Self {
        Self {
            value: Rc::new(RefCell::new(value)),
            custody: custody.clone(),
        }
    }
}

impl AtomicState<EndpointState> for Store {
    fn load(&self) -> Result<Versioned<EndpointState>, Error> {
        Ok(self.value.borrow().clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: Commit<EndpointState>,
    ) -> Result<Revision, Error> {
        if self.value.borrow().revision() != expected {
            return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
        }
        let mutations = commit.key_mutations().to_vec();
        for mutation in &mutations {
            self.custody.validate_mutation(mutation)?;
        }
        let value = commit.into_versioned(expected)?;
        for mutation in &mutations {
            self.custody.apply_mutation(mutation)?;
        }
        let revision = value.revision();
        *self.value.borrow_mut() = value;
        Ok(revision)
    }

    fn settle(&mut self, revision: Revision, pending: PendingId) -> Result<Revision, Error> {
        let current = self.value.borrow().clone();
        if current.revision() != revision {
            return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
        }
        let mut remaining = current.pending().to_vec();
        let Some(index) = remaining.iter().position(|item| item.id() == pending) else {
            return Err(Error::terminal(ErrorCode::InvalidTransition, Stage::Commit));
        };
        remaining.remove(index);
        let value = Commit::bounded(current.state().clone(), Vec::new(), remaining, 16, 16)?
            .into_versioned(revision)?;
        let revision = value.revision();
        *self.value.borrow_mut() = value;
        Ok(revision)
    }
}

// ---------------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Carrier {
    packet: Vec<u8>,
}

impl PacketCarrier for Carrier {
    fn send(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.packet = packet.to_vec();
        Ok(())
    }
}

#[derive(Default)]
struct Effects;

impl ApplicationEffects for Effects {
    fn apply(&mut self, _effect: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Default)]
struct Receiver {
    plaintext: Vec<u8>,
}

impl PlaintextReceiver for Receiver {
    fn release(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        self.plaintext = plaintext.to_vec();
        Ok(())
    }
}

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix_seconds(&self) -> Result<u64, Error> {
        Ok(self.0)
    }
}

struct FixedTrust {
    identity: IdentityPublic,
    profile: [u8; 32],
}

impl TrustFacts for FixedTrust {
    fn identity_key(
        &self,
        state_digest: &[u8; 32],
        purpose: &'static str,
        profile: &[u8; 32],
    ) -> Result<Vec<u8>, Error> {
        if *state_digest != self.identity.state_digest || *profile != self.profile {
            return Err(Error::terminal(
                ErrorCode::AuthenticationFailed,
                Stage::Validation,
            ));
        }
        match purpose {
            "ed25519-key-id" => Ok(self.identity.ed25519_key_id.to_vec()),
            "ed25519-public" => Ok(self.identity.ed25519_public.to_vec()),
            "ml-dsa-65-key-id" => Ok(self.identity.ml_dsa_65_key_id.to_vec()),
            "ml-dsa-65-public" => Ok(self.identity.ml_dsa_65_public.clone()),
            _ => Err(Error::terminal(
                ErrorCode::AuthenticationFailed,
                Stage::Validation,
            )),
        }
    }
}

fn integrity() -> CheckpointIntegrityKey {
    static BYTES: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    CheckpointIntegrityKey::from_secret_bytes(*BYTES.get_or_init(random_secret))
}

/// The caller's endpoint identifier bound into every test checkpoint.
fn scope() -> &'static [u8] {
    b"checkpoint-recovery"
}

fn authority() -> licoarc::VerifiedProtocolLine {
    let bundle = std::env::var_os("LICOARC_AUTHORITY_BUNDLE")
        .expect("LICOARC_AUTHORITY_BUNDLE must name the explicit read-only bundle");
    let bytes = std::fs::read(bundle).expect("explicit authority bundle must be readable");
    AuthorityBundle::new(&bytes)
        .admit()
        .expect("authority bundle must verify")
}

fn identity(custody: &TestCustody, marker: u8) -> (IdentityPublic, IdentitySigningHandles) {
    let signing = custody.signing_handles(marker);
    let identity = IdentityPublic {
        state_digest: [marker.wrapping_add(2); 32],
        ed25519_key_id: [marker.wrapping_add(3); 32],
        ed25519_public: custody.ed25519_public(&signing.ed25519).unwrap(),
        ml_dsa_65_key_id: [marker.wrapping_add(4); 32],
        ml_dsa_65_public: custody.ml_dsa_65_public(&signing.ml_dsa_65).unwrap(),
    };
    (identity, signing)
}

fn trusted(line: &licoarc::VerifiedProtocolLine, identity: &IdentityPublic) -> TrustedIdentity {
    TrustedIdentity::resolve(
        line,
        &FixedTrust {
            identity: identity.clone(),
            profile: *line.protection_profile_id(),
        },
        identity.clone(),
    )
    .unwrap()
}

type ResponderEndpoint = Endpoint<Responder, RustCryptoProvider, TestCustody, Store>;
type InitiatorEndpoint = Endpoint<Initiator, RustCryptoProvider, TestCustody, Store>;

struct Session {
    line: licoarc::VerifiedProtocolLine,
    responder: ResponderEndpoint,
    initiator: InitiatorEndpoint,
    responder_store: Store,
    initiator_store: Store,
    responder_custody: TestCustody,
    initiator_custody: TestCustody,
    round: u8,
}

fn establish() -> Session {
    let line = authority();
    let clock = FixedClock(50);
    let responder_custody = TestCustody::default();
    let initiator_custody = TestCustody::default();
    let (responder_identity, responder_signing) = identity(&responder_custody, 11);
    let (initiator_identity, initiator_signing) = identity(&initiator_custody, 21);

    let responder_store = Store::new(EndpointState::responder(), &responder_custody);
    let mut responder: ResponderEndpoint = Endpoint::responder(
        line.clone(),
        RustCryptoProvider,
        responder_custody.clone(),
        responder_store.clone(),
    )
    .unwrap();
    let bundle = responder
        .admit_prekey(
            &responder_identity,
            &responder_signing,
            1,
            responder_custody.stage_x25519(0x31, random_secret()),
            responder_custody.stage_ml_kem_768(0x32, random_secret()),
            10,
            100,
        )
        .unwrap();

    let initiator_store = Store::new(EndpointState::initiator(), &initiator_custody);
    let mut initiator: InitiatorEndpoint = Endpoint::initiator(
        line.clone(),
        RustCryptoProvider,
        initiator_custody.clone(),
        initiator_store.clone(),
    )
    .unwrap();
    let first = initiator
        .create_first_packet(
            &initiator_identity,
            &trusted(&line, &responder_identity),
            [0x81; 32],
            [0x82; 32],
            &initiator_signing,
            bundle,
            &clock,
            initiator_custody.stage_x25519(0x71, random_secret()),
            initiator_custody.entropy(0x72, random_secret()),
        )
        .unwrap();
    let accept = responder
        .accept_first_packet(
            &trusted(&line, &initiator_identity),
            &responder_identity,
            [0x82; 32],
            &first,
            &clock,
        )
        .unwrap();
    initiator.verify_session_accept(&accept).unwrap();
    Session {
        line,
        responder,
        initiator,
        responder_store,
        initiator_store,
        responder_custody,
        initiator_custody,
        round: 0,
    }
}

fn exchange(session: &mut Session, from_initiator: &[u8], from_responder: &[u8]) {
    let mut carrier = Carrier::default();
    let mut effects = Effects;
    let mut receiver = Receiver::default();
    session.round += 1;
    let round = session.round;
    let responder_send = session
        .responder_custody
        .stage_x25519(0x90 + u128::from(round), [0x90 + round; 32]);
    let initiator_receive = session
        .initiator_custody
        .stage_x25519(0xA0 + u128::from(round), [0xA0 + round; 32]);

    let pending = session.initiator.send_record(from_initiator, None).unwrap();
    session
        .initiator
        .dispatch_pending(pending, &mut carrier, &mut effects)
        .unwrap();
    let received = session
        .responder
        .receive_record(&carrier.packet, None)
        .unwrap();
    session
        .responder
        .release_pending_plaintext(received, &mut receiver)
        .unwrap();
    assert_eq!(receiver.plaintext, from_initiator);

    let pending = session
        .responder
        .send_record(from_responder, Some(responder_send.clone()))
        .unwrap();
    session
        .responder
        .dispatch_pending(pending, &mut carrier, &mut effects)
        .unwrap();
    let received = session
        .initiator
        .receive_record(&carrier.packet, Some(initiator_receive.clone()))
        .unwrap();
    session
        .initiator
        .release_pending_plaintext(received, &mut receiver)
        .unwrap();
    assert_eq!(receiver.plaintext, from_responder);
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

#[test]
fn a_restored_checkpoint_is_the_exact_committed_snapshot() {
    let mut session = establish();
    exchange(&mut session, b"one", b"two");
    let provider = RustCryptoProvider;

    for (endpoint_store, checkpoint) in [
        (
            session.initiator_store.clone(),
            session.initiator.checkpoint(&integrity(), scope()).unwrap(),
        ),
        (
            session.responder_store.clone(),
            session.responder.checkpoint(&integrity(), scope()).unwrap(),
        ),
    ] {
        let live = endpoint_store.load().unwrap();
        assert_eq!(
            format!("{checkpoint:?}"),
            "EndpointCheckpoint([REDACTED])",
            "a checkpoint never prints its secret bytes"
        );
        let restore = decode_endpoint_checkpoint(
            &provider,
            &session.line,
            &checkpoint,
            &integrity(),
            scope(),
        )
        .unwrap();
        assert_eq!(restore.generation(), live.revision().value());
        assert_eq!(restore.state(), live.state(), "the snapshot is lossless");
        assert_eq!(restore.pending().len(), live.pending().len());
        let restored = restore.into_versioned().unwrap();
        assert_eq!(restored.revision(), live.revision());
        assert_eq!(restored.state(), live.state());
        assert_eq!(restored.pending(), live.pending());
    }
}

#[test]
fn a_restored_session_continues_the_ratchet_in_the_same_role() {
    let mut session = establish();
    exchange(&mut session, b"one", b"two");
    let checkpoint = session.initiator.checkpoint(&integrity(), scope()).unwrap();
    let restored = decode_endpoint_checkpoint(
        &RustCryptoProvider,
        &session.line,
        &checkpoint,
        &integrity(),
        scope(),
    )
    .unwrap()
    .into_versioned()
    .unwrap();

    // The custodian keeps the same material; only the process boundary is
    // simulated by rebuilding the endpoint from the restored snapshot.
    let custody = TestCustody::default();
    let restored_revision = restored.revision().value();
    let restored_store = Store::from_versioned(restored, &custody);
    let mut resumed: InitiatorEndpoint = Endpoint::<Initiator, _, _, _>::resume(
        session.line.clone(),
        RustCryptoProvider,
        session.initiator_custody.clone(),
        restored_store,
        restored_revision,
    )
    .unwrap();

    // The initiator already holds the sending chain its last receive derived,
    // so dispatching the next record needs no new private; the responder side
    // must perform the DH transition instead.
    let pending = resumed.send_record(b"three", None).unwrap();
    let mut carrier = Carrier::default();
    let mut effects = Effects;
    resumed
        .dispatch_pending(pending, &mut carrier, &mut effects)
        .unwrap();
    // The responder receives a new ratchet public, so it too performs a DH
    // transition and needs a fresh private; authentication succeeds only if
    // the restored initiator chain was exactly the committed one.
    let responder_receive = session
        .responder_custody
        .stage_x25519(0xD0, random_secret());
    let received = session
        .responder
        .receive_record(&carrier.packet, Some(responder_receive))
        .unwrap();
    let mut receiver = Receiver::default();
    session
        .responder
        .release_pending_plaintext(received, &mut receiver)
        .unwrap();
    assert_eq!(
        receiver.plaintext, b"three",
        "the peer accepts the next ratchet step, so no counter or key was reused"
    );

    // The original committed generation is still the truthful one.
    assert_eq!(
        resumed.restart(0).unwrap_err().code,
        ErrorCode::StateRollback
    );
    let generation = resumed.checkpoint(&integrity(), scope()).unwrap();
    let generation = decode_endpoint_checkpoint(
        &RustCryptoProvider,
        &session.line,
        &generation,
        &integrity(),
        scope(),
    )
    .unwrap()
    .generation();
    resumed.restart(generation).unwrap();
}

#[test]
fn checkpoints_refuse_tampering_truncation_unknown_versions_and_capabilities() {
    let session = establish();
    let provider = RustCryptoProvider;
    let checkpoint = session.responder.checkpoint(&integrity(), scope()).unwrap();
    let bytes = checkpoint.expose_secret_bytes().to_vec();

    // A flipped seal is refused.
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x55;
    let tampered = EndpointCheckpoint::from_secret_bytes(tampered).unwrap();
    let refused =
        decode_endpoint_checkpoint(&provider, &session.line, &tampered, &integrity(), scope())
            .unwrap_err();
    assert_eq!(refused.code, ErrorCode::DigestMismatch);

    // Truncation is refused.
    let truncated =
        EndpointCheckpoint::from_secret_bytes(bytes[..bytes.len() / 2].to_vec()).unwrap();
    assert!(
        decode_endpoint_checkpoint(&provider, &session.line, &truncated, &integrity(), scope())
            .is_err()
    );

    // An unknown version is refused before the digest is even considered.
    let CborValue::Map(mut map) = encoding::decode(&bytes).unwrap() else {
        panic!("a checkpoint is a CBOR map");
    };
    map.insert(0, CborValue::Unsigned(99));
    let unknown =
        EndpointCheckpoint::from_secret_bytes(encoding::encode(&CborValue::Map(map)).unwrap())
            .unwrap();
    let refused =
        decode_endpoint_checkpoint(&provider, &session.line, &unknown, &integrity(), scope())
            .unwrap_err();
    assert_eq!(refused.code, ErrorCode::UnsupportedDefinition);

    // The seal is keyed, so whoever can rewrite the stored bytes still cannot
    // re-seal them: patching the body and recomputing the published unkeyed
    // digest leaves the tag field invalid.
    let CborValue::Map(mut map) = encoding::decode(&bytes).unwrap() else {
        panic!("a checkpoint is a CBOR map");
    };
    map.insert(3, CborValue::Unsigned(0));
    map.remove(&6);
    let body = encoding::encode(&CborValue::Map(map.clone())).unwrap();
    let unkeyed = provider.sha256(
        &[
            b"LICOARC-V1/ENDPOINT-CHECKPOINT/SNAPSHOT\0".as_slice(),
            body.as_slice(),
        ]
        .concat(),
    );
    map.insert(6, CborValue::Bytes(unkeyed.to_vec()));
    let forged =
        EndpointCheckpoint::from_secret_bytes(encoding::encode(&CborValue::Map(map)).unwrap())
            .unwrap();
    let refused =
        decode_endpoint_checkpoint(&provider, &session.line, &forged, &integrity(), scope())
            .unwrap_err();
    assert_eq!(
        refused.code,
        ErrorCode::DigestMismatch,
        "a recomputed unkeyed digest is not a seal"
    );

    // The right bytes under the wrong integrity key are refused too.
    let wrong = CheckpointIntegrityKey::from_secret_bytes(random_secret());
    let refused =
        decode_endpoint_checkpoint(&provider, &session.line, &checkpoint, &wrong, scope())
            .unwrap_err();
    assert_eq!(refused.code, ErrorCode::DigestMismatch);

    // An unsupported capability runtime is refused, not approximated: rewrite
    // the phase payload's capability slot and reseal it.
    let CborValue::Map(mut map) = encoding::decode(&bytes).unwrap() else {
        panic!("a checkpoint is a CBOR map");
    };
    let Some(CborValue::Map(mut phase)) = map.get(&4).cloned() else {
        panic!("the phase payload is a map");
    };
    let Some(CborValue::Map(mut payload)) = phase.get(&1).cloned() else {
        panic!("the established payload is a map");
    };
    payload.insert(4, CborValue::Map(std::collections::BTreeMap::new()));
    phase.insert(1, CborValue::Map(payload));
    map.insert(4, CborValue::Map(phase));
    map.remove(&7);
    let body = encoding::encode(&CborValue::Map(map.clone())).unwrap();
    let tag = provider
        .hmac_sha256(
            integrity().expose_secret_bytes(),
            &[
                b"LICOARC-V1/ENDPOINT-CHECKPOINT/SNAPSHOT\0".as_slice(),
                body.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
    map.insert(7, CborValue::Bytes(tag.to_vec()));
    let capability =
        EndpointCheckpoint::from_secret_bytes(encoding::encode(&CborValue::Map(map)).unwrap())
            .unwrap();
    let refused =
        decode_endpoint_checkpoint(&provider, &session.line, &capability, &integrity(), scope())
            .unwrap_err();
    assert_eq!(refused.code, ErrorCode::UnsupportedDefinition);

    // Bounds are enforced on the way in.
    assert_eq!(
        EndpointCheckpoint::from_secret_bytes(Vec::new())
            .unwrap_err()
            .code,
        ErrorCode::BoundExceeded
    );
}

#[test]
fn skipped_message_keys_survive_the_boundary_and_decrypt_exactly_once() {
    let mut session = establish();
    let provider = RustCryptoProvider;
    let mut carrier = Carrier::default();
    let mut effects = Effects;
    let mut receiver = Receiver::default();

    let first = session
        .initiator
        .send_record(b"delayed-first", None)
        .unwrap();
    session
        .initiator
        .dispatch_pending(first, &mut carrier, &mut effects)
        .unwrap();
    let delayed_packet = carrier.packet.clone();
    let second = session.initiator.send_record(b"second", None).unwrap();
    session
        .initiator
        .dispatch_pending(second, &mut carrier, &mut effects)
        .unwrap();

    // Receiving only the second record stores the first as a skipped message
    // key inside the responder snapshot.
    let received = session
        .responder
        .receive_record(&carrier.packet, None)
        .unwrap();
    session
        .responder
        .release_pending_plaintext(received, &mut receiver)
        .unwrap();
    assert_eq!(receiver.plaintext, b"second");

    let live = session.responder_store.load().unwrap();
    let checkpoint = session.responder.checkpoint(&integrity(), scope()).unwrap();
    let restored =
        decode_endpoint_checkpoint(&provider, &session.line, &checkpoint, &integrity(), scope())
            .unwrap()
            .into_versioned()
            .unwrap();
    assert_eq!(
        restored.state(),
        live.state(),
        "the skipped-key map is part of the restored snapshot"
    );

    let restored_revision = restored.revision().value();
    let mut resumed: ResponderEndpoint = Endpoint::<Responder, _, _, _>::resume(
        session.line.clone(),
        RustCryptoProvider,
        session.responder_custody.clone(),
        Store::from_versioned(restored, &session.responder_custody),
        restored_revision,
    )
    .unwrap();
    let received = resumed.receive_record(&delayed_packet, None).unwrap();
    let mut restored_receiver = Receiver::default();
    resumed
        .release_pending_plaintext(received, &mut restored_receiver)
        .unwrap();
    assert_eq!(
        restored_receiver.plaintext, b"delayed-first",
        "the restored skipped key decrypts the delayed record"
    );
    let refused = resumed.receive_record(&delayed_packet, None).unwrap_err();
    assert_eq!(
        refused.code,
        ErrorCode::Replay,
        "the restored skipped key is consumed exactly once"
    );
}

#[test]
fn resume_refuses_the_wrong_role_and_a_deleted_session() {
    let mut session = establish();
    let provider = RustCryptoProvider;

    // The responder's ready snapshot is not an initiator snapshot.
    let responder_ready = session.responder.checkpoint(&integrity(), scope()).unwrap();
    let restored = decode_endpoint_checkpoint(
        &provider,
        &session.line,
        &responder_ready,
        &integrity(),
        scope(),
    )
    .unwrap()
    .into_versioned()
    .unwrap();
    let custody = TestCustody::default();
    let refused = Endpoint::<Initiator, _, _, _>::resume(
        session.line.clone(),
        RustCryptoProvider,
        session.responder_custody.clone(),
        Store::from_versioned(restored, &custody),
        0,
    )
    .unwrap_err();
    assert_eq!(refused.code, ErrorCode::InvalidTransition);

    // A deleted session never resumes.
    session.initiator.delete_session().unwrap();
    let deleted = session.initiator.checkpoint(&integrity(), scope()).unwrap();
    let restored =
        decode_endpoint_checkpoint(&provider, &session.line, &deleted, &integrity(), scope())
            .unwrap()
            .into_versioned()
            .unwrap();
    let refused = Endpoint::<Initiator, _, _, _>::resume(
        session.line.clone(),
        RustCryptoProvider,
        session.initiator_custody.clone(),
        Store::from_versioned(restored, &custody),
        0,
    )
    .unwrap_err();
    assert_eq!(refused.code, ErrorCode::Deleted);
}

#[test]
fn responder_prekeys_survive_the_boundary() {
    let line = authority();
    let provider = RustCryptoProvider;
    let custody = TestCustody::default();
    let (responder_identity, responder_signing) = identity(&custody, 11);
    let store = Store::new(EndpointState::responder(), &custody);
    let mut responder: ResponderEndpoint = Endpoint::responder(
        line.clone(),
        RustCryptoProvider,
        custody.clone(),
        store.clone(),
    )
    .unwrap();
    for sequence in 1..=2 {
        let marker = 0x30 + sequence as u8;
        responder
            .admit_prekey(
                &responder_identity,
                &responder_signing,
                sequence,
                custody.stage_x25519(u128::from(marker) + 100, [marker; 32]),
                custody.stage_ml_kem_768(u128::from(marker) + 200, [marker; 64]),
                10,
                100,
            )
            .unwrap();
    }
    let live = store.load().unwrap();
    let checkpoint = responder.checkpoint(&integrity(), scope()).unwrap();
    let restored = decode_endpoint_checkpoint(&provider, &line, &checkpoint, &integrity(), scope())
        .unwrap()
        .into_versioned()
        .unwrap();
    assert_eq!(
        restored.state(),
        live.state(),
        "active prekey pairs are lossless"
    );
    assert_eq!(restored.revision(), live.revision());

    // The same custody plus the restored snapshot resumes in the responder
    // role with both pairs still present.
    let resumed: ResponderEndpoint = Endpoint::<Responder, _, _, _>::resume(
        line,
        RustCryptoProvider,
        custody.clone(),
        Store::from_versioned(restored, &custody),
        0,
    )
    .unwrap();
    let checkpoint = resumed.checkpoint(&integrity(), scope()).unwrap();
    let restored =
        decode_endpoint_checkpoint(&provider, &authority(), &checkpoint, &integrity(), scope())
            .unwrap()
            .into_versioned()
            .unwrap();
    assert_eq!(restored.state(), live.state());
}

#[test]
fn committed_pending_output_survives_the_boundary_and_is_dispatched_once() {
    let mut session = establish();
    let provider = RustCryptoProvider;
    let pending_id = session.initiator.send_record(b"pending", None).unwrap();
    let live = session.initiator_store.load().unwrap();
    assert_eq!(live.pending().len(), 1);
    assert_eq!(live.pending()[0].id(), pending_id);

    let checkpoint = session.initiator.checkpoint(&integrity(), scope()).unwrap();
    let restored =
        decode_endpoint_checkpoint(&provider, &session.line, &checkpoint, &integrity(), scope())
            .unwrap()
            .into_versioned()
            .unwrap();
    assert_eq!(
        restored.pending(),
        live.pending(),
        "the exact committed item survives"
    );

    let resumed_store = Store::from_versioned(restored, &session.initiator_custody);
    let inspector = resumed_store.clone();
    let mut resumed: InitiatorEndpoint = Endpoint::<Initiator, _, _, _>::resume(
        session.line.clone(),
        RustCryptoProvider,
        session.initiator_custody.clone(),
        resumed_store,
        0,
    )
    .unwrap();
    let mut carrier = Carrier::default();
    let mut effects = Effects;
    resumed
        .dispatch_pending(pending_id, &mut carrier, &mut effects)
        .unwrap();
    let received = session
        .responder
        .receive_record(&carrier.packet, None)
        .unwrap();
    let mut receiver = Receiver::default();
    session
        .responder
        .release_pending_plaintext(received, &mut receiver)
        .unwrap();
    assert_eq!(receiver.plaintext, b"pending");
    assert!(
        inspector.load().unwrap().pending().is_empty(),
        "dispatching the restored item settles it exactly once"
    );
}

#[test]
fn resume_refuses_a_replayed_checkpoint_below_the_floor() {
    let mut session = establish();
    let provider = RustCryptoProvider;
    // The caller seals and persists generation G; the session then advances.
    let stale = session.initiator.checkpoint(&integrity(), scope()).unwrap();
    let restored =
        decode_endpoint_checkpoint(&provider, &session.line, &stale, &integrity(), scope())
            .unwrap()
            .into_versioned()
            .unwrap();
    let stale_generation = restored.revision().value();
    let pending = session.initiator.send_record(b"advance", None).unwrap();
    let mut carrier = Carrier::default();
    let mut effects = Effects;
    session
        .initiator
        .dispatch_pending(pending, &mut carrier, &mut effects)
        .unwrap();
    let floor = session.initiator_store.load().unwrap().revision().value();
    assert!(
        floor > stale_generation,
        "the live revision must advance past the replayed snapshot"
    );

    // Replaying the authentic-but-older bytes against the persisted floor is
    // refused as a rollback: the ratchet never rewinds.
    let refused = Endpoint::<Initiator, _, _, _>::resume(
        session.line.clone(),
        RustCryptoProvider,
        session.initiator_custody.clone(),
        Store::from_versioned(restored, &session.initiator_custody),
        floor,
    )
    .unwrap_err();
    assert_eq!(refused.code, ErrorCode::StateRollback);
}

#[test]
fn restored_state_recheckpoints_under_its_bound_line() {
    let session = establish();
    let provider = RustCryptoProvider;
    let checkpoint = session.initiator.checkpoint(&integrity(), scope()).unwrap();
    let restored =
        decode_endpoint_checkpoint(&provider, &session.line, &checkpoint, &integrity(), scope())
            .unwrap()
            .into_versioned()
            .unwrap();
    let revision = restored.revision().value();
    let resumed: InitiatorEndpoint = Endpoint::<Initiator, _, _, _>::resume(
        session.line.clone(),
        RustCryptoProvider,
        session.initiator_custody.clone(),
        Store::from_versioned(restored, &session.initiator_custody),
        revision,
    )
    .unwrap();
    // The lineage a decode bound to the state still allows the same Line to
    // checkpoint the resumed endpoint.
    let again = resumed.checkpoint(&integrity(), scope()).unwrap();
    let twice = decode_endpoint_checkpoint(&provider, &session.line, &again, &integrity(), scope())
        .unwrap()
        .into_versioned()
        .unwrap();
    assert_eq!(twice.revision().value(), revision);
}

#[test]
fn a_checkpoint_refuses_transplant_to_another_endpoint_scope() {
    let session = establish();
    let provider = RustCryptoProvider;
    // The same integrity key, Line and Profile — the only difference is the
    // endpoint scope the caller asserts at restore.
    let blob = session.initiator.checkpoint(&integrity(), scope()).unwrap();
    let refused = decode_endpoint_checkpoint(
        &provider,
        &session.line,
        &blob,
        &integrity(),
        b"other-endpoint",
    )
    .unwrap_err();
    assert_eq!(refused.code, ErrorCode::ContentIdentityMismatch);
    // The matching scope still restores the identical snapshot.
    let restored =
        decode_endpoint_checkpoint(&provider, &session.line, &blob, &integrity(), scope())
            .unwrap()
            .into_versioned()
            .unwrap();
    assert_eq!(
        restored.state(),
        &session.initiator_store.load().unwrap().state().clone()
    );
}

/// A fresh random private secret for synthetic test custody material.
fn random_secret<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).expect("synthetic secret entropy");
    bytes
}
