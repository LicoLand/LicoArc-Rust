use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

use licoarc::{
    AuthorityBundle, Error, ErrorCode, Stage,
    encoding::{self, CborValue},
    endpoint::{
        CapabilityRuntime, CompleteCapabilityFlow, Endpoint, EndpointState, IdentityPublic,
        IdentitySigningHandles, Initiator, Responder, TrustedIdentity,
    },
    governance::{
        Authorization, ConsistencyObservation, GovernanceCandidate, GovernanceState, RecoveryEvent,
        Role,
    },
    group::{GroupOperation, GroupState, Member, MemberRole},
    identity::ChainTip,
    messaging::{Message, MessageKind},
    provider::{AgreementProvider, RustCryptoProvider, SignatureProvider},
    reliable::{
        AuthorizedSession, ConfirmationOutcome, ConfirmationStage, EndpointConfirmation,
        FinalityState, Outcome, ReliableState,
    },
    state::{
        ApplicationEffects, AtomicState, Clock, Commit, CustodyRef, Ed25519Signing, KeyCustody,
        KeyMutation, MlDsa65Signing, MlKem768Private, MlKemEncapsulationEntropy, PacketCarrier,
        PendingId, PlaintextReceiver, Revision, SecretHandle, StagedSecretHandle, TrustFacts,
        Versioned, X25519Private,
    },
    transport::{TransportOutcome, TransportRequest},
};

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

#[derive(Clone)]
struct KeyRecord {
    lifecycle: Lifecycle,
    material: Material,
}

#[derive(Clone, Default)]
struct SyntheticLifecycle {
    keys: HashMap<u128, KeyRecord>,
    aborted_x25519: Vec<u128>,
    aborted_ml_kem_768: Vec<u128>,
    adopted: Vec<u128>,
    deleted: Vec<u128>,
}

type SharedLifecycle = Rc<RefCell<SyntheticLifecycle>>;

struct TestCustody {
    provider: RustCryptoProvider,
    lifecycle: SharedLifecycle,
}

impl Default for TestCustody {
    fn default() -> Self {
        Self {
            provider: RustCryptoProvider,
            lifecycle: Rc::new(RefCell::new(SyntheticLifecycle::default())),
        }
    }
}

impl TestCustody {
    fn insert(&mut self, token: u128, lifecycle: Lifecycle, material: Material) {
        assert!(
            self.lifecycle
                .borrow_mut()
                .keys
                .insert(
                    token,
                    KeyRecord {
                        lifecycle,
                        material
                    }
                )
                .is_none(),
            "synthetic custody tokens are unique"
        );
    }

    fn signing_handles(&mut self, marker: u8) -> IdentitySigningHandles {
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

    fn stage_x25519(
        &mut self,
        token: u128,
        private: [u8; 32],
    ) -> StagedSecretHandle<X25519Private> {
        self.insert(token, Lifecycle::Staged, Material::X25519(private));
        StagedSecretHandle::from_custody_token(token)
    }

    fn stage_ml_kem_768(
        &mut self,
        token: u128,
        private: [u8; 64],
    ) -> StagedSecretHandle<MlKem768Private> {
        self.insert(token, Lifecycle::Staged, Material::MlKem768(private));
        StagedSecretHandle::from_custody_token(token)
    }

    fn ml_kem_entropy(
        &mut self,
        token: u128,
        entropy: [u8; 32],
    ) -> SecretHandle<MlKemEncapsulationEntropy> {
        self.insert(token, Lifecycle::Adopted, Material::MlKemEntropy(entropy));
        SecretHandle::from_custody_token(token)
    }

    fn missing() -> Error {
        Error::terminal(ErrorCode::ProviderFailure, Stage::Provider)
    }

    fn shared_lifecycle(&self) -> SharedLifecycle {
        Rc::clone(&self.lifecycle)
    }

    fn store<S: Clone>(&self, state: S) -> Store<S> {
        Store::new(state, self.shared_lifecycle())
    }

    fn lookup(&self, token: u128, expected: Lifecycle) -> Result<Material, Error> {
        let lifecycle = self.lifecycle.borrow();
        let record = lifecycle.keys.get(&token).ok_or_else(Self::missing)?;
        if record.lifecycle != expected {
            return Err(Self::missing());
        }
        Ok(record.material.clone())
    }

    fn referenced_material<P>(&self, handle: CustodyRef<'_, P>) -> Result<Material, Error> {
        match handle {
            CustodyRef::Adopted(handle) => self.lookup(handle.custody_token(), Lifecycle::Adopted),
            CustodyRef::Staged(handle) => self.lookup(handle.custody_token(), Lifecycle::Staged),
        }
    }
}

impl KeyCustody for TestCustody {
    fn ed25519_public(&self, handle: &SecretHandle<Ed25519Signing>) -> Result<[u8; 32], Error> {
        let Material::Ed25519(private) = self.lookup(handle.custody_token(), Lifecycle::Adopted)?
        else {
            return Err(Self::missing());
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
            return Err(Self::missing());
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
            return Err(Self::missing());
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
            return Err(Self::missing());
        };
        Ok(SignatureProvider::ml_dsa_65_sign(
            &self.provider,
            &private,
            message,
        ))
    }

    fn x25519_public(&self, handle: CustodyRef<'_, X25519Private>) -> Result<[u8; 32], Error> {
        let Material::X25519(private) = self.referenced_material(handle)? else {
            return Err(Self::missing());
        };
        Ok(AgreementProvider::x25519_public(&self.provider, &private))
    }

    fn x25519(
        &self,
        handle: CustodyRef<'_, X25519Private>,
        public: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        let Material::X25519(private) = self.referenced_material(handle)? else {
            return Err(Self::missing());
        };
        AgreementProvider::x25519(&self.provider, &private, public)
    }

    fn ml_kem_768_public(&self, handle: CustodyRef<'_, MlKem768Private>) -> Result<Vec<u8>, Error> {
        let Material::MlKem768(private) = self.referenced_material(handle)? else {
            return Err(Self::missing());
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
            return Err(Self::missing());
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
            return Err(Self::missing());
        };
        AgreementProvider::ml_kem_768_decapsulate(&self.provider, &private, ciphertext)
    }

    fn abort_x25519(&mut self, staged: &StagedSecretHandle<X25519Private>) {
        let mut lifecycle = self.lifecycle.borrow_mut();
        if lifecycle
            .keys
            .get(&staged.custody_token())
            .is_some_and(|record| {
                record.lifecycle == Lifecycle::Staged
                    && matches!(record.material, Material::X25519(_))
            })
        {
            lifecycle.keys.remove(&staged.custody_token());
            lifecycle.aborted_x25519.push(staged.custody_token());
        }
    }

    fn abort_ml_kem_768(&mut self, staged: &StagedSecretHandle<MlKem768Private>) {
        let mut lifecycle = self.lifecycle.borrow_mut();
        if lifecycle
            .keys
            .get(&staged.custody_token())
            .is_some_and(|record| {
                record.lifecycle == Lifecycle::Staged
                    && matches!(record.material, Material::MlKem768(_))
            })
        {
            lifecycle.keys.remove(&staged.custody_token());
            lifecycle.aborted_ml_kem_768.push(staged.custody_token());
        }
    }
}

#[derive(Clone)]
struct Store<S: Clone> {
    value: Versioned<S>,
    rollback_after_next_cas: Option<Versioned<S>>,
    fail_before_next_cas: bool,
    fail_after_next_cas: bool,
    lifecycle: SharedLifecycle,
}
impl<S: Clone> Store<S> {
    fn new(state: S, lifecycle: SharedLifecycle) -> Self {
        Self {
            value: Versioned::initial(state),
            rollback_after_next_cas: None,
            fail_before_next_cas: false,
            fail_after_next_cas: false,
            lifecycle,
        }
    }

    fn fail_next_cas_with_rollback(&mut self, rollback: Versioned<S>) {
        self.rollback_after_next_cas = Some(rollback);
    }

    fn fail_next_cas_before_commit(&mut self) {
        self.fail_before_next_cas = true;
    }

    fn fail_next_cas_after_commit(&mut self) {
        self.fail_after_next_cas = true;
    }
}
impl<S: Clone> AtomicState<S> for Store<S> {
    fn load(&self) -> Result<Versioned<S>, Error> {
        Ok(self.value.clone())
    }
    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: Commit<S>,
    ) -> Result<Revision, Error> {
        if let Some(rollback) = self.rollback_after_next_cas.take() {
            self.value = rollback;
            return Err(Error::retryable(ErrorCode::ProviderFailure, Stage::Commit));
        }
        if std::mem::take(&mut self.fail_before_next_cas) {
            return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
        }
        if self.value.revision() != expected {
            return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
        }
        let mutations = commit.key_mutations().to_vec();
        let mut next_lifecycle = {
            let lifecycle = self.lifecycle.borrow();
            for mutation in &mutations {
                validate_mutation(&lifecycle, mutation)?;
            }
            lifecycle.clone()
        };
        let value = commit.into_versioned(expected)?;
        for mutation in &mutations {
            apply_mutation(&mut next_lifecycle, mutation)?;
        }
        *self.lifecycle.borrow_mut() = next_lifecycle;
        self.value = value;
        if std::mem::take(&mut self.fail_after_next_cas) {
            return Err(Error::retryable(ErrorCode::ProviderFailure, Stage::Commit));
        }
        Ok(self.value.revision())
    }
    fn settle(&mut self, revision: Revision, pending: PendingId) -> Result<Revision, Error> {
        if self.value.revision() != revision {
            return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
        }
        let mut remaining = self.value.pending().to_vec();
        let Some(index) = remaining.iter().position(|item| item.id() == pending) else {
            return Err(Error::terminal(ErrorCode::InvalidTransition, Stage::Commit));
        };
        remaining.remove(index);
        let commit = Commit::bounded(self.value.state().clone(), Vec::new(), remaining, 16, 16)?;
        self.value = commit.into_versioned(revision)?;
        Ok(self.value.revision())
    }
}

fn mutation_matches(
    lifecycle: &SyntheticLifecycle,
    token: u128,
    expected: Lifecycle,
    purpose: fn(&Material) -> bool,
) -> bool {
    lifecycle
        .keys
        .get(&token)
        .is_some_and(|record| record.lifecycle == expected && purpose(&record.material))
}

fn validate_mutation(lifecycle: &SyntheticLifecycle, mutation: &KeyMutation) -> Result<(), Error> {
    let valid = match mutation {
        KeyMutation::AdoptX25519(handle) => mutation_matches(
            lifecycle,
            handle.custody_token(),
            Lifecycle::Staged,
            |material| matches!(material, Material::X25519(_)),
        ),
        KeyMutation::AdoptMlKem768(handle) => mutation_matches(
            lifecycle,
            handle.custody_token(),
            Lifecycle::Staged,
            |material| matches!(material, Material::MlKem768(_)),
        ),
        KeyMutation::DeleteX25519(handle) => mutation_matches(
            lifecycle,
            handle.custody_token(),
            Lifecycle::Adopted,
            |material| matches!(material, Material::X25519(_)),
        ),
        KeyMutation::DeleteMlKem768(handle) => mutation_matches(
            lifecycle,
            handle.custody_token(),
            Lifecycle::Adopted,
            |material| matches!(material, Material::MlKem768(_)),
        ),
        KeyMutation::DeleteMlKemEncapsulationEntropy(handle) => mutation_matches(
            lifecycle,
            handle.custody_token(),
            Lifecycle::Adopted,
            |material| matches!(material, Material::MlKemEntropy(_)),
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(Error::terminal(ErrorCode::ProviderFailure, Stage::Commit))
    }
}

fn apply_mutation(lifecycle: &mut SyntheticLifecycle, mutation: &KeyMutation) -> Result<(), Error> {
    validate_mutation(lifecycle, mutation)?;
    match mutation {
        KeyMutation::AdoptX25519(handle) => {
            lifecycle
                .keys
                .get_mut(&handle.custody_token())
                .expect("validated staged X25519")
                .lifecycle = Lifecycle::Adopted;
            lifecycle.adopted.push(handle.custody_token());
        }
        KeyMutation::AdoptMlKem768(handle) => {
            lifecycle
                .keys
                .get_mut(&handle.custody_token())
                .expect("validated staged ML-KEM")
                .lifecycle = Lifecycle::Adopted;
            lifecycle.adopted.push(handle.custody_token());
        }
        KeyMutation::DeleteX25519(handle) => {
            lifecycle.keys.remove(&handle.custody_token());
            lifecycle.deleted.push(handle.custody_token());
        }
        KeyMutation::DeleteMlKem768(handle) => {
            lifecycle.keys.remove(&handle.custody_token());
            lifecycle.deleted.push(handle.custody_token());
        }
        KeyMutation::DeleteMlKemEncapsulationEntropy(handle) => {
            lifecycle.keys.remove(&handle.custody_token());
            lifecycle.deleted.push(handle.custody_token());
        }
    }
    Ok(())
}

fn assert_same_tokens(actual: &[u128], expected: &[u128]) {
    let mut actual = actual.to_vec();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

#[derive(Default)]
struct CaptureCarrier {
    packet: Vec<u8>,
}

impl PacketCarrier for CaptureCarrier {
    fn send(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.packet = packet.to_vec();
        Ok(())
    }
}

#[derive(Default)]
struct CaptureReceiver {
    plaintext: Vec<u8>,
}

impl PlaintextReceiver for CaptureReceiver {
    fn release(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        self.plaintext = plaintext.to_vec();
        Ok(())
    }
}

#[derive(Default)]
struct NoEffects;

impl ApplicationEffects for NoEffects {
    fn apply(&mut self, _: &[u8]) -> Result<(), Error> {
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
        if state_digest != &self.identity.state_digest || profile != &self.profile {
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

fn identity(custody: &mut TestCustody, marker: u8) -> (IdentityPublic, IdentitySigningHandles) {
    let signing = custody.signing_handles(marker);
    (
        IdentityPublic {
            state_digest: [marker.wrapping_add(2); 32],
            ed25519_key_id: [marker.wrapping_add(3); 32],
            ed25519_public: custody.ed25519_public(&signing.ed25519).unwrap(),
            ml_dsa_65_key_id: [marker.wrapping_add(4); 32],
            ml_dsa_65_public: custody.ml_dsa_65_public(&signing.ml_dsa_65).unwrap(),
        },
        signing,
    )
}

fn authority() -> licoarc::VerifiedProtocolLine {
    let bundle = std::env::var_os("LICOARC_AUTHORITY_BUNDLE")
        .expect("LICOARC_AUTHORITY_BUNDLE must name the explicit read-only bundle");
    let bytes = std::fs::read(bundle).expect("explicit authority bundle must be readable");
    AuthorityBundle::new(&bytes)
        .admit()
        .expect("authority bundle must verify")
}

#[test]
fn synthetic_custody_rejects_missing_stale_and_cross_purpose_handles() {
    let mut custody = TestCustody::default();
    let signing = custody.signing_handles(11);
    let staged_x25519 = custody.stage_x25519(71, [71; 32]);
    let staged_ml_kem = custody.stage_ml_kem_768(72, [72; 64]);

    assert!(
        custody
            .x25519_public(CustodyRef::Adopted(&SecretHandle::from_custody_token(404)))
            .is_err()
    );
    assert!(
        custody
            .ml_dsa_65_public(&SecretHandle::from_custody_token(
                signing.ed25519.custody_token(),
            ))
            .is_err()
    );
    assert!(
        custody
            .x25519_public(CustodyRef::Staged(&StagedSecretHandle::from_custody_token(
                staged_ml_kem.custody_token(),
            )))
            .is_err()
    );
    assert!(
        custody
            .x25519_public(CustodyRef::Adopted(&staged_x25519.adopted_handle()))
            .is_err(),
        "a staged object cannot be forged into an adopted operation"
    );

    let lifecycle = custody.shared_lifecycle();
    let mut store = custody.store(());
    let later_valid = custody.stage_x25519(75, [75; 32]);
    let bad_batch = Commit::bounded(
        (),
        vec![
            KeyMutation::AdoptX25519(later_valid.clone()),
            KeyMutation::DeleteX25519(SecretHandle::from_custody_token(
                signing.ed25519.custody_token(),
            )),
        ],
        Vec::new(),
        2,
        0,
    )
    .unwrap();
    assert_eq!(
        store
            .compare_and_swap(Revision::initial(), bad_batch)
            .unwrap_err()
            .code,
        ErrorCode::ProviderFailure
    );
    assert_eq!(store.load().unwrap().revision(), Revision::initial());
    assert!(mutation_matches(
        &lifecycle.borrow(),
        75,
        Lifecycle::Staged,
        |material| matches!(material, Material::X25519(_)),
    ));
    custody.abort_x25519(&later_valid);
    store
        .compare_and_swap(
            Revision::initial(),
            Commit::bounded(
                (),
                vec![
                    KeyMutation::AdoptX25519(staged_x25519.clone()),
                    KeyMutation::AdoptMlKem768(staged_ml_kem.clone()),
                ],
                Vec::new(),
                2,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        custody
            .x25519_public(CustodyRef::Adopted(&staged_x25519.adopted_handle()))
            .is_ok()
    );
    custody.abort_x25519(&staged_x25519);
    assert!(
        custody
            .x25519_public(CustodyRef::Adopted(&staged_x25519.adopted_handle()))
            .is_ok(),
        "abort must not remove an adopted object"
    );
    assert_eq!(lifecycle.borrow().aborted_x25519, vec![75]);

    let rejected = store
        .compare_and_swap(
            Revision::initial(),
            Commit::bounded(
                (),
                vec![KeyMutation::DeleteX25519(staged_x25519.adopted_handle())],
                Vec::new(),
                1,
                0,
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(rejected.code, ErrorCode::Conflict);
    assert!(
        custody
            .x25519_public(CustodyRef::Adopted(&staged_x25519.adopted_handle()))
            .is_ok(),
        "a losing CAS must not apply handle deletion"
    );

    let stale_x25519 = custody.stage_x25519(73, [73; 32]);
    let stale_ml_kem = custody.stage_ml_kem_768(74, [74; 64]);
    custody.abort_x25519(&stale_x25519);
    custody.abort_ml_kem_768(&stale_ml_kem);
    assert!(
        custody
            .x25519_public(CustodyRef::Staged(&stale_x25519))
            .is_err()
    );
    assert!(
        custody
            .x25519_public(CustodyRef::Adopted(&stale_x25519.adopted_handle()))
            .is_err()
    );
    assert!(
        custody
            .ml_kem_768_public(CustodyRef::Staged(&stale_ml_kem))
            .is_err()
    );
}

#[test]
fn non_exact_recovery_reads_keep_tentative_prekeys_fenced() {
    let line = authority();
    let mut custody = TestCustody::default();
    let (responder_identity, signing) = identity(&mut custody, 41);
    let x25519 = custody.stage_x25519(61, [61; 32]);
    let ml_kem = custody.stage_ml_kem_768(62, [62; 64]);
    let lifecycle = custody.shared_lifecycle();

    let initial = Versioned::initial(EndpointState::responder());
    let mut store = custody.store(EndpointState::responder());
    store
        .compare_and_swap(
            Revision::initial(),
            Commit::bounded(EndpointState::responder(), Vec::new(), Vec::new(), 0, 0).unwrap(),
        )
        .unwrap();
    store.fail_next_cas_with_rollback(initial);
    let mut endpoint =
        Endpoint::<Responder, _, _, _>::responder(line, RustCryptoProvider, custody, store)
            .unwrap();

    let error = endpoint
        .admit_prekey(&responder_identity, &signing, 1, x25519, ml_kem, 10, 100)
        .unwrap_err();
    assert_eq!(
        (error.code, error.stage),
        (ErrorCode::ProviderFailure, Stage::Commit)
    );
    assert!(error.retryable);
    assert!(lifecycle.borrow().aborted_x25519.is_empty());
    assert!(lifecycle.borrow().aborted_ml_kem_768.is_empty());
    assert!(mutation_matches(
        &lifecycle.borrow(),
        61,
        Lifecycle::Staged,
        |material| matches!(material, Material::X25519(_)),
    ));
    assert!(mutation_matches(
        &lifecycle.borrow(),
        62,
        Lifecycle::Staged,
        |material| matches!(material, Material::MlKem768(_)),
    ));

    let mut successor_custody = TestCustody::default();
    let (successor_identity, successor_signing) = identity(&mut successor_custody, 51);
    let successor_x25519 = successor_custody.stage_x25519(71, [71; 32]);
    let successor_ml_kem = successor_custody.stage_ml_kem_768(72, [72; 64]);
    let successor_lifecycle = successor_custody.shared_lifecycle();
    let competing = Commit::bounded(EndpointState::responder(), Vec::new(), Vec::new(), 0, 0)
        .unwrap()
        .into_versioned(Revision::initial())
        .unwrap();
    let mut successor_store = successor_custody.store(EndpointState::responder());
    successor_store.fail_next_cas_with_rollback(competing);
    let mut successor_endpoint = Endpoint::<Responder, _, _, _>::responder(
        authority(),
        RustCryptoProvider,
        successor_custody,
        successor_store,
    )
    .unwrap();

    let successor_error = successor_endpoint
        .admit_prekey(
            &successor_identity,
            &successor_signing,
            1,
            successor_x25519,
            successor_ml_kem,
            10,
            100,
        )
        .unwrap_err();
    assert_eq!(
        (successor_error.code, successor_error.stage),
        (ErrorCode::Conflict, Stage::Commit)
    );
    assert!(successor_error.retryable);
    assert!(successor_lifecycle.borrow().aborted_x25519.is_empty());
    assert!(successor_lifecycle.borrow().aborted_ml_kem_768.is_empty());
    assert!(mutation_matches(
        &successor_lifecycle.borrow(),
        71,
        Lifecycle::Staged,
        |material| matches!(material, Material::X25519(_)),
    ));
    assert!(mutation_matches(
        &successor_lifecycle.borrow(),
        72,
        Lifecycle::Staged,
        |material| matches!(material, Material::MlKem768(_)),
    ));
}

#[test]
fn definite_and_committed_cas_errors_have_distinct_handle_outcomes() {
    let line = authority();

    let mut rejected_custody = TestCustody::default();
    let (rejected_identity, rejected_signing) = identity(&mut rejected_custody, 41);
    let rejected_x25519 = rejected_custody.stage_x25519(61, [61; 32]);
    let rejected_ml_kem = rejected_custody.stage_ml_kem_768(62, [62; 64]);
    let rejected_lifecycle = rejected_custody.shared_lifecycle();
    let mut rejected_store = rejected_custody.store(EndpointState::responder());
    rejected_store.fail_next_cas_before_commit();
    let mut rejected = Endpoint::<Responder, _, _, _>::responder(
        line.clone(),
        RustCryptoProvider,
        rejected_custody,
        rejected_store,
    )
    .unwrap();

    let error = rejected
        .admit_prekey(
            &rejected_identity,
            &rejected_signing,
            1,
            rejected_x25519,
            rejected_ml_kem,
            10,
            100,
        )
        .unwrap_err();
    assert_eq!(
        (error.code, error.stage, error.retryable),
        (ErrorCode::Conflict, Stage::Commit, false)
    );
    {
        let lifecycle = rejected_lifecycle.borrow();
        assert!(!lifecycle.keys.contains_key(&61));
        assert!(!lifecycle.keys.contains_key(&62));
        assert_eq!(lifecycle.aborted_x25519, vec![61]);
        assert_eq!(lifecycle.aborted_ml_kem_768, vec![62]);
        assert!(lifecycle.adopted.is_empty());
    }
    assert_eq!(
        rejected.into_store().load().unwrap().revision(),
        Revision::initial()
    );

    let mut committed_custody = TestCustody::default();
    let (committed_identity, committed_signing) = identity(&mut committed_custody, 51);
    let committed_x25519 = committed_custody.stage_x25519(71, [71; 32]);
    let committed_ml_kem = committed_custody.stage_ml_kem_768(72, [72; 64]);
    let committed_lifecycle = committed_custody.shared_lifecycle();
    let mut committed_store = committed_custody.store(EndpointState::responder());
    committed_store.fail_next_cas_after_commit();
    let mut committed = Endpoint::<Responder, _, _, _>::responder(
        line,
        RustCryptoProvider,
        committed_custody,
        committed_store,
    )
    .unwrap();

    let bundle = committed
        .admit_prekey(
            &committed_identity,
            &committed_signing,
            1,
            committed_x25519,
            committed_ml_kem,
            10,
            100,
        )
        .unwrap();
    assert_eq!(bundle.pair_sequence, 1);
    {
        let lifecycle = committed_lifecycle.borrow();
        assert_same_tokens(&lifecycle.adopted, &[71, 72]);
        assert!(lifecycle.aborted_x25519.is_empty());
        assert!(lifecycle.aborted_ml_kem_768.is_empty());
    }
    assert_eq!(committed.into_store().load().unwrap().revision().value(), 1);
}

#[test]
fn handshake_and_confirmation() {
    let line = authority();
    let provider = RustCryptoProvider;
    let mut initiator_custody = TestCustody::default();
    let (initiator_identity, initiator_signing) = identity(&mut initiator_custody, 11);
    let initiator_first_private = initiator_custody.stage_x25519(71, [71; 32]);
    let initiator_retry_private = initiator_custody.stage_x25519(99, [99; 32]);
    let initiator_receive_private = initiator_custody.stage_x25519(82, [82; 32]);
    let initiator_entropy = initiator_custody.ml_kem_entropy(72, [72; 32]);
    let initiator_retry_entropy = initiator_custody.ml_kem_entropy(98, [98; 32]);
    let initiator_store = initiator_custody.store(EndpointState::initiator());
    let initiator_lifecycle = initiator_custody.shared_lifecycle();
    let mut responder_custody = TestCustody::default();
    let (responder_identity, responder_signing) = identity(&mut responder_custody, 41);
    let responder_prekey_x25519 = responder_custody.stage_x25519(61, [61; 32]);
    let responder_prekey_ml_kem = responder_custody.stage_ml_kem_768(62, [62; 64]);
    let responder_spare_x25519 = responder_custody.stage_x25519(63, [63; 32]);
    let responder_spare_ml_kem = responder_custody.stage_ml_kem_768(64, [64; 64]);
    let responder_send_private = responder_custody.stage_x25519(81, [81; 32]);
    let responder_store = responder_custody.store(EndpointState::responder());
    let responder_lifecycle = responder_custody.shared_lifecycle();
    let trusted_initiator = trusted(&line, &initiator_identity);
    let trusted_responder = trusted(&line, &responder_identity);
    let clock = FixedClock(50);
    let mut responder = Endpoint::<Responder, _, _, _>::responder(
        line.clone(),
        provider,
        responder_custody,
        responder_store,
    )
    .unwrap();
    let bundle = responder
        .admit_prekey(
            &responder_identity,
            &responder_signing,
            1,
            responder_prekey_x25519,
            responder_prekey_ml_kem,
            10,
            100,
        )
        .unwrap();
    {
        let lifecycle = responder_lifecycle.borrow();
        assert!(mutation_matches(
            &lifecycle,
            61,
            Lifecycle::Adopted,
            |material| matches!(material, Material::X25519(_)),
        ));
        assert!(mutation_matches(
            &lifecycle,
            62,
            Lifecycle::Adopted,
            |material| matches!(material, Material::MlKem768(_)),
        ));
        assert_eq!(lifecycle.adopted, vec![61, 62]);
    }
    responder
        .admit_prekey(
            &responder_identity,
            &responder_signing,
            2,
            responder_spare_x25519,
            responder_spare_ml_kem,
            10,
            100,
        )
        .unwrap();
    {
        let lifecycle = responder_lifecycle.borrow();
        assert_same_tokens(&lifecycle.adopted, &[61, 62, 63, 64]);
    }
    let mut initiator = Endpoint::<Initiator, _, _, _>::initiator(
        line,
        provider,
        initiator_custody,
        initiator_store,
    )
    .unwrap();
    let first = initiator
        .create_first_packet(
            &initiator_identity,
            &trusted_responder,
            [81; 32],
            [82; 32],
            &initiator_signing,
            bundle,
            &clock,
            initiator_first_private,
            initiator_entropy,
        )
        .unwrap();
    {
        let lifecycle = initiator_lifecycle.borrow();
        assert!(mutation_matches(
            &lifecycle,
            71,
            Lifecycle::Adopted,
            |material| matches!(material, Material::X25519(_)),
        ));
        assert!(!lifecycle.keys.contains_key(&72));
        assert_eq!(lifecycle.adopted, vec![71]);
        assert_eq!(lifecycle.deleted, vec![72]);
    }
    let retry = initiator
        .create_first_packet(
            &initiator_identity,
            &trusted_responder,
            [81; 32],
            [82; 32],
            &initiator_signing,
            first.prekey.clone(),
            &clock,
            initiator_retry_private,
            initiator_retry_entropy,
        )
        .unwrap();
    assert_eq!(retry, first);
    {
        let lifecycle = initiator_lifecycle.borrow();
        assert!(!lifecycle.keys.contains_key(&99));
        assert!(mutation_matches(
            &lifecycle,
            98,
            Lifecycle::Adopted,
            |material| matches!(material, Material::MlKemEntropy(_)),
        ));
        assert_eq!(lifecycle.aborted_x25519, vec![99]);
    }
    let wire = licoarc::endpoint::encode_first_packet(&first).unwrap();
    let first = licoarc::endpoint::decode_first_packet(&wire).unwrap();
    for slot in 0..3 {
        let mut substituted = initiator_identity.clone();
        match slot {
            0 => substituted.state_digest[0] ^= 1,
            1 => substituted.ed25519_key_id[0] ^= 1,
            _ => substituted.ml_dsa_65_key_id[0] ^= 1,
        }
        let changed_trust = trusted(&authority(), &substituted);
        assert!(
            responder
                .accept_first_packet(
                    &changed_trust,
                    &responder_identity,
                    [82; 32],
                    &first,
                    &clock,
                )
                .is_err()
        );
    }
    for field in 0..7 {
        let mut changed = first.clone();
        match field {
            0 => {
                changed.protocol_line_id[0] ^= 1;
                changed.prekey.protocol_line_id[0] ^= 1;
            }
            1 => {
                changed.protection_profile_id[0] ^= 1;
                changed.prekey.protection_profile_id[0] ^= 1;
            }
            2 => changed.initiator_ed25519_signature[0] ^= 1,
            3 => changed.initiator_ml_dsa_65_signature[0] ^= 1,
            4 => changed.client_confirm_tag[0] ^= 1,
            5 => changed.initiator_user_authority_state_digest[0] ^= 1,
            _ => changed.responder_user_authority_state_digest[0] ^= 1,
        }
        assert!(
            responder
                .accept_first_packet(
                    &trusted_initiator,
                    &responder_identity,
                    [82; 32],
                    &changed,
                    &clock,
                )
                .is_err()
        );
    }
    let accept = responder
        .accept_first_packet(
            &trusted_initiator,
            &responder_identity,
            [82; 32],
            &first,
            &clock,
        )
        .unwrap();
    assert_eq!(
        responder
            .accept_first_packet(
                &trusted_initiator,
                &responder_identity,
                [82; 32],
                &first,
                &clock,
            )
            .unwrap(),
        accept
    );
    {
        let lifecycle = responder_lifecycle.borrow();
        assert!(mutation_matches(
            &lifecycle,
            61,
            Lifecycle::Adopted,
            |material| matches!(material, Material::X25519(_)),
        ));
        assert!(!lifecycle.keys.contains_key(&62));
        assert!(!lifecycle.keys.contains_key(&63));
        assert!(!lifecycle.keys.contains_key(&64));
        assert_same_tokens(&lifecycle.deleted, &[62, 63, 64]);
    }
    let mutations_before_changed_replay = {
        let lifecycle = responder_lifecycle.borrow();
        (lifecycle.adopted.clone(), lifecycle.deleted.clone())
    };
    let mut changed_replay = first.clone();
    changed_replay.client_confirm_tag[0] ^= 1;
    assert_eq!(
        responder
            .accept_first_packet(
                &trusted_initiator,
                &responder_identity,
                [82; 32],
                &changed_replay,
                &clock,
            )
            .unwrap_err()
            .code,
        ErrorCode::PrekeyConsumed
    );
    {
        let lifecycle = responder_lifecycle.borrow();
        assert_eq!(lifecycle.adopted, mutations_before_changed_replay.0);
        assert_eq!(lifecycle.deleted, mutations_before_changed_replay.1);
    }
    initiator.verify_session_accept(&accept).unwrap();
    let i2r = initiator.send_record(b"opaque-i2r", None).unwrap();
    assert_eq!(initiator.retry_record().unwrap(), i2r);
    let mut i2r_carrier = CaptureCarrier::default();
    initiator
        .dispatch_pending(i2r, &mut i2r_carrier, &mut NoEffects)
        .unwrap();
    let received = responder.receive_record(&i2r_carrier.packet, None).unwrap();
    let mut i2r_receiver = CaptureReceiver::default();
    responder
        .release_pending_plaintext(received, &mut i2r_receiver)
        .unwrap();
    assert_eq!(i2r_receiver.plaintext, b"opaque-i2r");

    let r2i = responder
        .send_record(b"opaque-r2i", Some(responder_send_private))
        .unwrap();
    {
        let lifecycle = responder_lifecycle.borrow();
        assert!(!lifecycle.keys.contains_key(&61));
        assert!(mutation_matches(
            &lifecycle,
            81,
            Lifecycle::Adopted,
            |material| matches!(material, Material::X25519(_)),
        ));
        assert_same_tokens(&lifecycle.deleted, &[62, 63, 64, 61]);
    }
    let mut r2i_carrier = CaptureCarrier::default();
    responder
        .dispatch_pending(r2i, &mut r2i_carrier, &mut NoEffects)
        .unwrap();
    let received = initiator
        .receive_record(&r2i_carrier.packet, Some(initiator_receive_private))
        .unwrap();
    {
        let lifecycle = initiator_lifecycle.borrow();
        assert!(!lifecycle.keys.contains_key(&71));
        assert!(mutation_matches(
            &lifecycle,
            82,
            Lifecycle::Adopted,
            |material| matches!(material, Material::X25519(_)),
        ));
        assert_eq!(lifecycle.deleted, vec![72, 71]);
    }
    let mut r2i_receiver = CaptureReceiver::default();
    initiator
        .release_pending_plaintext(received, &mut r2i_receiver)
        .unwrap();
    assert_eq!(r2i_receiver.plaintext, b"opaque-r2i");

    initiator.delete_session().unwrap();
    {
        let lifecycle = initiator_lifecycle.borrow();
        assert!(!lifecycle.keys.contains_key(&82));
        assert_eq!(lifecycle.deleted, vec![72, 71, 82]);
    }
    assert_eq!(
        initiator.retry_record().unwrap_err().code,
        ErrorCode::Deleted
    );
    assert_eq!(
        initiator
            .send_record(b"after-delete", None)
            .unwrap_err()
            .code,
        ErrorCode::Deleted
    );
    assert_eq!(initiator.restart(0).unwrap_err().code, ErrorCode::Deleted);
    assert_eq!(
        initiator.delete_session().unwrap_err().code,
        ErrorCode::Deleted
    );
    responder.delete_session().unwrap();
    {
        let lifecycle = responder_lifecycle.borrow();
        assert!(!lifecycle.keys.contains_key(&81));
        assert_same_tokens(&lifecycle.deleted, &[62, 63, 64, 61, 81]);
    }
    assert!(initiator.into_store().load().unwrap().pending().is_empty());
}

#[test]
fn complete_capability_flow() {
    let line = authority();
    let provider = RustCryptoProvider;
    let mut initiator_custody = TestCustody::default();
    let (initiator_identity, initiator_signing) = identity(&mut initiator_custody, 11);
    let initiator_first_private = initiator_custody.stage_x25519(71, [71; 32]);
    let initiator_entropy = initiator_custody.ml_kem_entropy(72, [72; 32]);
    let initiator_store = initiator_custody.store(EndpointState::initiator());
    let mut responder_custody = TestCustody::default();
    let (responder_identity, responder_signing) = identity(&mut responder_custody, 41);
    let responder_prekey_x25519 = responder_custody.stage_x25519(61, [61; 32]);
    let responder_prekey_ml_kem = responder_custody.stage_ml_kem_768(62, [62; 64]);
    let responder_store = responder_custody.store(EndpointState::responder());
    let trusted_initiator = trusted(&line, &initiator_identity);
    let trusted_responder = trusted(&line, &responder_identity);
    let handshake_clock = FixedClock(50);
    let mut responder = Endpoint::<Responder, _, _, _>::responder(
        line.clone(),
        provider,
        responder_custody,
        responder_store,
    )
    .unwrap();
    let prekey = responder
        .admit_prekey(
            &responder_identity,
            &responder_signing,
            1,
            responder_prekey_x25519,
            responder_prekey_ml_kem,
            10,
            100,
        )
        .unwrap();
    let mut initiator = Endpoint::<Initiator, _, _, _>::initiator(
        line,
        provider,
        initiator_custody,
        initiator_store,
    )
    .unwrap();
    let first = initiator
        .create_first_packet(
            &initiator_identity,
            &trusted_responder,
            [81; 32],
            [82; 32],
            &initiator_signing,
            prekey,
            &handshake_clock,
            initiator_first_private,
            initiator_entropy,
        )
        .unwrap();
    let accept = responder
        .accept_first_packet(
            &trusted_initiator,
            &responder_identity,
            [82; 32],
            &first,
            &handshake_clock,
        )
        .unwrap();
    initiator.verify_session_accept(&accept).unwrap();

    let author = [10; 32];
    let recipient = [11; 32];
    initiator
        .bootstrap_capabilities(
            CapabilityRuntime::new(
                GovernanceState {
                    network_ref: [1; 32],
                    bundle_epoch: 0,
                    bundle_digest: None,
                    role_versions: BTreeMap::new(),
                },
                None,
                ReliableState {
                    intent_digest: [2; 32],
                    route_digest: [3; 32],
                    protected_packet_digest: [4; 32],
                    retries: 0,
                    migrations: 0,
                    transitions: 0,
                    outcome: Outcome::Pending,
                },
                GroupState {
                    group_id: [5; 32],
                    epoch: 0,
                    previous_digest: None,
                    members: vec![
                        Member {
                            endpoint: author,
                            role: MemberRole::StateAuthority,
                        },
                        Member {
                            endpoint: recipient,
                            role: MemberRole::Member,
                        },
                    ],
                    transition_digest: [6; 32],
                },
            )
            .unwrap(),
        )
        .unwrap();

    let roles = [
        Role::Membership,
        Role::Compatibility,
        Role::Revocation,
        Role::Distribution,
        Role::Consistency,
        Role::Recovery,
        Role::Abuse,
    ];
    let governance = GovernanceCandidate {
        network_ref: [1; 32],
        bundle_epoch: 1,
        bundle_digest: [7; 32],
        role_versions: roles.into_iter().map(|role| (role, 1)).collect(),
        expires_at: 52,
        authorizations: roles
            .into_iter()
            .flat_map(|role| {
                (0..4).map(move |index| Authorization {
                    root: [1 + index / 2; 16],
                    key: [1 + index; 16],
                    role,
                })
            })
            .collect(),
        active_roots_only: true,
        canonical_digest_valid: true,
        distribution_consistent: true,
        signature_scope_valid: true,
        recovery_event: RecoveryEvent::None,
        recovery_predecessor: None,
        observations: vec![
            ConsistencyObservation {
                observer_ref: [8; 32],
                observed_version: 1,
                observed_digest: [7; 32],
                statement_digest: [9; 32],
            },
            ConsistencyObservation {
                observer_ref: [10; 32],
                observed_version: 1,
                observed_digest: [7; 32],
                statement_digest: [11; 32],
            },
        ],
        split_view: false,
        endpoint_admission_local: true,
        abuse_advisory_only: true,
    };
    let message = Message {
        id: [12; 16],
        kind: MessageKind::Request,
        relates_to: None,
        content_type: 42,
        payload: b"opaque-capability-payload".to_vec(),
        extensions: BTreeMap::new(),
        critical: Vec::new(),
        chunk_index: None,
        chunk_final: None,
        attachment_id: None,
        attachments: Vec::new(),
    };
    let claim = CborValue::Map(BTreeMap::from([(0, CborValue::Unsigned(1))]));
    let body = encoding::encode(&claim).unwrap();
    let path = format!("/v1/handles/{}/claim", "A".repeat(43));
    let transport = TransportRequest {
        scheme: "https",
        tls_version: "1.3",
        tls_cipher_suite: "TLS_CHACHA20_POLY1305_SHA256",
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
        header_bytes: 128,
        operation_id: Some([13; 16]),
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
    let confirmation = EndpointConfirmation {
        confirmation_id: [14; 16],
        confirmed_message_ids: vec![message.id],
        stage: ConfirmationStage::EndpointAccepted,
        outcome: ConfirmationOutcome::Succeeded,
        failure_code: None,
        result_digest: None,
    };
    let confirmation_session = AuthorizedSession {
        session_id: [15; 16],
        sender_endpoint: recipient,
        expected_sender_endpoint: recipient,
        authenticated: true,
        sender_authorized: true,
    };
    let capability_clock = FixedClock(51);
    let receipt = initiator
        .apply_complete_capability_flow(
            CompleteCapabilityFlow {
                governance: &governance,
                identity: ChainTip {
                    endpoint: initiator_identity.state_digest,
                    epoch: 1,
                    digest: [18; 32],
                },
                identity_predecessor: None,
                message: &message,
                reliable_route_digest: [19; 32],
                group_author: author,
                group_operation: GroupOperation::ChangeRole {
                    endpoint: recipient,
                    role: MemberRole::StateAuthority,
                },
                group_message_id: [20; 16],
                group_payload: b"opaque-group-payload",
                confirmation: &confirmation,
                confirmation_session: &confirmation_session,
                current_finality: FinalityState::Pending,
                expected_result_digest: None,
                attachment_complete: true,
                transport_request: &transport,
                transport_status: 202,
            },
            &capability_clock,
        )
        .unwrap();
    assert!(!receipt.protected_packet.is_empty());
    assert_eq!(receipt.projections.len(), 1);
    assert_eq!(receipt.transport_outcome, TransportOutcome::Accepted);
    assert_eq!(
        initiator
            .apply_complete_capability_flow(
                CompleteCapabilityFlow {
                    governance: &governance,
                    identity: ChainTip {
                        endpoint: initiator_identity.state_digest,
                        epoch: 1,
                        digest: [18; 32],
                    },
                    identity_predecessor: None,
                    message: &message,
                    reliable_route_digest: [19; 32],
                    group_author: author,
                    group_operation: GroupOperation::ChangeRole {
                        endpoint: recipient,
                        role: MemberRole::StateAuthority,
                    },
                    group_message_id: [20; 16],
                    group_payload: b"opaque-group-payload",
                    confirmation: &confirmation,
                    confirmation_session: &confirmation_session,
                    current_finality: FinalityState::Pending,
                    expected_result_digest: None,
                    attachment_complete: true,
                    transport_request: &transport,
                    transport_status: 202,
                },
                &capability_clock
            )
            .unwrap_err()
            .code,
        ErrorCode::InvalidTransition
    );
    assert_eq!(initiator.into_store().load().unwrap().revision().value(), 4);
}
