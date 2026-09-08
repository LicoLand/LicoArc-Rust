use licoarc::{
    Error, ErrorCode, Stage,
    state::{
        ApplicationEffects, AtomicState, Commit, CustodyRef, Ed25519Signing, KeyCustody,
        KeyMutation, MlDsa65Signing, MlKem768Private, MlKemEncapsulationEntropy, PacketCarrier,
        PendingId, PendingItem, PlaintextReceiver, Revision, SecretHandle, StagedSecretHandle,
        Versioned, X25519Private, drive_pending, release_plaintext, validate_restart,
    },
};

const MAX_MUTATIONS: usize = 2;
const MAX_PENDING: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    counter: u8,
    prekeys: u8,
    skipped: Vec<u8>,
    replay: Vec<u8>,
    inbox: Vec<u8>,
    deleted: bool,
}

impl Snapshot {
    fn initial() -> Self {
        Self {
            counter: 0,
            prekeys: 2,
            skipped: vec![3],
            replay: vec![5],
            inbox: Vec::new(),
            deleted: false,
        }
    }

    fn changed() -> Self {
        Self {
            counter: 1,
            prekeys: 1,
            skipped: vec![7, 8],
            replay: vec![5, 9],
            inbox: vec![11],
            deleted: false,
        }
    }
}

#[derive(Clone)]
struct FaultStore {
    value: Versioned<Snapshot>,
    adopted_keys: usize,
    deleted_keys: usize,
    cas_calls: usize,
    fail_cas: bool,
    fail_settle: bool,
}

impl FaultStore {
    fn new() -> Self {
        Self {
            value: Versioned::initial(Snapshot::initial()),
            adopted_keys: 0,
            deleted_keys: 0,
            cas_calls: 0,
            fail_cas: false,
            fail_settle: false,
        }
    }

    fn item(&self, id: PendingId) -> PendingItem {
        self.value
            .pending()
            .iter()
            .find(|item| item.id() == id)
            .expect("committed pending item")
            .clone()
    }
}

impl AtomicState<Snapshot> for FaultStore {
    fn load(&self) -> Result<Versioned<Snapshot>, Error> {
        Ok(self.value.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected: Revision,
        commit: Commit<Snapshot>,
    ) -> Result<Revision, Error> {
        self.cas_calls += 1;
        if self.fail_cas {
            return Err(Error::terminal(ErrorCode::ProviderFailure, Stage::Commit));
        }
        if expected != self.value.revision() {
            return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
        }

        let adopted_keys = self.adopted_keys
            + commit
                .key_mutations()
                .iter()
                .filter(|mutation| {
                    matches!(
                        mutation,
                        KeyMutation::AdoptX25519(_) | KeyMutation::AdoptMlKem768(_)
                    )
                })
                .count();
        let deleted_keys = self.deleted_keys
            + commit
                .key_mutations()
                .iter()
                .filter(|mutation| {
                    matches!(
                        mutation,
                        KeyMutation::DeleteX25519(_)
                            | KeyMutation::DeleteMlKem768(_)
                            | KeyMutation::DeleteMlKemEncapsulationEntropy(_)
                    )
                })
                .count();
        let value = commit.into_versioned(expected)?;
        self.value = value;
        self.adopted_keys = adopted_keys;
        self.deleted_keys = deleted_keys;
        Ok(self.value.revision())
    }

    fn settle(&mut self, revision: Revision, pending: PendingId) -> Result<Revision, Error> {
        if self.fail_settle {
            return Err(Error::terminal(ErrorCode::ProviderFailure, Stage::Commit));
        }
        if revision != self.value.revision() {
            return Err(Error::terminal(ErrorCode::Conflict, Stage::Commit));
        }
        let Some(index) = self
            .value
            .pending()
            .iter()
            .position(|item| item.id() == pending)
        else {
            return Err(Error::terminal(ErrorCode::InvalidTransition, Stage::Commit));
        };
        let mut remaining = self.value.pending().to_vec();
        remaining.remove(index);
        let settlement = Commit::bounded(
            self.value.state().clone(),
            Vec::new(),
            remaining.clone(),
            MAX_MUTATIONS,
            MAX_PENDING,
        )?;
        self.value = settlement.into_versioned(revision)?;
        Ok(self.value.revision())
    }
}

#[derive(Default)]
struct FaultCustody {
    fail_operations: bool,
    x25519_aborts: Vec<u128>,
    ml_kem_aborts: Vec<u128>,
}

impl KeyCustody for FaultCustody {
    fn ed25519_public(&self, handle: &SecretHandle<Ed25519Signing>) -> Result<[u8; 32], Error> {
        self.result([handle.custody_token() as u8; 32])
    }

    fn ed25519_sign(
        &self,
        handle: &SecretHandle<Ed25519Signing>,
        _: &[u8],
    ) -> Result<[u8; 64], Error> {
        self.result([handle.custody_token() as u8; 64])
    }

    fn ml_dsa_65_public(&self, handle: &SecretHandle<MlDsa65Signing>) -> Result<Vec<u8>, Error> {
        self.result(vec![handle.custody_token() as u8])
    }

    fn ml_dsa_65_sign(
        &self,
        handle: &SecretHandle<MlDsa65Signing>,
        _: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.result(vec![handle.custody_token() as u8; 2])
    }

    fn x25519_public(&self, handle: CustodyRef<'_, X25519Private>) -> Result<[u8; 32], Error> {
        self.result([handle.custody_token() as u8; 32])
    }

    fn x25519(
        &self,
        handle: CustodyRef<'_, X25519Private>,
        _: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        self.result([handle.custody_token() as u8; 32])
    }

    fn ml_kem_768_public(&self, handle: CustodyRef<'_, MlKem768Private>) -> Result<Vec<u8>, Error> {
        self.result(vec![handle.custody_token() as u8])
    }

    fn ml_kem_768_encapsulate(
        &self,
        _: &[u8],
        entropy: &SecretHandle<MlKemEncapsulationEntropy>,
    ) -> Result<(Vec<u8>, [u8; 32]), Error> {
        let marker = entropy.custody_token() as u8;
        self.result((vec![marker], [marker; 32]))
    }

    fn ml_kem_768_decapsulate(
        &self,
        handle: &SecretHandle<MlKem768Private>,
        _: &[u8],
    ) -> Result<[u8; 32], Error> {
        self.result([handle.custody_token() as u8; 32])
    }

    fn abort_x25519(&mut self, staged: &StagedSecretHandle<X25519Private>) {
        self.x25519_aborts.push(staged.custody_token());
    }

    fn abort_ml_kem_768(&mut self, staged: &StagedSecretHandle<MlKem768Private>) {
        self.ml_kem_aborts.push(staged.custody_token());
    }
}

impl FaultCustody {
    fn result<T>(&self, value: T) -> Result<T, Error> {
        if self.fail_operations {
            return Err(Error::terminal(ErrorCode::ProviderFailure, Stage::Provider));
        }
        Ok(value)
    }
}

#[derive(Default)]
struct Boundary {
    calls: usize,
    fail: bool,
    observed: Vec<Vec<u8>>,
}

impl Boundary {
    fn call(&mut self, value: &[u8]) -> Result<(), Error> {
        self.calls += 1;
        self.observed.push(value.to_vec());
        if self.fail {
            return Err(Error::retryable(ErrorCode::ProviderFailure, Stage::Commit));
        }
        Ok(())
    }
}

impl PacketCarrier for Boundary {
    fn send(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.call(packet)
    }
}

impl ApplicationEffects for Boundary {
    fn apply(&mut self, effect: &[u8]) -> Result<(), Error> {
        self.call(effect)
    }
}

impl PlaintextReceiver for Boundary {
    fn release(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        self.call(plaintext)
    }
}

fn commit(
    next: Snapshot,
    mutations: Vec<KeyMutation>,
    pending: Vec<PendingItem>,
) -> Commit<Snapshot> {
    Commit::bounded(next, mutations, pending, MAX_MUTATIONS, MAX_PENDING).expect("bounded commit")
}

#[test]
fn purpose_specific_custody_operations_and_staged_lifecycle_are_closed() {
    let mut custody = FaultCustody::default();
    let ed25519 = SecretHandle::<Ed25519Signing>::from_custody_token(11);
    let ml_dsa = SecretHandle::<MlDsa65Signing>::from_custody_token(12);
    let x25519 = SecretHandle::<X25519Private>::from_custody_token(13);
    let staged_x25519 = StagedSecretHandle::<X25519Private>::from_custody_token(14);
    let ml_kem = SecretHandle::<MlKem768Private>::from_custody_token(15);
    let staged_ml_kem = StagedSecretHandle::<MlKem768Private>::from_custody_token(16);
    let entropy = SecretHandle::<MlKemEncapsulationEntropy>::from_custody_token(17);

    assert_eq!(custody.ed25519_public(&ed25519).unwrap(), [11; 32]);
    assert_eq!(
        custody.ed25519_sign(&ed25519, b"message").unwrap(),
        [11; 64]
    );
    assert_eq!(custody.ml_dsa_65_public(&ml_dsa).unwrap(), vec![12]);
    assert_eq!(
        custody.ml_dsa_65_sign(&ml_dsa, b"message").unwrap(),
        vec![12; 2]
    );
    assert_eq!(
        custody.x25519_public(CustodyRef::Adopted(&x25519)).unwrap(),
        [13; 32]
    );
    assert_eq!(
        custody
            .x25519(CustodyRef::Staged(&staged_x25519), &[0; 32])
            .unwrap(),
        [14; 32]
    );
    assert_eq!(
        custody
            .ml_kem_768_public(CustodyRef::Adopted(&ml_kem))
            .unwrap(),
        vec![15]
    );
    assert_eq!(
        custody
            .ml_kem_768_public(CustodyRef::Staged(&staged_ml_kem))
            .unwrap(),
        vec![16]
    );
    assert_eq!(
        custody.ml_kem_768_encapsulate(&[1], &entropy).unwrap(),
        (vec![17], [17; 32])
    );
    assert_eq!(
        custody.ml_kem_768_decapsulate(&ml_kem, &[2]).unwrap(),
        [15; 32]
    );

    assert_eq!(staged_x25519.adopted_handle().custody_token(), 14);
    assert_eq!(staged_ml_kem.adopted_handle().custody_token(), 16);
    custody.abort_x25519(&staged_x25519);
    custody.abort_ml_kem_768(&staged_ml_kem);
    assert_eq!(custody.x25519_aborts, vec![14]);
    assert_eq!(custody.ml_kem_aborts, vec![16]);

    custody.fail_operations = true;
    let error = custody.ed25519_public(&ed25519).unwrap_err();
    assert_eq!(
        (error.code, error.stage),
        (ErrorCode::ProviderFailure, Stage::Provider)
    );
}

#[test]
fn preparation_and_cas_failures_are_old_or_new_without_spin() {
    let original = Snapshot::initial();
    let mut store = FaultStore::new();
    let mut custody = FaultCustody::default();

    // A fault before preparation performs no custody or CAS work.
    assert_eq!(store.cas_calls, 0);
    assert_eq!(store.value.state(), &original);

    let staged = StagedSecretHandle::<X25519Private>::from_custody_token(1);
    custody.fail_operations = true;
    assert!(custody.x25519_public(CustodyRef::Staged(&staged)).is_err());
    assert_eq!(store.cas_calls, 0);

    custody.fail_operations = false;
    store.fail_cas = true;
    assert!(
        store
            .compare_and_swap(
                Revision::initial(),
                commit(
                    Snapshot::changed(),
                    vec![KeyMutation::AdoptX25519(staged.clone())],
                    Vec::new(),
                ),
            )
            .is_err()
    );
    custody.abort_x25519(&staged);
    assert_eq!(store.cas_calls, 1);
    assert_eq!(store.value.state(), &original);
    assert_eq!(store.adopted_keys, 0);
    assert_eq!(custody.x25519_aborts, vec![1]);

    store.fail_cas = false;
    let staged = StagedSecretHandle::<MlKem768Private>::from_custody_token(2);
    assert_eq!(
        store
            .compare_and_swap(
                Revision::initial(),
                commit(
                    Snapshot::changed(),
                    vec![KeyMutation::AdoptMlKem768(staged)],
                    Vec::new(),
                ),
            )
            .unwrap()
            .value(),
        1
    );
    assert_eq!(store.value.state(), &Snapshot::changed());
    assert_eq!(store.adopted_keys, 1);

    let before_stale = store.value.clone();
    assert_eq!(
        store
            .compare_and_swap(
                Revision::initial(),
                commit(Snapshot::initial(), Vec::new(), Vec::new()),
            )
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(store.cas_calls, 3);
    assert_eq!(store.value, before_stale);
}

#[test]
fn pending_survives_crash_and_known_failure_is_redriven() {
    let packet_id = PendingId::from_token(1);
    let effect_id = PendingId::from_token(2);
    let mut store = FaultStore::new();
    let revision = store
        .compare_and_swap(
            Revision::initial(),
            commit(
                Snapshot::changed(),
                Vec::new(),
                vec![
                    PendingItem::packet(packet_id, vec![21]).unwrap(),
                    PendingItem::effect(effect_id, vec![22]).unwrap(),
                ],
            ),
        )
        .unwrap();
    let mut restarted = store.clone();
    let mut carrier = Boundary {
        calls: 0,
        fail: true,
        observed: Vec::new(),
    };
    let mut effects = Boundary::default();
    assert_eq!(restarted.value.pending().len(), 2);
    assert_eq!(
        restarted
            .value
            .pending()
            .iter()
            .map(PendingItem::id)
            .collect::<Vec<_>>(),
        vec![packet_id, effect_id]
    );

    let forged = PendingItem::packet(PendingId::from_token(99), vec![99]).unwrap();
    assert_eq!(
        drive_pending(
            &mut restarted,
            revision,
            &forged,
            &mut carrier,
            &mut effects,
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidTransition
    );
    assert_eq!(carrier.calls, 0);

    let packet = restarted.item(packet_id);
    assert!(
        drive_pending(
            &mut restarted,
            revision,
            &packet,
            &mut carrier,
            &mut effects,
        )
        .is_err()
    );
    assert_eq!(restarted.value.pending().len(), 2);
    carrier.fail = false;
    let revision = drive_pending(
        &mut restarted,
        revision,
        &packet,
        &mut carrier,
        &mut effects,
    )
    .unwrap();
    assert_eq!(carrier.calls, 2);
    assert_eq!(carrier.observed, vec![vec![21], vec![21]]);
    assert_eq!(restarted.value.pending().len(), 1);

    let carrier_calls = carrier.calls;
    assert_eq!(
        drive_pending(
            &mut restarted,
            Revision::initial(),
            &packet,
            &mut carrier,
            &mut effects,
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    assert_eq!(carrier.calls, carrier_calls);
    assert_eq!(
        drive_pending(
            &mut restarted,
            revision,
            &packet,
            &mut carrier,
            &mut effects,
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidTransition
    );
    assert_eq!(carrier.calls, carrier_calls);

    // A completed effect followed by settlement failure remains fenced and is
    // not automatically retried.
    restarted.fail_settle = true;
    let effect = restarted.item(effect_id);
    assert!(
        drive_pending(
            &mut restarted,
            revision,
            &effect,
            &mut carrier,
            &mut effects,
        )
        .is_err()
    );
    assert_eq!(effects.calls, 1);
    assert_eq!(effects.observed, vec![vec![22]]);
    assert_eq!(restarted.value.pending(), &[effect]);
}

#[test]
fn pending_roles_are_separated_and_commit_order_survives_settlement() {
    let first = PendingItem::packet(PendingId::from_token(20), vec![1]).unwrap();
    let middle = PendingItem::effect(PendingId::from_token(21), vec![2]).unwrap();
    let last = PendingItem::packet(PendingId::from_token(22), vec![3]).unwrap();
    let plaintext = PendingItem::plaintext(PendingId::from_token(23), vec![4]).unwrap();
    let mut store = FaultStore::new();
    let revision = store
        .compare_and_swap(
            Revision::initial(),
            commit(
                Snapshot::changed(),
                Vec::new(),
                vec![first.clone(), middle.clone(), last.clone()],
            ),
        )
        .unwrap();
    assert_eq!(
        store.value.pending(),
        &[first.clone(), middle.clone(), last.clone()]
    );

    let next_revision = store.settle(revision, middle.id()).unwrap();
    assert_eq!(store.value.pending(), &[first.clone(), last.clone()]);

    let mut carrier = Boundary::default();
    let mut effects = Boundary::default();
    assert_eq!(
        drive_pending(
            &mut store,
            next_revision,
            &plaintext,
            &mut carrier,
            &mut effects,
        )
        .unwrap_err()
        .code,
        ErrorCode::InvalidTransition
    );
    assert_eq!((carrier.calls, effects.calls), (0, 0));

    let mut receiver = Boundary::default();
    assert_eq!(
        release_plaintext(&mut store, next_revision, &first, &mut receiver)
            .unwrap_err()
            .code,
        ErrorCode::InvalidTransition
    );
    assert_eq!(receiver.calls, 0);
}

#[test]
fn plaintext_releases_only_after_durable_receive_and_settles() {
    let id = PendingId::from_token(3);
    let pending = PendingItem::plaintext(id, vec![31]).unwrap();
    let mut store = FaultStore::new();
    let mut receiver = Boundary {
        calls: 0,
        fail: true,
        observed: Vec::new(),
    };

    store.fail_cas = true;
    assert!(
        store
            .compare_and_swap(
                Revision::initial(),
                commit(Snapshot::changed(), Vec::new(), vec![pending.clone()],),
            )
            .is_err()
    );
    assert_eq!(receiver.calls, 0);
    assert!(store.value.pending().is_empty());

    store.fail_cas = false;
    let revision = store
        .compare_and_swap(
            Revision::initial(),
            commit(Snapshot::changed(), Vec::new(), vec![pending.clone()]),
        )
        .unwrap();
    assert_eq!(store.value.state().inbox, vec![11]);
    assert!(release_plaintext(&mut store, revision, &pending, &mut receiver).is_err());
    assert_eq!(store.value.pending(), std::slice::from_ref(&pending));
    receiver.fail = false;
    assert_eq!(
        release_plaintext(&mut store, revision, &pending, &mut receiver)
            .unwrap()
            .value(),
        2
    );
    assert!(store.value.pending().is_empty());
    assert_eq!(receiver.calls, 2);
    assert_eq!(receiver.observed, vec![vec![31], vec![31]]);
}

#[test]
fn restart_deletion_and_resource_bounds_are_closed() {
    assert!(validate_restart(Revision::initial(), Revision::initial()).is_ok());
    let one = commit(Snapshot::changed(), Vec::new(), Vec::new())
        .into_versioned(Revision::initial())
        .unwrap()
        .revision();
    assert_eq!(
        validate_restart(Revision::initial(), one).unwrap_err().code,
        ErrorCode::StateRollback
    );
    assert_eq!(
        validate_restart(one, Revision::initial()).unwrap_err().code,
        ErrorCode::InvalidTransition
    );

    let exact_mutations = vec![
        KeyMutation::DeleteX25519(SecretHandle::from_custody_token(1)),
        KeyMutation::AdoptMlKem768(StagedSecretHandle::from_custody_token(2)),
    ];
    let exact_pending = vec![
        PendingItem::packet(PendingId::from_token(10), vec![]).unwrap(),
        PendingItem::effect(PendingId::from_token(11), vec![]).unwrap(),
        PendingItem::plaintext(PendingId::from_token(12), vec![]).unwrap(),
    ];
    assert!(
        Commit::bounded(
            Snapshot::initial(),
            exact_mutations.clone(),
            exact_pending.clone(),
            MAX_MUTATIONS,
            MAX_PENDING,
        )
        .is_ok()
    );
    let mut plus_one_mutation = exact_mutations;
    plus_one_mutation.push(KeyMutation::DeleteMlKem768(
        SecretHandle::from_custody_token(3),
    ));
    assert_eq!(
        Commit::bounded(
            Snapshot::initial(),
            plus_one_mutation,
            Vec::new(),
            MAX_MUTATIONS,
            MAX_PENDING,
        )
        .unwrap_err()
        .code,
        ErrorCode::BoundExceeded
    );
    let mut plus_one_pending = exact_pending;
    plus_one_pending.push(PendingItem::packet(PendingId::from_token(13), vec![]).unwrap());
    assert_eq!(
        Commit::bounded(
            Snapshot::initial(),
            Vec::new(),
            plus_one_pending,
            MAX_MUTATIONS,
            MAX_PENDING,
        )
        .unwrap_err()
        .code,
        ErrorCode::BoundExceeded
    );
    let duplicate = PendingItem::packet(PendingId::from_token(14), vec![]).unwrap();
    assert_eq!(
        Commit::bounded(
            Snapshot::initial(),
            Vec::new(),
            vec![duplicate.clone(), duplicate],
            MAX_MUTATIONS,
            MAX_PENDING,
        )
        .unwrap_err()
        .code,
        ErrorCode::BoundExceeded
    );
    assert_eq!(
        Commit::bounded(
            Snapshot::initial(),
            vec![
                KeyMutation::DeleteX25519(SecretHandle::from_custody_token(15)),
                KeyMutation::DeleteMlKem768(SecretHandle::from_custody_token(15)),
            ],
            Vec::new(),
            MAX_MUTATIONS,
            MAX_PENDING,
        )
        .unwrap_err()
        .code,
        ErrorCode::BoundExceeded
    );

    let mut store = FaultStore::new();
    let original = store.value.clone();
    let deleted = Snapshot {
        prekeys: 0,
        skipped: Vec::new(),
        replay: Vec::new(),
        inbox: Vec::new(),
        deleted: true,
        ..Snapshot::initial()
    };
    store.fail_cas = true;
    assert!(
        store
            .compare_and_swap(
                Revision::initial(),
                commit(
                    deleted.clone(),
                    vec![KeyMutation::DeleteX25519(SecretHandle::from_custody_token(
                        99
                    ))],
                    Vec::new(),
                ),
            )
            .is_err()
    );
    assert_eq!(store.value, original);
    assert_eq!(store.deleted_keys, 0);
    store.fail_cas = false;
    store
        .compare_and_swap(
            Revision::initial(),
            commit(
                deleted.clone(),
                vec![
                    KeyMutation::DeleteX25519(SecretHandle::from_custody_token(99)),
                    KeyMutation::DeleteMlKemEncapsulationEntropy(SecretHandle::from_custody_token(
                        100,
                    )),
                ],
                Vec::new(),
            ),
        )
        .unwrap();
    assert_eq!(store.value.state(), &deleted);
    assert_eq!(store.deleted_keys, 2);
}

#[test]
fn diagnostics_redact_state_keys_and_protocol_content() {
    let canary = "protocol-content-canary";
    let pending =
        PendingItem::effect(PendingId::from_token(1), canary.as_bytes().to_vec()).unwrap();
    let commit = commit(
        Snapshot {
            inbox: canary.as_bytes().to_vec(),
            ..Snapshot::initial()
        },
        vec![KeyMutation::DeleteMlKemEncapsulationEntropy(
            SecretHandle::from_custody_token(0xfeed),
        )],
        vec![pending.clone()],
    );
    let rendered = format!("{pending:?} {commit:?}");
    assert!(!rendered.contains(canary));
    assert!(!rendered.contains("feed"));
}
