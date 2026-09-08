use licoarc::{
    Error, ErrorCode, Stage,
    encoding::CborValue,
    group::{GroupState, Member, MemberRole},
    messaging::{Message, MessageKind},
    provider::RustCryptoProvider,
    state::{
        ApplicationEffects, AtomicState, Commit, PacketCarrier, PendingId, PendingItem, Revision,
        Versioned, drive_pending,
    },
    transport::TransportRequest,
};

#[test]
fn error_diagnostics_are_structurally_bounded() {
    let error = Error::terminal(ErrorCode::AuthenticationFailed, Stage::Provider);
    assert_eq!(
        format!("{error:?} {error}"),
        "Error { code: AuthenticationFailed, stage: Provider, retryable: false } AuthenticationFailed at Provider"
    );
}

struct Unused;
impl AtomicState<()> for Unused {
    fn load(&self) -> Result<Versioned<()>, Error> {
        Ok(Versioned::initial(()))
    }
    fn compare_and_swap(&mut self, _: Revision, _: Commit<()>) -> Result<Revision, Error> {
        unreachable!()
    }
    fn settle(&mut self, _: Revision, _: PendingId) -> Result<Revision, Error> {
        unreachable!()
    }
}
impl PacketCarrier for Unused {
    fn send(&mut self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}
impl ApplicationEffects for Unused {
    fn apply(&mut self, _: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

#[test]
fn public_contract_symbols_are_usable_without_hidden_io() {
    let _ = core::mem::size_of::<PendingItem>();
    let _ = drive_pending::<(), Unused, Unused, Unused>;
}

#[test]
fn content_bearing_debug_surfaces_are_redacted() {
    let canary = b"public-debug-content-canary";
    let cbor = CborValue::Bytes(canary.to_vec());
    let message = Message {
        id: [2; 16],
        kind: MessageKind::Event,
        relates_to: None,
        content_type: 42,
        payload: canary.to_vec(),
        extensions: Default::default(),
        critical: Vec::new(),
        chunk_index: None,
        chunk_final: None,
        attachment_id: None,
        attachments: Vec::new(),
    };
    let request = TransportRequest {
        scheme: "https",
        tls_version: "1.3",
        tls_cipher_suite: "TLS_CHACHA20_POLY1305_SHA256",
        certificate_chain_valid: true,
        http_version: "2",
        renegotiation: false,
        method: "POST",
        path: std::str::from_utf8(canary).unwrap(),
        query_present: false,
        fragment_present: false,
        early_data: false,
        name_validated: true,
        authority_present: true,
        header_names_lowercase: true,
        header_bytes: 0,
        operation_id: Some([3; 16]),
        operation_id_canonical: true,
        media_type: "application/licoarc-transport+cbor",
        media_type_parameters: false,
        content_length: Some(canary.len()),
        content_length_canonical: true,
        transfer_encoding: false,
        content_encoding_identity: true,
        trailers: false,
        streaming: false,
        body: canary,
    };
    let group = GroupState {
        group_id: [4; 32],
        epoch: 0,
        previous_digest: None,
        members: vec![
            Member {
                endpoint: [5; 32],
                role: MemberRole::StateAuthority,
            },
            Member {
                endpoint: [6; 32],
                role: MemberRole::Member,
            },
        ],
        transition_digest: [7; 32],
    };
    let projection = group
        .projections(&RustCryptoProvider, [8; 16], &[5; 32], canary)
        .unwrap()
        .remove(0);

    let rendered = format!("{cbor:?} {message:?} {request:?} {projection:?}");
    assert!(!rendered.contains(std::str::from_utf8(canary).unwrap()));
}
