//! Writes one structurally valid wire encoding per fuzz target into
//! `fuzz/corpus/<target>/` so coverage-guided runs start inside the
//! grammars instead of rediscovering the CBOR map shapes.
use licoarc::encoding::CborValue;
use licoarc::endpoint::{FirstPacket, PrekeyBundle, SessionAccept};
use licoarc::protection::RatchetHeader;
use licoarc::transport::{ClientFrame, FailureClass, StationFrame, TransportOutcome};
use std::collections::BTreeMap;
use std::path::Path;

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new("corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
}

fn main() {
    let mut deep = BTreeMap::new();
    deep.insert(
        0,
        CborValue::Array(vec![
            CborValue::Bytes(vec![7; 32]),
            CborValue::Map(BTreeMap::from([(
                1,
                CborValue::Array(vec![CborValue::Unsigned(42), CborValue::Bool(true)]),
            )])),
            CborValue::Null,
        ]),
    );
    write(
        "cbor_decode",
        "nested",
        &licoarc::encoding::encode(&CborValue::Map(deep)).unwrap(),
    );

    let hello = ClientFrame::Hello {
        device_key: [1; 32],
        signature: [2; 64],
    }
    .encode()
    .unwrap();
    let send = ClientFrame::Send {
        request_id: 9,
        handle: [3; 32],
        packet: vec![4; 64],
    }
    .encode()
    .unwrap();
    let ack = ClientFrame::Ack {
        delivery_sequence: 5,
    }
    .encode()
    .unwrap();
    let challenge = StationFrame::Challenge { nonce: [8; 32] }.encode().unwrap();
    let ready = StationFrame::Ready {
        mailbox_id: [9; 16],
    }
    .encode()
    .unwrap();
    let result = StationFrame::Result {
        request_id: 9,
        outcome: TransportOutcome::Rejected,
        failure_class: Some(FailureClass::MailboxFull),
        retry_after_ms: Some(1500),
    }
    .encode()
    .unwrap();
    let deliver = StationFrame::Deliver {
        delivery_sequence: 5,
        handle: [3; 32],
        packet: vec![4; 64],
    }
    .encode()
    .unwrap();
    let drained = StationFrame::Drained.encode().unwrap();
    for (index, frame) in [hello, send, ack, challenge, ready, result, deliver, drained]
        .iter()
        .enumerate()
    {
        write("mailbox_frames", &format!("frame{index}"), frame);
    }

    let prekey = PrekeyBundle {
        protocol_line_id: [0x11; 32],
        protection_profile_id: [0x22; 32],
        responder_identity_state_digest: [0x33; 32],
        ed25519_key_id: [0x44; 32],
        ml_dsa_65_key_id: [0x55; 32],
        pair_sequence: 3,
        x25519_public: [0x66; 32],
        ml_kem_768_public: vec![0x77; 1184],
        valid_from: 1_000,
        valid_until: 2_000,
        ed25519_signature: [0x88; 64],
        ml_dsa_65_signature: vec![0x99; 3309],
    };
    let packet = FirstPacket {
        protocol_line_id: [0x11; 32],
        protection_profile_id: [0x22; 32],
        initiator_identity_state_digest: [0xaa; 32],
        initiator_user_authority_state_digest: [0xbb; 32],
        responder_identity_state_digest: [0x33; 32],
        responder_user_authority_state_digest: [0xcc; 32],
        prekey,
        initiator_x25519_public: [0xdd; 32],
        ml_kem_768_ciphertext: vec![0xee; 1088],
        initiator_ed25519_key_id: [0xff; 32],
        initiator_ml_dsa_65_key_id: [0x12; 32],
        initiator_ed25519_signature: [0x34; 64],
        initiator_ml_dsa_65_signature: vec![0x56; 3309],
        client_confirm_ciphertext: [0x78; 36],
        client_confirm_tag: [0x9a; 16],
    };
    write(
        "first_packet",
        "valid",
        &licoarc::endpoint::encode_first_packet(&packet).unwrap(),
    );

    let accept = SessionAccept {
        transcript_digest: [1; 32],
        session_context_digest: [2; 32],
        initiator_user_authority_state_digest: [3; 32],
        responder_identity_state_digest: [4; 32],
        responder_user_authority_state_digest: [5; 32],
        pair_sequence: 7,
        mac: [6; 32],
    };
    write(
        "session_accept",
        "valid",
        &licoarc::endpoint::encode_session_accept(&accept).unwrap(),
    );

    let header = RatchetHeader {
        dh: [0x42; 32],
        pn: 3,
        n: 9,
    }
    .encode()
    .unwrap();
    write("record_header", "header", &header);
    let mut framed = header.clone();
    framed.extend_from_slice(&[0xab; 64]);
    write("record_header", "record", &framed);
}
