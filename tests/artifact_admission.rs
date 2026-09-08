use std::{env, fs};

use licoarc::{AuthorityBundle, ErrorCode};
use serde_json::Value;

const BUNDLE_DIGEST: &str = "b6ceacb359568cb09800317a8d4668442f55a1a66bba04f13c3e865a6cd2f8e0";
const LINE_ID: &str = "c0b64d71865ce972a944db3d31a18cb03395300f3ed006c21e64429178c23a08";
const PROFILE_ID: &str = "4b7d575f397862f9031e44b716921e86c410b5facf379bde21955922b0d58a17";

#[test]
fn exact_explicit_candidate_complete_bundle_is_admitted() {
    let bytes = authority_bytes();
    let line = AuthorityBundle::new(&bytes).admit().unwrap();

    assert_eq!(
        line.snapshot_digest().as_bytes(),
        &decode_digest(BUNDLE_DIGEST)
    );
    assert_eq!(line.wire_id(), "licoarc.protocol-line.v1");
    assert_eq!(line.generation(), 1);
    assert_eq!(line.protocol_line_id(), &decode_digest(LINE_ID));
    assert_eq!(line.protection_profile_id(), &decode_digest(PROFILE_ID));
    assert_eq!(line.capability_ids().len(), 8);
    assert_eq!(line.conformance_case_count(), 212);
    assert_eq!(line.operation_ids().len(), 29);
    assert_eq!(line.protection_bound("MAX_ACTIVE_SESSIONS"), Some(256));
    assert_eq!(
        line.protection_bound("MAX_PROTECTED_PACKET_BYTES"),
        Some(524_288)
    );
}

#[test]
fn malformed_and_non_current_bundle_metadata_fail_closed() {
    assert_eq!(
        AuthorityBundle::new(b"").admit().unwrap_err().code,
        ErrorCode::BoundExceeded
    );
    assert_eq!(
        AuthorityBundle::new(b"{}").admit().unwrap_err().code,
        ErrorCode::InvalidAuthorityInput
    );

    let mut bundle = authority_value();
    bundle["definitionStatus"] = Value::String("PARTIAL".to_owned());
    assert_rejected(bundle, ErrorCode::UnsupportedDefinition);

    let mut bundle = authority_value();
    bundle["sessionEligible"] = Value::Bool(false);
    assert_rejected(bundle, ErrorCode::UnsupportedDefinition);

    let mut bundle = authority_value();
    bundle["digest"] = Value::String("00".repeat(32));
    assert_rejected(bundle, ErrorCode::DigestMismatch);
}

#[test]
fn content_address_rejects_every_semantic_source_mutation() {
    let mutations: &[(&str, Value)] = &[
        (
            "/sources/spec~1v1~1manifest.json/protocolLineId",
            Value::String("00".repeat(32)),
        ),
        (
            "/sources/spec~1protocol-lines.json/lines/0/protocolLineId",
            Value::String("11".repeat(32)),
        ),
        (
            "/sources/spec~1protection-profiles.json/profiles/0/profileId",
            Value::String("22".repeat(32)),
        ),
        (
            "/sources/spec~1v1~1manifest.json/capabilities/0/definitionStatus",
            Value::String("PARTIAL".to_owned()),
        ),
        (
            "/sources/spec~1v1~1protection~1bounds.json/bounds/MAX_PROTECTED_PACKET_BYTES",
            Value::from(524_289_u64),
        ),
        (
            "/sources/spec~1v1~1security~1claims.json/claims/0/status",
            Value::String("unproved".to_owned()),
        ),
        (
            "/sources/conformance~1v1~1protection~1manifest.json/caseCount",
            Value::from(20_u64),
        ),
        (
            "/sources/conformance~1v1~1manifest.json/capabilityCorpora/0/manifestPath",
            Value::String("conformance/v1/security/manifest.json".to_owned()),
        ),
    ];

    for (pointer, replacement) in mutations {
        let mut bundle = authority_value();
        *bundle
            .pointer_mut(pointer)
            .expect("authority pointer exists") = replacement.clone();
        assert_rejected(bundle, ErrorCode::DigestMismatch);
    }
}

#[test]
fn path_scoped_source_bounds_reject_before_content_addressing() {
    let mut bundle = authority_value();
    bundle["sources"]["spec/v1/foundation/representation.json"]["governance"]["encoding"] =
        Value::Array(vec![Value::Null; 65]);
    assert_rejected(bundle, ErrorCode::BoundExceeded);

    let mut bundle = authority_value();
    bundle["sources"]["spec/v1/security/formal-bindings.json"]["bindings"] =
        Value::Array(vec![Value::Null; 257]);
    assert_rejected(bundle, ErrorCode::BoundExceeded);

    let mut bundle = authority_value();
    bundle["sources"]["conformance/v1/foundation/cases.json"]["cases"] =
        Value::Array(vec![Value::Null; 513]);
    assert_rejected(bundle, ErrorCode::BoundExceeded);
}

#[test]
fn duplicate_members_and_trailing_bytes_are_rejected_before_admission() {
    let duplicate = br#"{"artifactVersion":"licoarc.bundle.v1","artifactVersion":"other"}"#;
    assert_eq!(
        AuthorityBundle::new(duplicate).admit().unwrap_err().code,
        ErrorCode::InvalidAuthorityInput
    );

    let mut bytes = authority_bytes();
    bytes.extend_from_slice(b"\nfalse");
    assert_eq!(
        AuthorityBundle::new(&bytes).admit().unwrap_err().code,
        ErrorCode::InvalidAuthorityInput
    );
}

fn authority_bytes() -> Vec<u8> {
    let path = env::var_os("LICOARC_AUTHORITY_BUNDLE")
        .expect("LICOARC_AUTHORITY_BUNDLE must name the explicit read-only bundle");
    fs::read(path).expect("explicit authority bundle must be readable")
}

fn authority_value() -> Value {
    serde_json::from_slice(&authority_bytes()).expect("authority bundle is JSON")
}

fn assert_rejected(bundle: Value, expected: ErrorCode) {
    let bytes = serde_json::to_vec(&bundle).unwrap();
    assert_eq!(
        AuthorityBundle::new(&bytes).admit().unwrap_err().code,
        expected
    );
}

fn decode_digest(value: &str) -> [u8; 32] {
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}
