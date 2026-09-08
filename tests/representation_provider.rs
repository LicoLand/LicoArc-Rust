use std::collections::BTreeMap;

use licoarc::{
    ErrorCode,
    encoding::{CborValue, decode, encode},
    provider::{DigestProvider, RustCryptoProvider},
};

#[test]
fn deterministic_cbor_rejects_noncanonical_and_unknown_forms() {
    let value = CborValue::Map(BTreeMap::from([
        (0, CborValue::Bytes(vec![1, 2, 3])),
        (1, CborValue::Unsigned(24)),
    ]));
    let bytes = encode(&value).unwrap();
    assert_eq!(decode(&bytes).unwrap(), value);
    assert_eq!(encode(&CborValue::Null).unwrap(), [0xf6]);
    assert_eq!(decode(&[0xf6]).unwrap(), CborValue::Null);
    assert_eq!(
        decode(&[0x18, 0x00]).unwrap_err().code,
        ErrorCode::NonCanonicalRepresentation
    );
    assert_eq!(
        decode(&[0xbf, 0xff]).unwrap_err().code,
        ErrorCode::InvalidRepresentation
    );
}

#[test]
fn deterministic_cbor_enforces_current_resource_profile_on_encode() {
    assert_eq!(
        encode(&CborValue::Bytes(vec![0; 262_145]))
            .unwrap_err()
            .code,
        ErrorCode::BoundExceeded
    );
    assert_eq!(
        encode(&CborValue::Array(vec![CborValue::Bool(false); 65]))
            .unwrap_err()
            .code,
        ErrorCode::BoundExceeded
    );
    assert_eq!(
        encode(&CborValue::Unsigned(9_007_199_254_740_992))
            .unwrap_err()
            .code,
        ErrorCode::BoundExceeded
    );
    let mut nested = CborValue::Bool(false);
    for _ in 0..17 {
        nested = CborValue::Array(vec![nested]);
    }
    assert_eq!(encode(&nested).unwrap_err().code, ErrorCode::BoundExceeded);
}

#[test]
fn decided_digest_provider_matches_primary_vector() {
    let actual = RustCryptoProvider.sha256(b"abc");
    assert_eq!(
        actual,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
}
