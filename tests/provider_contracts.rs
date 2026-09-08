use licoarc::provider::{
    AeadProvider, AgreementProvider, DigestProvider, KdfProvider, ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES, ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_PUBLIC_KEY_BYTES,
    RustCryptoProvider, SignatureProvider,
};

fn hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), N * 2);
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).expect("valid hex");
    }
    output
}

fn hex_vec(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

#[test]
fn sha_hkdf_and_hmac_match_primary_vectors() {
    let provider = RustCryptoProvider;
    assert_eq!(
        provider.sha256(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );

    let mut okm = [0_u8; 42];
    provider
        .hkdf_sha256(
            &hex::<13>("000102030405060708090a0b0c"),
            &[0x0b; 22],
            &hex::<10>("f0f1f2f3f4f5f6f7f8f9"),
            &mut okm,
        )
        .expect("RFC 5869 case 1 must expand");
    assert_eq!(
        okm,
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );

    let hmac = hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(
        provider
            .hmac_sha256(&[0x0b; 20], b"Hi There")
            .expect("RFC 4231 case 1 must authenticate"),
        hmac
    );
    provider
        .hmac_sha256_verify(&[0x0b; 20], b"Hi There", &hmac)
        .expect("fixed-size MAC verification must accept the RFC vector");
    let mut mutated = hmac;
    mutated[0] ^= 1;
    assert!(
        provider
            .hmac_sha256_verify(&[0x0b; 20], b"Hi There", &mutated)
            .is_err()
    );
}

#[test]
fn chacha20_poly1305_matches_rfc_8439_and_rejects_mutation() {
    let provider = RustCryptoProvider;
    let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex("070000004041424344454647");
    let aad = hex_vec("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = hex_vec(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b6116",
        "1ae10b594f09e26a7e902ecbd0600691"
    ));

    let sealed = provider
        .seal(&key, &nonce, &aad, plaintext)
        .expect("RFC 8439 input must seal");
    assert_eq!(sealed, expected);
    assert_eq!(
        provider
            .open(&key, &nonce, &aad, &sealed)
            .expect("RFC 8439 output must open"),
        plaintext
    );
    let mut mutated = sealed;
    mutated[0] ^= 1;
    assert!(provider.open(&key, &nonce, &aad, &mutated).is_err());
}

#[test]
fn x25519_matches_rfc_7748_and_rejects_all_zero() {
    let provider = RustCryptoProvider;
    let alice_private = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    assert_eq!(provider.x25519_public(&alice_private), alice_public);
    assert_eq!(
        provider
            .x25519(&alice_private, &bob_public)
            .expect("RFC 7748 input must agree"),
        shared
    );
    assert!(provider.x25519(&alice_private, &[0; 32]).is_err());
}

#[test]
fn ed25519_matches_rfc_8032_and_is_strict_about_weak_keys() {
    let provider = RustCryptoProvider;
    let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));

    assert_eq!(provider.ed25519_public(&seed), public);
    assert_eq!(provider.ed25519_sign(&seed, b""), signature);
    provider
        .ed25519_verify_strict(&public, b"", &signature)
        .expect("RFC 8032 case 1 must verify");

    let mut weak_public = [0_u8; 32];
    weak_public[0] = 1;
    let mut weak_signature = [0_u8; 64];
    weak_signature[0] = 1;
    assert!(
        provider
            .ed25519_verify_strict(&weak_public, b"", &weak_signature)
            .is_err()
    );
}

#[test]
fn ml_kem_768_round_trips_and_implicitly_rejects_mutated_ciphertext() {
    let provider = RustCryptoProvider;
    let seed = [0x42; 64];
    let entropy = [0x24; 32];
    let public = provider.ml_kem_768_public(&seed);
    assert_eq!(public.len(), ML_KEM_768_PUBLIC_KEY_BYTES);
    let (ciphertext, shared) = provider
        .ml_kem_768_encapsulate(&public, &entropy)
        .expect("fixed ML-KEM-768 input must encapsulate");
    assert_eq!(ciphertext.len(), ML_KEM_768_CIPHERTEXT_BYTES);
    assert_eq!(
        provider
            .ml_kem_768_decapsulate(&seed, &ciphertext)
            .expect("valid ciphertext must decapsulate"),
        shared
    );

    let mut mutated = ciphertext;
    mutated[0] ^= 1;
    let rejected_secret = provider
        .ml_kem_768_decapsulate(&seed, &mutated)
        .expect("correctly sized invalid ciphertext uses implicit rejection");
    assert_ne!(rejected_secret, shared);
    assert!(
        provider
            .ml_kem_768_decapsulate(&seed, &mutated[..mutated.len() - 1])
            .is_err()
    );
}

#[test]
fn ml_dsa_65_round_trips_and_rejects_repeated_hint_indices() {
    const OMEGA: usize = 55;
    const K: usize = 6;

    let provider = RustCryptoProvider;
    let seed = [0x5a; 32];
    let message = b"synthetic ML-DSA-65 provider contract";
    let public = provider.ml_dsa_65_public(&seed);
    let mut signature = provider.ml_dsa_65_sign(&seed, message);
    assert_eq!(public.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
    assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_BYTES);
    provider
        .ml_dsa_65_verify(&public, message, &signature)
        .expect("fixed ML-DSA-65 input must verify");

    let hint_offset = signature.len() - (OMEGA + K);
    let cuts = signature[hint_offset + OMEGA..].to_vec();
    let mut start = 0_usize;
    let duplicate_at = cuts
        .into_iter()
        .map(usize::from)
        .find_map(|end| {
            let result = (end >= start + 2).then_some(hint_offset + start + 1);
            start = end;
            result
        })
        .expect("deterministic signature must contain a repeatable hint segment");
    signature[duplicate_at] = signature[duplicate_at - 1];
    assert!(
        provider
            .ml_dsa_65_verify(&public, message, &signature)
            .is_err()
    );
}

#[test]
fn direct_provider_pins_and_features_match_the_locked_graph() {
    let manifest = include_str!("../Cargo.toml");
    let lock = include_str!("../Cargo.lock");
    let expected = [
        ("sha2", "0.11.0", "default-features = false"),
        ("hkdf", "0.13.0", "default-features = false"),
        ("hmac", "0.13.0", "default-features = false"),
        (
            "chacha20poly1305",
            "0.11.0",
            "default-features = false, features = [\"zeroize\"]",
        ),
        (
            "x25519-dalek",
            "3.0.0",
            "default-features = false, features = [\"static_secrets\", \"zeroize\"]",
        ),
        (
            "ed25519-dalek",
            "3.0.0",
            "default-features = false, features = [\"signature\", \"zeroize\"]",
        ),
        (
            "ml-kem",
            "0.3.2",
            "default-features = false, features = [\"alloc\", \"zeroize\"]",
        ),
        (
            "ml-dsa",
            "0.1.1",
            "default-features = false, features = [\"alloc\", \"zeroize\"]",
        ),
    ];

    for (name, version, settings) in expected {
        let manifest_line = format!("{name} = {{ version = \"={version}\", {settings} }}");
        assert!(manifest.lines().any(|line| line == manifest_line));
        let lock_entry = format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"");
        assert_eq!(lock.matches(&lock_entry).count(), 1);
    }
    assert!(manifest.contains("unsafe_code = \"forbid\""));
}
