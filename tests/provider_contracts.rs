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

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).expect("synthetic secret entropy");
    bytes
}

#[test]
fn sha256_matches_its_public_vector_and_kdf_mac_verify_runtime_keys() {
    let provider = RustCryptoProvider;
    // Public known-answer digest; the input carries no key material.
    assert_eq!(
        provider.sha256(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );

    let salt = random::<32>();
    let ikm = random::<32>();
    let info = b"licoarc-provider-contract";
    let mut okm = [0_u8; 42];
    provider
        .hkdf_sha256(&salt, &ikm, info, &mut okm)
        .expect("runtime input must expand");
    let mut repeated = [0_u8; 42];
    provider
        .hkdf_sha256(&salt, &ikm, info, &mut repeated)
        .expect("runtime input must expand");
    assert_eq!(okm, repeated, "HKDF must be deterministic");
    let mut other = [0_u8; 42];
    provider
        .hkdf_sha256(&salt, &random::<32>(), info, &mut other)
        .expect("runtime input must expand");
    assert_ne!(okm, other, "distinct IKM must derive distinct output");

    let mac_key = random::<32>();
    let message = b"licoarc-provider-contract";
    let mac = provider
        .hmac_sha256(&mac_key, message)
        .expect("runtime key must authenticate");
    assert_eq!(
        provider
            .hmac_sha256(&mac_key, message)
            .expect("runtime key must authenticate"),
        mac,
        "HMAC must be deterministic"
    );
    provider
        .hmac_sha256_verify(&mac_key, message, &mac)
        .expect("own MAC must verify");
    let mut mutated = mac;
    mutated[0] ^= 1;
    assert!(
        provider
            .hmac_sha256_verify(&mac_key, message, &mutated)
            .is_err()
    );
    assert!(
        provider
            .hmac_sha256_verify(&random::<32>(), message, &mac)
            .is_err()
    );
}

#[test]
fn chacha20_poly1305_round_trips_and_rejects_tampered_input() {
    let provider = RustCryptoProvider;
    let key = random::<32>();
    let nonce = random::<12>();
    let aad = random::<16>();
    let plaintext = b"synthetic AEAD provider contract";

    let sealed = provider
        .seal(&key, &nonce, &aad, plaintext)
        .expect("runtime input must seal");
    assert_eq!(sealed.len(), plaintext.len() + 16, "seal appends the tag");
    assert_eq!(
        provider
            .seal(&key, &nonce, &aad, plaintext)
            .expect("runtime input must seal"),
        sealed,
        "sealing is deterministic for the same key and nonce"
    );
    assert_eq!(
        provider
            .open(&key, &nonce, &aad, &sealed)
            .expect("own ciphertext must open"),
        plaintext
    );

    let mut mutated_body = sealed.clone();
    mutated_body[0] ^= 1;
    assert!(provider.open(&key, &nonce, &aad, &mutated_body).is_err());
    let mut mutated_tag = sealed.clone();
    *mutated_tag.last_mut().unwrap() ^= 1;
    assert!(provider.open(&key, &nonce, &aad, &mutated_tag).is_err());
    assert!(
        provider
            .open(&random::<32>(), &nonce, &aad, &sealed)
            .is_err()
    );
    assert!(provider.open(&key, &random::<12>(), &aad, &sealed).is_err());
    assert!(
        provider
            .open(&key, &nonce, &random::<16>(), &sealed)
            .is_err()
    );
}

#[test]
fn x25519_agrees_for_runtime_keys_and_rejects_all_zero_public() {
    let provider = RustCryptoProvider;
    let alice_private = random::<32>();
    let bob_private = random::<32>();
    let alice_public = provider.x25519_public(&alice_private);
    let bob_public = provider.x25519_public(&bob_private);
    assert_eq!(
        provider.x25519_public(&alice_private),
        alice_public,
        "public derivation must be deterministic"
    );
    assert_ne!(
        alice_public, bob_public,
        "distinct secrets yield distinct public keys"
    );
    assert_eq!(
        provider
            .x25519(&alice_private, &bob_public)
            .expect("runtime keys must agree"),
        provider
            .x25519(&bob_private, &alice_public)
            .expect("runtime keys must agree"),
        "both parties must derive the same shared secret"
    );
    assert!(provider.x25519(&alice_private, &[0; 32]).is_err());
}

#[test]
fn ed25519_signs_deterministically_and_rejects_wrong_key_or_mutation() {
    let provider = RustCryptoProvider;
    let seed = random::<32>();
    let public = provider.ed25519_public(&seed);
    assert_eq!(
        provider.ed25519_public(&seed),
        public,
        "public derivation must be deterministic"
    );
    let message = b"synthetic signature provider contract";
    let signature = provider.ed25519_sign(&seed, message);
    assert_eq!(
        provider.ed25519_sign(&seed, message),
        signature,
        "Ed25519 signatures must be deterministic"
    );
    provider
        .ed25519_verify_strict(&public, message, &signature)
        .expect("own signature must verify");

    let other_public = provider.ed25519_public(&random::<32>());
    assert_ne!(public, other_public, "distinct seeds yield distinct keys");
    assert!(
        provider
            .ed25519_verify_strict(&other_public, message, &signature)
            .is_err()
    );
    assert!(
        provider
            .ed25519_verify_strict(&public, b"different message", &signature)
            .is_err()
    );
    let mut bad_signature = signature;
    bad_signature[0] ^= 1;
    assert!(
        provider
            .ed25519_verify_strict(&public, message, &bad_signature)
            .is_err()
    );

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
    let mut seed = [0_u8; 64];
    let mut entropy = [0_u8; 32];
    getrandom::fill(&mut seed).expect("synthetic seed entropy");
    getrandom::fill(&mut entropy).expect("synthetic entropy");
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
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).expect("synthetic seed entropy");
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
