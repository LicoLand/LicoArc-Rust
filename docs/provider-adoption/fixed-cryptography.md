# Fixed Cryptography Provider Adoption

The crate locks one fixed RustCrypto provider generation. The adapter exposes
only SHA-256, HKDF-SHA-256, HMAC-SHA-256, ChaCha20-Poly1305, X25519, Ed25519,
ML-KEM-768, and ML-DSA-65 operations. Neither callers nor wire input select an
algorithm, parameter set, dependency, fallback, or reduced-round variant.
LicoArc remains the sole authority for protocol domains and failure meaning.

## Locked direct dependencies

| Operation | Crate | Version | Enabled direct features | Safe API boundary |
| --- | --- | --- | --- | --- |
| SHA-256 | `sha2` | 0.11.0 | none | one-shot `Digest` |
| HKDF-SHA-256 | `hkdf` | 0.13.0 | none | `Hkdf::new` and `expand` |
| HMAC-SHA-256 | `hmac` | 0.13.0 | none | `Mac::update` and `finalize` |
| ChaCha20-Poly1305 | `chacha20poly1305` | 0.11.0 | `zeroize` | detached `AeadInOut` seal/open |
| X25519 | `x25519-dalek` | 3.0.0 | `static_secrets`, `zeroize` | `StaticSecret::diffie_hellman` |
| Ed25519 | `ed25519-dalek` | 3.0.0 | `signature`, `zeroize` | seed signing and `verify_strict` |
| ML-KEM-768 | `ml-kem` | 0.3.2 | `alloc`, `zeroize` | deterministic seed key generation, encapsulation, decapsulation |
| ML-DSA-65 | `ml-dsa` | 0.1.1 | `alloc`, `zeroize` | seed key generation, signing, canonical decoding and verification |

Every direct dependency disables default features. OS random generation,
PKCS#8/PEM, serde, hazmat, legacy, batch verification, XChaCha, and
reduced-round variants are not enabled. Endpoint orchestration supplies
purpose-specific opaque handles to caller-owned custody, which performs the
fixed signing, X25519, ML-KEM private-key, and encapsulation-entropy operations
without exposing the corresponding private material across the custody
interface. The locked feature tree can still show dependency defaults selected
internally by another crate; the table records the direct features selected by
this crate, not a claim about every transitive edge.

The fixed shapes are a 32-byte SHA/HMAC/X25519/shared-secret result, a
12-byte ChaCha20-Poly1305 nonce with a 16-byte tag, a 32-byte Ed25519 public
key and 64-byte signature, an ML-KEM-768 public key of 1,184 bytes and
ciphertext of 1,088 bytes, and an ML-DSA-65 public key of 1,952 bytes and
signature of 3,309 bytes. Ed25519 verification uses the strict API and rejects
weak public keys. X25519 rejects the all-zero shared secret. Correctly sized
ML-KEM ciphertext always yields key material, including implicit-rejection
material for an invalid ciphertext; the provider exposes no validity bit.
Uniform confirmation outside this adapter decides handshake acceptance.

The focused provider contract suite binds standard SHA-256, RFC 5869,
RFC 4231, RFC 8439, RFC 7748, and RFC 8032 vectors. It also binds deterministic
ML-KEM-768 encapsulation/decapsulation, mutated-ciphertext implicit rejection,
ML-DSA-65 sign/verify, the public repeated-hint negative construction, exact
sizes, exact direct pins and features, and the local unsafe-code lint. These
tests verify this adoption boundary; they do not make a protocol-conformance,
interoperability, hardware-custody, audit, or publication claim.

All eight cryptographic crates are dual-licensed Apache-2.0 OR MIT and declare
an MSRV no greater than this crate's Rust 1.95 requirement. Version or feature
changes require a new locked graph review and the focused provider suite.

## ML-DSA advisory review

The locked `ml-dsa` 0.1.1 is newer than every applicable patched boundary:

- [GHSA-hcp2-x6j4-29j7](https://github.com/advisories/GHSA-hcp2-x6j4-29j7)
  covers a signing-time decomposition side channel and is patched in
  0.1.0-rc.3.
- [GHSA-5x2r-hc65-25f9](https://github.com/advisories/GHSA-5x2r-hc65-25f9)
  covers acceptance of repeated hint indices and is patched in 0.1.0-rc.4.
  The focused suite constructs and rejects the ML-DSA-65 negative case.
- [GHSA-h37v-hp6w-2pp8](https://github.com/advisories/GHSA-h37v-hp6w-2pp8)
  covers the zero-low-bits `UseHint` arithmetic error and is patched in
  0.1.0-rc.5.

This review records the resolved version boundary; it is not a claim that the
dependency, its implementation, or the complete graph has received an
independent security or side-channel audit.
