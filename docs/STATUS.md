# LicoArc Rust Status

Status dimensions are reported independently.

## Intent

The approved local intent is an independent safe-Rust implementation of the
exact current Candidate/COMPLETE stable-core v1 input. LicoArc remains the sole
protocol authority.

## Implementation

- Rust 1.95 and edition 2024 admit only the exact explicit bundle and verify its
  118-source closure, Line/Profile identities, complete capability, proof,
  binding, bounds, and corpus facts before runtime construction.
- Fixed injectable operations cover SHA-256, HKDF/HMAC-SHA-256,
  ChaCha20-Poly1305, X25519, strict Ed25519, ML-KEM-768, and ML-DSA-65 using the
  locked provider generation recorded under `docs/provider-adoption/`.
- Purpose-specific opaque handles keep caller-supplied Ed25519 and ML-DSA-65
  signing, X25519, ML-KEM-768 private-key, and encapsulation-entropy operations
  behind caller-owned custody. The Endpoint and ratchet receive only the fixed
  public, signature, ciphertext, or shared-secret results required by V1.
- Sealed Initiator and Responder Endpoints implement paired one-time prekeys,
  dual authentication, user-authority-bound SessionAccept, bidirectional ratchets,
  retry, replay, out-of-order receive, restart, rollback, and logical deletion.
- The caller's coupled state/custody backend applies each complete Endpoint
  snapshot, pending-output set, and bounded handle adoption/deletion set as one
  old-or-new revision transition. Definitely rejected transitions abort staged
  handles; uncertain commit results are resolved from stored revision/state or
  leave the same handles fenced for caller recovery.
- Foundation, Governance, Identity, Pairwise Protection, Generic Messaging,
  Reliable Exchange, Group Collaboration, and HTTPS
  Transport use bounded deterministic reducers and caller-owned state/effects.
- The manifest-derived production registry executes 212/212 cases through all
  29 operation IDs with 8/8 capability coverage and zero incomplete, skipped,
  unmapped, duplicate, or surplus dispositions.
- Local source forbids unsafe code. Hardware custody, dependency-internal
  unsafe, independent audit, physical erasure, malicious-store rollback
  detection, and compromised-process guarantees remain unclaimed.

## Verification

Focused locked tests cover exact admission, provider and custody contracts,
public handle boundaries, two-role handle-only handshake and ratchet flows,
atomic handle recovery and deletion, all capabilities, exact conformance,
privacy, and repository independence.
The exact 212-case registry result establishes complete dispatch and result
oracle coverage; each case establishes only the semantics its operation
executes. The five fixed V1 handshake cases decode the canonical FirstPacket,
bind it to the admitted Line/Profile and call production handshake
authentication with provider-backed Ed25519 and ML-DSA-65 verification. They
cover valid authentication, independent signature mutation, Line mismatch and
authority substitution. Production Endpoint tests separately cover complete
two-role establishment and state transitions. This focused evidence is not a
cryptographic claim for every corpus case or a proof of SDK security.
`tools/verify` accepts one explicit authority bundle and closes formatting,
warnings-denied Clippy, doc tests, all targets, and exact conformance. Local
verification does not claim publication, interoperability, or external audit.

## Release

No source tag, crate publication, package publication, Protocol Line
publication, deployment, or hosted operation is claimed.

## Support

Support remains unclaimed. Protocol Line and crate publication, product
integration, interoperability, device admission, external audit, deployment,
and hosted operation remain separate and unmet.
