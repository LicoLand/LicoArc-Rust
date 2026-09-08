# Security Policy

LicoArc owns protocol and cryptographic semantics; this repository never
repairs, extends, or reinterprets them. The implementation uses one pinned
fixed-algorithm provider generation, strict signature verification, ML-KEM
implicit rejection, bounded state transitions, and local `unsafe_code =
"forbid"`.

Handshake signing, X25519, ML-KEM private-key, and encapsulation-entropy
operations use purpose-specific opaque handles through caller-owned custody.
Endpoint-owned handle adoption, replacement, consumption, and deletion travel
with the associated state transition in one bounded caller-implemented atomic
commit. Private material does not cross that custody interface, and diagnostic
forms redact handles and protected values.

Local verification is not an independent cryptographic audit. Dependencies may
contain internal unsafe code. Logical deletion removes reachable protocol state
and requests deletion of Endpoint-owned handles through the atomic custody
lifecycle, but does not claim physical erasure, protection from a compromised
process or malicious store, hardware custody, or side-channel resistance. The
caller-supplied custody and atomic-state implementation remains responsible for
enforcing handle purpose, reachability, and old-or-new mutation semantics.

Security reports must omit secrets, private keys, plaintext, ciphertext,
runtime data, local paths, machine identity, and other protected operational
details. Use synthetic, minimum-necessary reproduction material.
