# LicoArc Rust

LicoArc Rust is a private, independent safe-Rust implementation of the exact
current Candidate/COMPLETE stable-core v1 input. It admits only an explicitly
supplied content-addressed authority bundle, exposes sealed Initiator and
Responder Endpoints, implements the hybrid handshake and classic Double
Ratchet, and composes all eight mandatory capabilities through caller-owned
purpose-specific opaque secret handles and atomic state, handle-lifecycle, and
effect boundaries.

LicoArc remains the sole authority for protocol semantics. This repository is
not an executable or published Protocol Line and makes no formal security,
deployment, interoperability, audit, device, operation, or support claim.
Opaque handles keep caller-supplied signing, X25519, ML-KEM private-key, and
encapsulation-entropy material behind caller custody; they do not establish
hardware custody or physical erasure.

## Verify

Use Rust 1.95 or newer with `rustfmt` and Clippy installed:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

To require complete conformance against an authority candidate, supply its
bundle explicitly:

```sh
tools/verify <explicit-licoarc-bundle>
```

The verifier does not discover or invoke another implementation. The current
complete registry executes 212 cases across 29 operation IDs exactly once and
requires every incomplete, skipped, unmapped, duplicate, and surplus counter to
remain zero.

See `PRODUCT.md`, `CONTEXT.md`, and `docs/STATUS.md` for the canonical boundary
and current status.
