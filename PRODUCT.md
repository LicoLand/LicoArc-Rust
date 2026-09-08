# LicoArc Rust Product

LicoArc Rust is an independent safe-Rust implementation of the exact current
Candidate/COMPLETE stable-core v1 input. It admits one content-addressed
authority bundle, implements both Endpoint roles and all eight mandatory
capabilities, and verifies the complete standalone corpus locally.

## Product boundary

This repository owns Rust source, local build configuration, tests, and
implementation-local documentation. LicoArc remains the sole authority for
protocol semantics, identifiers, schemas, algorithms, state machines,
conformance policy, lifecycle, and publication.

## Current goal

Consume one explicitly caller-supplied `licoarc.bundle.v1` without copying its
normative sources. Keep authority admission, fixed cryptographic operations,
purpose-specific opaque custody, atomic caller state and handle lifecycle,
trust, time, carrier, and effects as separate boundaries. Endpoint handshake
and ratchet orchestration invokes private operations by handle; the caller's
coupled state/custody backend atomically adopts and deletes Endpoint-owned
handles with the associated state transition.

## Non-goals

- defining or translating protocol meaning;
- reusing TypeScript or Go protocol execution;
- operating a Station or hosted Network;
- publishing a crate, Protocol Line, package, deployment, or support claim;
- claiming formal security proof, interoperability, device admission, external
  audit, product integration, hardware custody, physical erasure, or
  malicious-store rollback protection.
