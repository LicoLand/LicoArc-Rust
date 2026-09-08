# LicoArc Rust Context

This repository is an implementation workspace, not a protocol authority.
`PRODUCT.md` owns durable intent and `docs/STATUS.md` owns current facts.

## Invariants

- The repository owner is `licoarc-rust`.
- LicoArc is the sole authority for Lico Arc Protocol meaning.
- Rust code may not mint identifiers, patch wire semantics, create a
  translation path, or use another language implementation as a behavioral
  oracle.
- Build and test output is local and disposable.
- Implementation, verification, release, support, and hosted operation remain
  separate claims.
- The crate remains unpublished until a separately authorized release.
- Authority bytes are explicit, read-only, content-addressed caller input; the
  repository never searches for a sibling checkout or a mutable latest value.
- Snapshot provenance, Protocol Line content identity, and protection Profile
  content identity are distinct and checked before runtime construction.
- The admitted input is the unique initial V1 Candidate/COMPLETE stable-core
  Line with all eight mandatory capabilities and an indivisible protection
  Profile. Incomplete, content-mismatched, or component-selected input is
  terminal before secret or state work.
- Generic Messaging payloads remain opaque exact bytes. Group is optional and
  bounded to 64 members and 64 per-member projections.
- Caller-owned purpose-specific, non-serializable opaque handles authorize only
  their fixed signing, X25519, ML-KEM private-key, or encapsulation-entropy
  operation; Endpoint and ratchet orchestration never extract the corresponding
  private material.
- Identity signing handles remain caller-owned references. Endpoint-owned
  staged prekey and ratchet handles are adopted, transferred, replaced,
  consumed, or deleted only through the key mutations in the associated
  revisioned commit.
- Each Endpoint operation prepares one bounded snapshot, pending-output set,
  and key-mutation set. The caller's coupled `AtomicState` and custody backend
  commits the complete old-or-new result before packets, effects, or plaintext
  become available.
- Local source forbids unsafe code. Dependency-internal unsafe and physical
  erasure remain explicitly outside that guarantee. Opaque handles do not by
  themselves claim hardware custody or protection from a compromised process
  or malicious store.
