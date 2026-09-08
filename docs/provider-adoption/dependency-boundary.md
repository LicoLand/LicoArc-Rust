# Dependency Safety Boundary

`unsafe_code = "forbid"` applies to the `licoarc-rust` crate and its local
targets. It does not lint dependency implementations, procedural macros, or
build-time code.

The locked representation and digest graphs include dependencies that use
internal unsafe code for parsing/formatting buffers, optimized hashing, or CPU
feature detection. Serde derive also executes procedural-macro code at build
time. Production code calls only the reviewed safe APIs documented in the
provider records. Cryptographic dependencies may use internal unsafe code,
optimized assembly or intrinsics, constant-time helpers, heap-backed secret
storage, and zeroization on their own documented boundaries. Those
implementation details are outside the local lint and have not been
independently audited here.

Accordingly, this adoption makes no claim of transitive or whole-toolchain safe
Rust, complete constant-time behavior, independent cryptographic audit,
physical erasure, allocator or swap erasure, hardware-backed custody, or
protection from compiler and platform behavior. `zeroize` narrows ordinary
in-memory lifetime where implemented; it does not establish those stronger
properties. The purpose-specific opaque handle interface prevents Endpoint and
ratchet orchestration from extracting caller-custodied private material, but it
does not strengthen the implementation properties of the selected custody
backend or these dependencies. Dependency changes require the provider record,
focused vectors, license, and locked graph to be reviewed together.
