# JCS Number Provider Adoption

The representation boundary uses `ryu-js` 1.0.3 with no optional features for
the already-defined operation “finite IEEE-754 binary64 value to ECMAScript
number text.” The crate's safe `Buffer::format_finite` API is the only adopted
operation; its public raw formatting API is not used. Locked `serde_json`
1.0.151 enables `float_roundtrip` for correctly rounded binary64 parsing and
provides duplicate-aware token parsing and JSON string escaping, but its
default float formatter is not used as the JCS number oracle.

Local validation rejects non-finite values and integral values outside
`[-9007199254740991, 9007199254740991]` before canonical output. Local tests
cover the current LicoArc `1e-6` vector plus the applicable finite,
non-integral RFC 8785 Appendix B boundary and rounding samples. UTF-16 member
ordering, source bounds, duplicate detection, string escaping, and protocol
digest domains remain local responsibilities outside the number provider.

`ryu-js` is licensed Apache-2.0 OR BSL-1.0 and is a Rust port of the proved Ryu
algorithm specialized for ECMAScript formatting. It contains internal unsafe
code behind its safe buffer API. The repository's `unsafe_code = "forbid"`
lint governs this crate only and is not an end-to-end dependency safety claim;
the residual dependency boundary is recorded in `dependency-boundary.md`.
