# LicoArc fuzz targets

libFuzzer targets over the crate's untrusted-input decoders. The directory is a
standalone `cargo-fuzz` crate: it is not part of the `licoarc` package targets,
so `tools/verify` is unaffected.

| Target | Surface |
| --- | --- |
| `cbor_decode` | `encoding::decode` deterministic-CBOR bounds and canonicality |
| `mailbox_frames` | `transport::ClientFrame::decode` and `StationFrame::decode` |
| `first_packet` | `endpoint::decode_first_packet` |
| `session_accept` | `endpoint::decode_session_accept` |
| `record_header` | `protection::RatchetHeader::decode` via the receiver's 38..=48 header-prefix scan |

## Run locally (stable toolchain)

Rust's sanitizer-coverage flags are stable `-C` flags, so a coverage-guided
run needs no nightly when they are scoped to target code only:

```sh
cd fuzz
TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
env "CARGO_TARGET_$(echo "$TRIPLE" | tr 'a-z-' 'A-Z_')_RUSTFLAGS=-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table" \
    cargo build --release --locked --target "$TRIPLE" --bins
cargo run --locked --example gen_seeds
mkdir -p artifacts
"target/$TRIPLE/release/session_accept" corpus/session_accept \
    -max_total_time=60 -artifact_prefix=artifacts/session_accept-
```

Each binary is a normal libFuzzer driver: `-runs=N`, `-max_total_time=`, corpus
directories and `-artifact_prefix=` all work as documented upstream.

## Run with cargo-fuzz (nightly)

With `cargo-fuzz` installed and a nightly toolchain, run the same targets with
sanitizers from the repository root:

```sh
cargo +nightly fuzz run session_accept -- -max_total_time=60
```
