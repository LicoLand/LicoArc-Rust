#![no_main]

use libfuzzer_sys::fuzz_target;
use licoarc::protection::RatchetHeader;

// Mirrors the bounded header-prefix scan the receiver applies before
// authenticating a protected record: candidate header lengths 38..=48.
fuzz_target!(|data: &[u8]| {
    for length in 38..=data.len().min(48) {
        if RatchetHeader::decode(&data[..length]).is_ok() {
            break;
        }
    }
});
