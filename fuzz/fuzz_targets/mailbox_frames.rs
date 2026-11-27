#![no_main]

use libfuzzer_sys::fuzz_target;
use licoarc::transport::{ClientFrame, StationFrame};

fuzz_target!(|data: &[u8]| {
    let _ = ClientFrame::decode(data);
    let _ = StationFrame::decode(data);
});
