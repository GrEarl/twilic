#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = twilic::decode(data);
    let _ = twilic::v2::decode(data);
});
