#![no_main]

use libfuzzer_sys::fuzz_target;
use twilic::TwilicCodec;

fuzz_target!(|data: &[u8]| {
    let mut codec = TwilicCodec::default();
    let _ = codec.decode_message(data);
    let _ = codec.decode_value(data);
});
