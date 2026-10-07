#include "twilic/errors.h"
#include "twilic/protocol.h"
#include "twilic/v2.h"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::vector<uint8_t> bytes(data, data + size);
  try {
    (void)twilic::decode(bytes);
  } catch (const twilic::TwilicError&) {
  }
  try {
    (void)twilic::decode_v2(bytes);
  } catch (const twilic::TwilicError&) {
  }
  try {
    twilic::TwilicCodec codec;
    (void)codec.decode_message(bytes);
    (void)codec.decode_value(bytes);
  } catch (const twilic::TwilicError&) {
  }
  return 0;
}
