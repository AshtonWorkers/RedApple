// RED APPLE RA-DISC ImageIO/HEIF stdin feed driver.
//
// Reads one mutated input from stdin and runs the PR #7 proof harness entry
// point against it. Compile together with LLVMFuzzerTestOneInput.cc on macOS
// without -fsanitize=fuzzer so the lane can feed bytes over stdin.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size);

namespace {

constexpr size_t kMaxInputBytes = 4 * 1024 * 1024;

bool read_stdin(std::vector<uint8_t>& out) {
  uint8_t buffer[8192];
  while (true) {
    const size_t n = std::fread(buffer, 1, sizeof(buffer), stdin);
    if (n == 0) {
      return std::feof(stdin) != 0;
    }
    if (out.size() + n > kMaxInputBytes) {
      return false;
    }
    out.insert(out.end(), buffer, buffer + n);
  }
}

}  // namespace

int main() {
  std::vector<uint8_t> data;
  data.reserve(4096);
  if (!read_stdin(data)) {
    return 2;
  }
  return LLVMFuzzerTestOneInput(data.data(), data.size());
}
