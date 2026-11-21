// Reject-case fixture: ImageIO decode without a reachable parser malloc.
#include <CoreFoundation/CoreFoundation.h>
#include <ImageIO/ImageIO.h>

#include <cstdint>
#include <cstddef>

__attribute__((noinline)) bool decode_with_imageio(const uint8_t* data, size_t size) {
  CFDataRef cf_data = CFDataCreate(kCFAllocatorDefault, data, CFIndex(size));
  if (cf_data == nullptr) return false;
  CGImageSourceRef source = CGImageSourceCreateWithData(cf_data, nullptr);
  CFRelease(cf_data);
  if (source == nullptr) return false;
  bool decoded = false;
  if (CGImageSourceGetCount(source) > 0) {
    CGImageRef image = CGImageSourceCreateImageAtIndex(source, 0, nullptr);
    if (image != nullptr) {
      decoded = true;
      CGImageRelease(image);
    }
  }
  CFRelease(source);
  return decoded;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  volatile bool decoded = decode_with_imageio(Data, Size);
  (void)decoded;
  return 0;
}
