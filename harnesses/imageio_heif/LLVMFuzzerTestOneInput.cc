// RED APPLE RA-FND HEIF/ImageIO libFuzzer harness.
//
// The parser is intentionally small and mechanical: it walks ISO BMFF boxes,
// allocates parser state through parser_malloc(), and only hands plausible HEIF
// inputs to ImageIO for decode. parser_malloc() is the allocation the Foundry
// coverage gate looks for.

#include <CoreFoundation/CoreFoundation.h>
#include <ImageIO/ImageIO.h>

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>

namespace {

constexpr size_t kMaxBoxes = 32;
constexpr size_t kMaxBrandBytes = 128;

struct Box {
  uint32_t size;
  uint32_t type;
  size_t offset;
  size_t header_size;
};

struct HeifBoxes {
  size_t count = 0;
  bool has_meta = false;
  bool has_ftyp_heif = false;
  char major_brand[5] = {0, 0, 0, 0, 0};
};

__attribute__((noinline)) void* parser_malloc(size_t size) {
  return std::malloc(size);
}

__attribute__((noinline)) void parser_free(void* ptr) {
  std::free(ptr);
}

inline uint32_t read_u32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
         (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline uint64_t read_u64(const uint8_t* p) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value = (value << 8) | uint64_t(p[i]);
  }
  return value;
}

constexpr uint32_t box_type(const char* text) {
  return (uint32_t(uint8_t(text[0])) << 24) |
         (uint32_t(uint8_t(text[1])) << 16) |
         (uint32_t(uint8_t(text[2])) << 8) |
         uint32_t(uint8_t(text[3]));
}

bool is_heif_brand(uint32_t brand) {
  switch (brand) {
    case box_type("heic"):
    case box_type("heix"):
    case box_type("hevc"):
    case box_type("hevx"):
    case box_type("heim"):
    case box_type("heis"):
    case box_type("hevm"):
    case box_type("hevs"):
    case box_type("mif1"):
    case box_type("msf1"):
      return true;
    default:
      return false;
  }
}

__attribute__((noinline)) HeifBoxes parse_heif_boxes(const uint8_t* data, size_t size) {
  HeifBoxes result;
  if (size < 8) {
    return result;
  }

  Box* boxes = static_cast<Box*>(parser_malloc(kMaxBoxes * sizeof(Box)));
  if (boxes == nullptr) {
    return result;
  }

  const uint32_t meta_type = box_type("meta");
  const uint32_t ftyp_type = box_type("ftyp");
  size_t offset = 0;

  while (offset + 8 <= size && result.count < kMaxBoxes) {
    const uint32_t declared_size = read_u32(data + offset);
    const uint32_t type = read_u32(data + offset + 4);
    size_t header_size = 8;
    uint64_t box_size = declared_size;

    if (declared_size == 1) {
      if (offset + 16 > size) {
        break;
      }
      box_size = read_u64(data + offset + 8);
      header_size = 16;
    } else if (declared_size == 0) {
      box_size = size - offset;
    }

    if (box_size < header_size || box_size > uint64_t(size - offset)) {
      break;
    }

    boxes[result.count].size = uint32_t(box_size);
    boxes[result.count].type = type;
    boxes[result.count].offset = offset;
    boxes[result.count].header_size = header_size;
    ++result.count;

    if (type == meta_type) {
      result.has_meta = true;
    }

    if (type == ftyp_type && box_size >= header_size + 8) {
      const size_t payload = offset + header_size;
      const size_t payload_size = size_t(box_size) - header_size;
      const uint32_t major = read_u32(data + payload);
      if (is_heif_brand(major)) {
        result.has_ftyp_heif = true;
        std::memcpy(result.major_brand, data + payload, 4);
        result.major_brand[4] = '\0';
      }

      if (!result.has_ftyp_heif && payload_size >= 16 && payload_size <= kMaxBrandBytes) {
        // Minor version occupies payload[4:8]; compatible brands follow.
        for (size_t pos = payload + 8; pos + 4 <= payload + payload_size; pos += 4) {
          if (is_heif_brand(read_u32(data + pos))) {
            result.has_ftyp_heif = true;
            std::memcpy(result.major_brand, data + payload, 4);
            result.major_brand[4] = '\0';
            break;
          }
        }
      }
    }

    offset += size_t(box_size);
  }

  parser_free(boxes);
  return result;
}

__attribute__((noinline)) bool decode_with_imageio(const uint8_t* data, size_t size) {
  CFDataRef cf_data = CFDataCreate(kCFAllocatorDefault, data, CFIndex(size));
  if (cf_data == nullptr) {
    return false;
  }

  CGImageSourceRef source = CGImageSourceCreateWithData(cf_data, nullptr);
  CFRelease(cf_data);
  if (source == nullptr) {
    return false;
  }

  bool decoded = false;
  const size_t count = CGImageSourceGetCount(source);
  if (count > 0) {
    CGImageRef image = CGImageSourceCreateImageAtIndex(source, 0, nullptr);
    if (image != nullptr) {
      decoded = true;
      CGImageRelease(image);
    }
  }

  CFRelease(source);
  return decoded;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  const HeifBoxes boxes = parse_heif_boxes(Data, Size);
  if (!boxes.has_ftyp_heif || !boxes.has_meta) {
    return 0;
  }

  volatile bool decoded = decode_with_imageio(Data, Size);
  (void)decoded;
  return 0;
}
