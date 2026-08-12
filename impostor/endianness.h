#ifndef ENDIANESS_H
#define ENDIANESS_H

#include <stdint.h>

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
    #define IS_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#else
    static __inline uint8_t __test_endianness() {
        uint16_t i = 1;
        uint8_t *p = (uint8_t*)(&i);
        return p[0] == 0;
    }
    #define IS_BIG_ENDIAN (__test_endianness())
#endif

#define IS_LITTLE_ENDIAN !IS_BIG_ENDIAN

static __inline uint16_t __byte_swp_16(uint16_t __x) {

    return (uint16_t)(__x << 8) 
         | (uint16_t)(__x >> 8);
}

static __inline uint32_t __byte_swp_32(uint32_t __x) {

    return (uint32_t)(__x >> 24) 
         | (uint32_t)((__x >> 8) & 0x0000ff00) 
         | (uint32_t)((__x << 8) & 0x00ff0000)
         | (uint32_t)(__x << 24);
}

static __inline uint64_t __byte_swp_64(uint64_t __x) {

    return (uint64_t)(__x >> 56) 
         | (uint64_t)((__x >> 40) & 0x000000000000ff00)
         | (uint64_t)((__x >> 24) & 0x0000000000ff0000)
         | (uint64_t)((__x >> 8 ) & 0x00000000ff000000)
         | (uint64_t)((__x << 8 ) & 0x000000ff00000000)
         | (uint64_t)((__x << 24) & 0x0000ff0000000000)
         | (uint64_t)((__x << 40) & 0x00ff000000000000)
         | (uint64_t)((__x << 56) & 0xff00000000000000);
}

#if IS_LITTLE_ENDIAN
// 16-bit
#define htobe16(x) __byte_swp_16(x)
#define betoh16(x) __byte_swp_16(x)
#define letoh16(x) (uint16_t)(x)
#define htole16(x) (uint16_t)(x)
// 32-bit
#define htobe32(x) __byte_swp_32(x)
#define betoh32(x) __byte_swp_32(x)
#define letoh32(x) (uint32_t)(x)
#define htole32(x) (uint32_t)(x)
// 64-bit
#define htobe64(x) __byte_swp_64(x)
#define betoh64(x) __byte_swp_64(x)
#define letoh64(x) (uint64_t)(x)
#define htole64(x) (uint64_t)(x)

#elif IS_BIG_ENDIAN
// 16-bit
#define htobe16(x) (uint16_t)(x)
#define betoh16(x) (uint16_t)(x)
#define letoh16(x) __byte_swp_16(x)
#define htole16(x) __byte_swp_16(x)
// 32-bit
#define htobe32(x) (uint32_t)(x)
#define betoh32(x) (uint32_t)(x)
#define letoh32(x) __byte_swp_32(x)
#define htole32(x) __byte_swp_32(x)
// 64-bit
#define htobe64(x) (uint64_t)(x)
#define betoh64(x) (uint64_t)(x)
#define letoh64(x) __byte_swp_64(x)
#define htole64(x) __byte_swp_64(x)
#endif


#endif // ENDIANESS_H