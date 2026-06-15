/*
 * AFL++ fuzzing harness — license validation library
 *
 * Build:  make fuzzer
 * Run:    afl-fuzz -i corpus/ -o findings/ -- ./fuzzer @@
 *
 * AFL++ is launching, the binary runs, but the fuzzer makes no progress.
 * Something is wrong. Find the issues and fix them.
 */

#include "license.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    size_t chunk_offset;
    size_t data_offset;
    uint16_t len;
} sig_info_t;

static const uint8_t k_signature_key[32] = {
    0x2d, 0x91, 0x43, 0xa7, 0x5c, 0xe1, 0x18, 0x6f,
    0xb2, 0x09, 0xd4, 0x73, 0x8a, 0x35, 0xc6, 0x1e,
    0x57, 0xfa, 0x24, 0x80, 0x6a, 0xbd, 0x11, 0xce,
    0x98, 0x4f, 0xe3, 0x2a, 0x75, 0x0c, 0xb9, 0x61
};

static void write_uint32_be(uint8_t *buf, uint32_t value)
{
    buf[0] = value >> 24;
    buf[1] = value >> 16;
    buf[2] = value >> 8;
    buf[3] = value;
}

static uint16_t read_u16_be(const uint8_t *data)
{
    return ((uint16_t)data[0] << 8) |
           (uint16_t)data[1];
}

static uint32_t calculate_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];

        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^
                  (0xEDB88320 & (-(crc & 1)));
        }
    }

    return ~crc;
}

static uint64_t rotl64(uint64_t value, unsigned shift)
{
    return (value << shift) |
           (value >> (64U - shift));
}

static void calculate_signature_mac(
    uint8_t out[32],
    const uint8_t *data,
    size_t size,
    size_t skip_offset,
    size_t skip_len)
{
    uint64_t state[4] = {
        0x243F6A8885A308D3ULL,
        0x13198A2E03707344ULL,
        0xA4093822299F31D0ULL,
        0x082EFA98EC4E6C89ULL
    };

    for (size_t i = 0; i < size; i++) {

        if (i >= skip_offset &&
            i < skip_offset + skip_len)
        {
            continue;
        }

        uint64_t byte = data[i];
        uint64_t key =
            k_signature_key[
                i % sizeof(k_signature_key)
            ];

        state[0] ^= byte + key + (uint64_t)i;
        state[0] *= 0x100000001B3ULL;
        state[0] = rotl64(state[0], 5);

        state[1] ^= state[0] +
                    byte +
                    0x9E3779B97F4A7C15ULL;

        state[1] *= 0xC2B2AE3D27D4EB4FULL;
        state[1] = rotl64(state[1], 11);

        state[2] ^= state[1] +
                    (byte << (i & 7));

        state[2] *= 0x165667B19E3779F9ULL;
        state[2] = rotl64(state[2], 17);

        state[3] ^= state[2] +
                    key +
                    (uint64_t)(size - i);

        state[3] *= 0x9E3779B185EBCA87ULL;
        state[3] = rotl64(state[3], 23);
    }

    for (size_t i = 0; i < 4; i++) {

        for (size_t j = 0; j < 8; j++) {

            out[(i * 8) + j] =
                (uint8_t)(
                    state[i] >>
                    (56 - (j * 8))
                );
        }
    }
}

static int find_signature_chunk(
    const uint8_t *buf,
    size_t file_len,
    sig_info_t *sig)
{
    size_t offset = 8;

    while (offset + 3 <= file_len)
    {
        uint8_t type = buf[offset];

        uint16_t chunk_len =
            read_u16_be(buf + offset + 1);

        size_t data_offset =
            offset + 3;

        if (data_offset + chunk_len >
            file_len)
        {
            return 0;
        }

        if (type == CHUNK_TYPE_SIGNATURE)
        {
            sig->chunk_offset = offset;
            sig->data_offset = data_offset;
            sig->len = chunk_len;
            return 1;
        }

        offset =
            offset + 1 + 2 + chunk_len;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        return 1;

    FILE *f = fopen(argv[1], "rb");

    if (!f)
        return 0;

    uint8_t buf[65536];

    size_t len =
        fread(buf, 1, sizeof(buf), f);

    fclose(f);

    if (len < 8)
        return 0;

    sig_info_t sig;

    if (find_signature_chunk(
            buf,
            len,
            &sig))
    {
        /* repair length */

        buf[sig.chunk_offset + 1] = 0x01;
        buf[sig.chunk_offset + 2] = 0x00;

        sig.len = 256;

        uint8_t expected[32];

        calculate_signature_mac(
            expected,
            buf + 4,
            len - 4,
            sig.data_offset - 4,
            256);

        memcpy(
            buf + sig.data_offset,
            expected,
            32);

        memset(
            buf + sig.data_offset + 32,
            0,
            256 - 32);
    }

    /* repair crc last */

    uint32_t crc =
        calculate_crc32(
            buf + 4,
            len - 4);

    write_uint32_be(buf, crc);

    init_license_system();

    validate_license(buf, len);

    cleanup_license_system();

    return 0;
}
