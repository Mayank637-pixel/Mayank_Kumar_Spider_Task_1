#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "license.h"

// Helper to calculate CRC32 for testing
static uint32_t calc_crc32(const uint8_t *data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

static uint64_t rotl64(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64U - shift));
}

static void calc_signature_mac(
    uint8_t out[32],
    const uint8_t *data,
    size_t size,
    size_t skip_offset,
    size_t skip_len
) {
    static const uint8_t signature_key[32] = {
        0x2d, 0x91, 0x43, 0xa7, 0x5c, 0xe1, 0x18, 0x6f,
        0xb2, 0x09, 0xd4, 0x73, 0x8a, 0x35, 0xc6, 0x1e,
        0x57, 0xfa, 0x24, 0x80, 0x6a, 0xbd, 0x11, 0xce,
        0x98, 0x4f, 0xe3, 0x2a, 0x75, 0x0c, 0xb9, 0x61
    };
    uint64_t state[4] = {
        0x243F6A8885A308D3ULL,
        0x13198A2E03707344ULL,
        0xA4093822299F31D0ULL,
        0x082EFA98EC4E6C89ULL
    };

    for (size_t i = 0; i < size; i++) {
        uint64_t byte;
        uint64_t key;

        if (i >= skip_offset && i < skip_offset + skip_len) {
            continue;
        }

        byte = data[i];
        key = signature_key[i % sizeof(signature_key)];

        state[0] ^= byte + key + (uint64_t)i;
        state[0] *= 0x100000001B3ULL;
        state[0] = rotl64(state[0], 5);

        state[1] ^= state[0] + byte + 0x9E3779B97F4A7C15ULL;
        state[1] *= 0xC2B2AE3D27D4EB4FULL;
        state[1] = rotl64(state[1], 11);

        state[2] ^= state[1] + (byte << (i & 7));
        state[2] *= 0x165667B19E3779F9ULL;
        state[2] = rotl64(state[2], 17);

        state[3] ^= state[2] + key + (uint64_t)(size - i);
        state[3] *= 0x9E3779B185EBCA87ULL;
        state[3] = rotl64(state[3], 23);
    }

    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            out[(i * 8) + j] = (uint8_t)(state[i] >> (56 - (j * 8)));
        }
    }
}

static void set_signature(uint8_t *buffer, size_t total_size, size_t sig_payload_offset) {
    uint8_t expected[32];

    memset(buffer + sig_payload_offset, 0, 256);
    calc_signature_mac(expected, buffer + 4, total_size - 4, sig_payload_offset - 4, 256);
    memcpy(buffer + sig_payload_offset, expected, sizeof(expected));
}

static void set_crc(uint8_t *buffer, size_t total_size) {
    uint32_t crc = calc_crc32(buffer + 4, total_size - 4);
    buffer[0] = (crc >> 24) & 0xFF;
    buffer[1] = (crc >> 16) & 0xFF;
    buffer[2] = (crc >> 8) & 0xFF;
    buffer[3] = crc & 0xFF;
}

void test_init_cleanup() {
    assert(init_license_system() == 1);
    assert(init_license_system() == 0); // double init fails
    cleanup_license_system();
    cleanup_license_system(); // double cleanup safe
    assert(init_license_system() == 1);
    cleanup_license_system();
    printf("[+] test_init_cleanup passed\n");
}

void test_valid_license_basic() {
    init_license_system();
    uint8_t buffer[1024] = {0};
    size_t offset = 8;
    size_t sig_payload_offset;
    
    // Chunk: Owner
    buffer[offset++] = CHUNK_TYPE_OWNER;
    buffer[offset++] = 0; buffer[offset++] = 4;
    memcpy(&buffer[offset], "Test", 4); offset += 4;
    
    // Chunk: Level
    buffer[offset++] = CHUNK_TYPE_LEVEL;
    buffer[offset++] = 0; buffer[offset++] = 4;
    buffer[offset++] = 0; buffer[offset++] = 0; buffer[offset++] = 0; buffer[offset++] = 1;
    
    // Chunk: Expiry
    buffer[offset++] = CHUNK_TYPE_EXPIRY;
    buffer[offset++] = 0; buffer[offset++] = 4;
    buffer[offset++] = 0; buffer[offset++] = 0; buffer[offset++] = 0; buffer[offset++] = 1;
    
    // Chunk: Features
    buffer[offset++] = CHUNK_TYPE_FEATURES;
    buffer[offset++] = 0; buffer[offset++] = 3;
    memcpy(&buffer[offset], "ABC", 3); offset += 3;
    
    // Chunk: HWID
    buffer[offset++] = CHUNK_TYPE_HWID;
    buffer[offset++] = 0; buffer[offset++] = 4;
    memcpy(&buffer[offset], "HWID", 4); offset += 4;
    
    // Chunk: Signature (required)
    buffer[offset++] = CHUNK_TYPE_SIGNATURE;
    buffer[offset++] = 1; buffer[offset++] = 0; // 256 bytes
    sig_payload_offset = offset;
    memset(&buffer[offset], 0, 256); offset += 256;
    
    // Chunk: Override (safe size <= 64)
    buffer[offset++] = CHUNK_TYPE_OVERRIDE;
    buffer[offset++] = 0; buffer[offset++] = 12;
    memcpy(&buffer[offset], "ADMIN_BYPASS", 12); offset += 12;

    size_t total_size = offset;
    buffer[4] = 0x01; buffer[5] = 0x00; // version
    buffer[6] = 0x00; buffer[7] = 0x00; // flags
    set_signature(buffer, total_size, sig_payload_offset);
    set_crc(buffer, total_size);
    
    assert(validate_license(buffer, total_size) == 1);
    cleanup_license_system();
    printf("[+] test_valid_license_basic passed\n");
}

void test_all_chunks() {
    init_license_system();
    uint8_t buffer[2048] = {0};
    size_t offset = 8;
    size_t sig_payload_offset;

    // Metadata
    buffer[offset++] = CHUNK_TYPE_METADATA;
    buffer[offset++] = 0; buffer[offset++] = 4;
    memcpy(&buffer[offset], "META", 4); offset += 4;

    // Issuer
    buffer[offset++] = CHUNK_TYPE_ISSUER;
    buffer[offset++] = 0; buffer[offset++] = 4;
    memcpy(&buffer[offset], "ISSU", 4); offset += 4;

    // Limits
    buffer[offset++] = CHUNK_TYPE_LIMITS;
    buffer[offset++] = 0; buffer[offset++] = 8;
    memset(&buffer[offset], 0, 8); offset += 8;

    // Comment
    buffer[offset++] = CHUNK_TYPE_COMMENT;
    buffer[offset++] = 0; buffer[offset++] = 4;
    memcpy(&buffer[offset], "COMM", 4); offset += 4;
    
    // Signature
    buffer[offset++] = CHUNK_TYPE_SIGNATURE;
    buffer[offset++] = 1; buffer[offset++] = 0;
    sig_payload_offset = offset;
    memset(&buffer[offset], 0, 256); offset += 256;

    size_t total_size = offset;
    buffer[4] = 0x01; buffer[5] = 0x00; // version
    buffer[6] = 0x00; buffer[7] = 0x00; // flags
    set_signature(buffer, total_size, sig_payload_offset);
    set_crc(buffer, total_size);

    assert(validate_license(buffer, total_size) == 1);
    cleanup_license_system();
    printf("[+] test_all_chunks passed\n");
}

void test_invalid_checksum() {
    init_license_system();
    uint8_t buffer[272] = {0};
    buffer[4] = 0x01; buffer[5] = 0x00;
    buffer[8] = CHUNK_TYPE_SIGNATURE;
    buffer[9] = 1; buffer[10] = 0;
    
    buffer[0] = 0; buffer[1] = 0; buffer[2] = 0; buffer[3] = 0;
    assert(validate_license(buffer, 272) == 0);
    cleanup_license_system();
    printf("[+] test_invalid_checksum passed\n");
}

void test_invalid_signature() {
    init_license_system();
    uint8_t buffer[272] = {0};
    size_t total_size = 267;
    buffer[4] = 0x01; buffer[5] = 0x00;
    buffer[8] = CHUNK_TYPE_SIGNATURE;
    buffer[9] = 1; buffer[10] = 0;
    memset(&buffer[11], 0xAA, 256);
    set_crc(buffer, total_size);

    assert(validate_license(buffer, total_size) == 0);
    cleanup_license_system();
    printf("[+] test_invalid_signature passed\n");
}

void test_missing_signature() {
    init_license_system();
    uint8_t buffer[64] = {0};
    buffer[4] = 0x01; buffer[5] = 0x00;
    
    buffer[8] = CHUNK_TYPE_OWNER;
    buffer[9] = 0; buffer[10] = 4;
    memcpy(&buffer[11], "Test", 4);
    
    size_t total_size = 15;
    set_crc(buffer, total_size);

    assert(validate_license(buffer, total_size) == 0);
    cleanup_license_system();
    printf("[+] test_missing_signature passed\n");
}

void test_trailing_bytes_rejected() {
    init_license_system();
    uint8_t buffer[300] = {0};
    size_t offset = 8;
    size_t sig_payload_offset;

    buffer[offset++] = CHUNK_TYPE_SIGNATURE;
    buffer[offset++] = 1; buffer[offset++] = 0;
    sig_payload_offset = offset;
    memset(&buffer[offset], 0, 256); offset += 256;
    buffer[offset++] = 0xFF;

    buffer[4] = 0x01; buffer[5] = 0x00;
    set_signature(buffer, offset, sig_payload_offset);
    set_crc(buffer, offset);

    assert(validate_license(buffer, offset) == 0);
    cleanup_license_system();
    printf("[+] test_trailing_bytes_rejected passed\n");
}

void test_uninitialized() {
    // Note: Do not call init_license_system()
    uint8_t buffer[272] = {0};
    assert(validate_license(buffer, 272) == 0);
    printf("[+] test_uninitialized passed\n");
}

int main() {
    printf("Running license validation tests...\n");
    test_init_cleanup();
    test_valid_license_basic();
    test_all_chunks();
    test_invalid_checksum();
    test_invalid_signature();
    test_missing_signature();
    test_trailing_bytes_rejected();
    test_uninitialized();
    printf("All legit flows tested successfully!\n");
    return 0;
}
