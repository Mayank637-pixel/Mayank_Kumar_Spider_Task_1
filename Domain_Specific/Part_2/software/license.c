#include "license.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_system_initialized = 0;
static char g_owner[256] = {0};
static int g_level = 0;
static int g_expiry = 0;
static char g_features[128] = {0};
static char g_hwid[64] = {0};
static const uint8_t k_signature_key[32] = {
    0x2d, 0x91, 0x43, 0xa7, 0x5c, 0xe1, 0x18, 0x6f,
    0xb2, 0x09, 0xd4, 0x73, 0x8a, 0x35, 0xc6, 0x1e,
    0x57, 0xfa, 0x24, 0x80, 0x6a, 0xbd, 0x11, 0xce,
    0x98, 0x4f, 0xe3, 0x2a, 0x75, 0x0c, 0xb9, 0x61
};

static void log_debug(const char *msg) {
}

static void log_error(const char *msg) {
    printf("[ERROR] %s\n", msg);
}

static uint32_t calculate_crc32(const uint8_t *data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

static uint16_t read_u16_be(const uint8_t *data) {
    return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

static uint32_t read_u32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint64_t rotl64(uint64_t value, unsigned shift) {
    return (value << shift) | (value >> (64U - shift));
}

static void calculate_signature_mac(
    uint8_t out[32],
    const uint8_t *data,
    size_t size,
    size_t skip_offset,
    size_t skip_len
) {
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
        key = k_signature_key[i % sizeof(k_signature_key)];

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

static int verify_signature(
    const uint8_t *sig,
    size_t sig_len,
    const uint8_t *data,
    size_t data_len,
    size_t sig_offset
) {
    uint8_t expected[32];

    log_debug("Verifying cryptographic signature...");
    if (sig_len != 256 || sig_offset > data_len || sig_len > data_len - sig_offset) {
        return 0;
    }

    calculate_signature_mac(expected, data, data_len, sig_offset, sig_len);
    if (memcmp(sig, expected, sizeof(expected)) != 0) {
        return 0;
    }

    for (size_t i = sizeof(expected); i < sig_len; i++) {
        if (sig[i] != 0) {
            return 0;
        }
    }

    return 1;
}

int init_license_system(void) {
    if (g_system_initialized) {
        log_error("System already initialized!");
        return 0;
    }
    
    memset(g_owner, 0, sizeof(g_owner));
    g_level = 0;
    g_expiry = 0;
    memset(g_features, 0, sizeof(g_features));
    memset(g_hwid, 0, sizeof(g_hwid));
    
    g_system_initialized = 1;
    log_debug("License system initialized.");
    return 1;
}

void cleanup_license_system(void) {
    if (!g_system_initialized) return;
    g_system_initialized = 0;
    log_debug("License system cleaned up.");
}

static int process_owner(const uint8_t *data, uint16_t len) {
    if (len >= sizeof(g_owner)) return 0;
    memcpy(g_owner, data, len);
    g_owner[len] = '\0';
    return 1;
}

static int process_level(const uint8_t *data, uint16_t len) {
    if (len != 4) return 0;
    g_level = (int)read_u32_be(data);
    return 1;
}

static int process_expiry(const uint8_t *data, uint16_t len) {
    if (len != 4) return 0;
    g_expiry = (int)read_u32_be(data);
    return 1;
}

static int process_features(const uint8_t *data, uint16_t len) {
    if (len >= sizeof(g_features)) return 0;
    memcpy(g_features, data, len);
    g_features[len] = '\0';
    return 1;
}

static int process_hwid(const uint8_t *data, uint16_t len) {
    if (len >= sizeof(g_hwid)) return 0;
    memcpy(g_hwid, data, len);
    g_hwid[len] = '\0';
    return 1;
}

static int process_metadata(const uint8_t *data, uint16_t len) {
    log_debug("Processing metadata chunk...");
    if (len > 1024) return 0;
    return 1;
}

static int process_issuer(const uint8_t *data, uint16_t len) {
    log_debug("Processing issuer chunk...");
    return (len < 128); 
}

static int process_limits(const uint8_t *data, uint16_t len) {
    if (len < 8) return 0;
    return 1;
}

static int process_comment(const uint8_t *data, uint16_t len) {
    return 1;
}

static int process_signature(const uint8_t *data, uint16_t len) {
    if (len != 256) return 0;
    log_debug("Found signature block.");
    return 1;
}

static int process_override(const uint8_t *data, uint16_t len) {
    log_debug("Processing override chunk...");
    
    char override_buffer[64];
    
    memcpy(override_buffer, data, len);
    
    override_buffer[63] = '\0';
    
    return 1;
}

int validate_license(const uint8_t *data, size_t size) {
    if (!g_system_initialized) {
        log_error("License system not initialized!");
        return 0;
    }

    if (!data || size < 8) {
        log_error("Invalid input data or size.");
        return 0;
    }

    uint32_t expected_crc = read_u32_be(data);
    uint32_t actual_crc = calculate_crc32(data + 4, size - 4);
    
    if (expected_crc != actual_crc) {
        log_error("CRC32 checksum mismatch!");
        return 0;
    }

    uint16_t version = read_u16_be(data + 4);
    if (version != 0x0100) {
        log_error("Unsupported license version.");
        return 0;
    }
    
    uint16_t flags = read_u16_be(data + 6);
    (void)flags;

    size_t offset = 8;
    int has_signature = 0;
    const uint8_t *signature_data = NULL;
    size_t signature_offset = 0;
    uint16_t signature_len = 0;

    while (offset + 3 <= size) {
        uint8_t type = data[offset];
        uint16_t len = read_u16_be(data + offset + 1);
        offset += 3;

        if (offset + len > size) {
            log_error("Chunk goes out of bounds.");
            return 0;
        }

        const uint8_t *chunk_data = data + offset;
        int success = 0;

        switch (type) {
            case CHUNK_TYPE_OWNER:
                success = process_owner(chunk_data, len);
                break;
            case CHUNK_TYPE_LEVEL:
                success = process_level(chunk_data, len);
                break;
            case CHUNK_TYPE_EXPIRY:
                success = process_expiry(chunk_data, len);
                break;
            case CHUNK_TYPE_SIGNATURE:
                success = process_signature(chunk_data, len);
                if (success) {
                    has_signature = 1;
                    signature_data = chunk_data;
                    signature_offset = offset;
                    signature_len = len;
                }
                break;
            case CHUNK_TYPE_COMMENT:
                success = process_comment(chunk_data, len);
                break;
            case CHUNK_TYPE_FEATURES:
                success = process_features(chunk_data, len);
                break;
            case CHUNK_TYPE_LIMITS:
                success = process_limits(chunk_data, len);
                break;
            case CHUNK_TYPE_METADATA:
                success = process_metadata(chunk_data, len);
                break;
            case CHUNK_TYPE_HWID:
                success = process_hwid(chunk_data, len);
                break;
            case CHUNK_TYPE_ISSUER:
                success = process_issuer(chunk_data, len);
                break;
            case CHUNK_TYPE_OVERRIDE:
                success = process_override(chunk_data, len);
                break;
            default:
                log_error("Unknown chunk type.");
                success = 0;
                break;
        }

        if (!success) {
            log_error("Failed to process chunk.");
            return 0;
        }

        offset += len;
    }

    if (offset != size) {
        log_error("Trailing bytes after final chunk.");
        return 0;
    }

    if (!has_signature) {
        log_error("License is missing a signature.");
        return 0;
    }

    if (!verify_signature(signature_data, signature_len, data + 4, size - 4, signature_offset - 4)) {
        log_error("Signature verification failed.");
        return 0;
    }

    log_debug("License validated successfully!");
    return 1;
}
