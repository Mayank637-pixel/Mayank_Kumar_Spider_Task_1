#ifndef LICENSE_H
#define LICENSE_H

#include <stdint.h>
#include <stddef.h>

#define CHUNK_TYPE_OWNER 0x01
#define CHUNK_TYPE_LEVEL 0x02
#define CHUNK_TYPE_EXPIRY 0x03
#define CHUNK_TYPE_SIGNATURE 0x04
#define CHUNK_TYPE_COMMENT 0x05
#define CHUNK_TYPE_FEATURES 0x06
#define CHUNK_TYPE_LIMITS 0x07
#define CHUNK_TYPE_METADATA 0x08
#define CHUNK_TYPE_HWID 0x09
#define CHUNK_TYPE_ISSUER 0x0A
#define CHUNK_TYPE_OVERRIDE 0x42

int init_license_system(void);
void cleanup_license_system(void);
int validate_license(const uint8_t *data, size_t size);

#endif // LICENSE_H
