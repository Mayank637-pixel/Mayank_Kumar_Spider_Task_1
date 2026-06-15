#ifndef XAR_PARSER_H
#define XAR_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define XAR_MAGIC "XAR!"
#define XAR_MAGIC_SIZE 4
#define XAR_VERSION 1
#define XAR_HEADER_SIZE 24
#define XAR_META_SIZE 16
#define XAR_CHUNK_HEADER_SIZE 16

enum xar_chunk_type {
    XAR_CHUNK_RAW = 1,
    XAR_CHUNK_TEXT = 2,
    XAR_CHUNK_META = 3,
    XAR_CHUNK_INDEX = 4
};

struct xar_header {
    char magic[XAR_MAGIC_SIZE];
    uint16_t version;
    uint16_t flags;
    uint32_t archive_id;
    uint32_t metadata_size;
    uint32_t chunk_count;
    uint32_t chunk_area_offset;
};

struct xar_metadata {
    uint32_t creator_offset;
    uint32_t comment_offset;
    uint32_t creator_length;
    uint32_t comment_length;
    char creator[64];
    char comment[128];
};

struct xar_chunk {
    uint8_t type;
    uint8_t flags;
    uint16_t reserved;
    uint32_t length;
    uint32_t stored_checksum;
    uint32_t metadata_ref;
    unsigned char *data;
    char label[32];
};

struct xar_archive {
    struct xar_header header;
    struct xar_metadata metadata;
    struct xar_chunk *chunks;
    size_t parsed_chunks;
    const unsigned char *file_data;
    size_t file_size;
};

int xar_parse_buffer(struct xar_archive *archive,
                     const unsigned char *data,
                     size_t size);
void xar_print_summary(const struct xar_archive *archive);
void xar_free_archive(struct xar_archive *archive);

#endif
