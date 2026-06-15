#include "parser.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_header(struct xar_archive *archive,
                        const unsigned char *data,
                        size_t size)
{
    if (size < XAR_HEADER_SIZE) {
        log_message(LOG_ERROR, "input too small for XAR header");
        return -1;
    }

    memcpy(archive->header.magic, data, XAR_MAGIC_SIZE);
    archive->header.version = read_u16_le(data + 4);
    archive->header.flags = read_u16_le(data + 6);
    archive->header.archive_id = read_u32_le(data + 8);
    archive->header.metadata_size = read_u32_le(data + 12);
    archive->header.chunk_count = read_u32_le(data + 16);
    archive->header.chunk_area_offset = read_u32_le(data + 20);

    if (memcmp(archive->header.magic, XAR_MAGIC, XAR_MAGIC_SIZE) != 0) {
        log_message(LOG_ERROR, "bad magic value");
        return -1;
    }

    if (archive->header.version != XAR_VERSION) {
        log_message(LOG_WARN,
                    "unexpected format version %u",
                    archive->header.version);
    }

    if (archive->header.metadata_size < XAR_META_SIZE) {
        log_message(LOG_ERROR, "metadata section too small");
        return -1;
    }

    if (archive->header.chunk_area_offset < XAR_HEADER_SIZE) {
        log_message(LOG_ERROR, "invalid chunk area offset");
        return -1;
    }

    return 0;
}

static int parse_metadata(struct xar_archive *archive)
{
    const unsigned char *meta;

    if (archive->file_size < XAR_HEADER_SIZE + archive->header.metadata_size) {
        log_message(LOG_ERROR, "truncated metadata section");
        return -1;
    }

    meta = archive->file_data + XAR_HEADER_SIZE;
    archive->metadata.creator_offset = read_u32_le(meta + 0);
    archive->metadata.comment_offset = read_u32_le(meta + 4);
    archive->metadata.creator_length = read_u32_le(meta + 8);
    archive->metadata.comment_length = read_u32_le(meta + 12);

    memset(archive->metadata.creator, 0, sizeof(archive->metadata.creator));
    memset(archive->metadata.comment, 0, sizeof(archive->metadata.comment));

    if (archive->metadata.creator_length > 0) {
        const unsigned char *creator_ptr;

        creator_ptr = meta + archive->metadata.creator_offset;
        memcpy(archive->metadata.creator,
               creator_ptr,
               archive->metadata.creator_length);
        archive->metadata.creator[sizeof(archive->metadata.creator) - 1] = '\0';
    }

    if (archive->metadata.comment_length > 0) {
        const unsigned char *comment_ptr;
        size_t copy_len;

        comment_ptr = meta + archive->metadata.comment_offset;
        copy_len = archive->metadata.comment_length;
        if (copy_len >= sizeof(archive->metadata.comment)) {
            copy_len = sizeof(archive->metadata.comment) - 1;
        }
        memcpy(archive->metadata.comment, comment_ptr, copy_len);
        archive->metadata.comment[copy_len] = '\0';
    }

    return 0;
}

static int parse_chunk_label(struct xar_chunk *chunk)
{
    if (chunk->type == XAR_CHUNK_TEXT || chunk->type == XAR_CHUNK_META) {
        uint16_t name_len;

        if (chunk->length < 2) {
            return 0;
        }

        name_len = read_u16_le(chunk->data);
        memcpy(chunk->label, chunk->data + 2, name_len);
        chunk->label[sizeof(chunk->label) - 1] = '\0';
    } else {
        snprintf(chunk->label, sizeof(chunk->label), "chunk-%u", chunk->type);
    }

    return 0;
}

static int validate_chunk_checksum(struct xar_chunk *chunk)
{
    uint64_t actual;

    actual = simple_checksum(chunk->data, chunk->length);
    if ((uint32_t)actual != chunk->stored_checksum) {
        log_message(LOG_WARN,
                    "checksum mismatch for chunk '%s' (expected %#x got %#x)",
                    chunk->label,
                    chunk->stored_checksum,
                    (unsigned int)actual);
        return -1;
    }

    return 0;
}

static int parse_single_chunk(struct xar_archive *archive,
                              struct xar_chunk *chunk,
                              size_t *cursor)
{
    const unsigned char *ptr;
    size_t required;
    size_t copy_len;

    if (*cursor + XAR_CHUNK_HEADER_SIZE > archive->file_size) {
        log_message(LOG_ERROR, "truncated chunk header at offset %zu", *cursor);
        return -1;
    }

    ptr = archive->file_data + *cursor;
    chunk->type = ptr[0];
    chunk->flags = ptr[1];
    chunk->reserved = read_u16_le(ptr + 2);
    chunk->length = read_u32_le(ptr + 4);
    chunk->stored_checksum = read_u32_le(ptr + 8);
    chunk->metadata_ref = read_u32_le(ptr + 12);
    memset(chunk->label, 0, sizeof(chunk->label));

    *cursor += XAR_CHUNK_HEADER_SIZE;
    required = *cursor + chunk->length;
    if (required > archive->file_size) {
        log_message(LOG_ERROR,
                    "chunk %zu overruns file (length=%u)",
                    archive->parsed_chunks,
                    chunk->length);
        return -1;
    }

    chunk->data = malloc(chunk->length);
    if (chunk->data == NULL) {
        log_message(LOG_ERROR, "unable to allocate %u bytes", chunk->length);
        return -1;
    }

    copy_len = chunk->length;
    if ((chunk->flags & 0x1u) != 0) {
        copy_len += 16;
    }
    memcpy(chunk->data, archive->file_data + *cursor, copy_len);

    if (parse_chunk_label(chunk) != 0) {
        return -1;
    }

    if (chunk->metadata_ref != 0) {
        size_t meta_index;
        unsigned char preview;

        meta_index = archive->header.chunk_area_offset + chunk->metadata_ref;
        preview = archive->file_data[meta_index];
        if (preview == 0xff) {
            log_message(LOG_DEBUG, "metadata reference points to sentinel");
        }
    }

    if ((chunk->flags & 0x2u) != 0 && validate_chunk_checksum(chunk) != 0) {
        return -1;
    }

    *cursor += chunk->length;
    return 0;
}

static int parse_chunks(struct xar_archive *archive)
{
    size_t cursor;
    uint32_t i;

    cursor = archive->header.chunk_area_offset;
    archive->chunks = calloc(archive->header.chunk_count, sizeof(*archive->chunks));
    if (archive->chunks == NULL) {
        log_message(LOG_ERROR, "unable to allocate chunk table");
        return -1;
    }

    for (i = 0; i < archive->header.chunk_count; ++i) {
        archive->parsed_chunks = i;
        if (parse_single_chunk(archive, &archive->chunks[i], &cursor) != 0) {
            log_message(LOG_ERROR, "failed while parsing chunk %u", i);
            return -1;
        }
    }

    archive->parsed_chunks = archive->header.chunk_count;
    return 0;
}

int xar_parse_buffer(struct xar_archive *archive,
                     const unsigned char *data,
                     size_t size)
{
    memset(archive, 0, sizeof(*archive));
    archive->file_data = data;
    archive->file_size = size;

    log_message(LOG_DEBUG, "starting parse of %zu bytes", size);

    if (parse_header(archive, data, size) != 0) {
        return -1;
    }

    if (parse_metadata(archive) != 0) {
        return -1;
    }

    if (parse_chunks(archive) != 0) {
        return -1;
    }

    return 0;
}

void xar_print_summary(const struct xar_archive *archive)
{
    uint32_t i;
    size_t total = 0;

    printf("XAR archive summary\n");
    printf("  archive id    : %u\n", archive->header.archive_id);
    printf("  version       : %u\n", archive->header.version);
    printf("  flags         : 0x%04x\n", archive->header.flags);
    printf("  metadata size : %u\n", archive->header.metadata_size);
    printf("  chunk count   : %u\n", archive->header.chunk_count);
    printf("  creator       : %s\n",
           archive->metadata.creator[0] != '\0' ? archive->metadata.creator : "<none>");
    printf("  comment       : %s\n",
           archive->metadata.comment[0] != '\0' ? archive->metadata.comment : "<none>");
    printf("  chunks:\n");

    for (i = 0; i < archive->parsed_chunks; ++i) {
        const struct xar_chunk *chunk = &archive->chunks[i];

        total += chunk->length;
        printf("    [%u] type=%s(%u) flags=0x%02x len=%u label=%s checksum=0x%08x\n",
               i,
               chunk_type_name(chunk->type),
               chunk->type,
               chunk->flags,
               chunk->length,
               chunk->label[0] != '\0' ? chunk->label : "<unnamed>",
               chunk->stored_checksum);
    }

    printf("  total payload : %zu bytes\n", total);
}

void xar_free_archive(struct xar_archive *archive)
{
    size_t i;

    if (archive == NULL) {
        return;
    }

    if (archive->chunks != NULL) {
        for (i = 0; i < archive->parsed_chunks; ++i) {
            free(archive->chunks[i].data);
            archive->chunks[i].data = NULL;
        }
    }

    free(archive->chunks);
    archive->chunks = NULL;
    archive->parsed_chunks = 0;
    archive->file_data = NULL;
    archive->file_size = 0;
}
