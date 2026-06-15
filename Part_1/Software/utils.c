#include "utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static enum log_level g_log_level = LOG_INFO;

void log_set_level(enum log_level level)
{
    g_log_level = level;
}

void log_message(enum log_level level, const char *fmt, ...)
{
    static const char *names[] = {
        "DEBUG",
        "INFO",
        "WARN",
        "ERROR"
    };
    va_list ap;

    if (level < g_log_level) {
        return;
    }

    fprintf(stderr, "[%s] ", names[level]);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}

int read_file(const char *path, struct file_buffer *out)
{
    FILE *fp;
    long len;
    size_t read_len;
    unsigned char *buffer;

    memset(out, 0, sizeof(*out));

    fp = fopen(path, "rb");
    if (fp == NULL) {
        log_message(LOG_ERROR, "unable to open '%s'", path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        log_message(LOG_ERROR, "failed to seek to end of '%s'", path);
        return -1;
    }

    len = ftell(fp);
    if (len < 0) {
        fclose(fp);
        log_message(LOG_ERROR, "failed to get length of '%s'", path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        log_message(LOG_ERROR, "failed to rewind '%s'", path);
        return -1;
    }

    buffer = malloc((size_t)len);
    if (buffer == NULL) {
        fclose(fp);
        log_message(LOG_ERROR, "out of memory while reading '%s'", path);
        return -1;
    }

    read_len = fread(buffer, 1, (size_t)len, fp);
    fclose(fp);

    if (read_len != (size_t)len) {
        free(buffer);
        log_message(LOG_ERROR, "short read while reading '%s'", path);
        return -1;
    }

    out->data = buffer;
    out->size = (size_t)len;
    return 0;
}

void free_file_buffer(struct file_buffer *buffer)
{
    if (buffer == NULL) {
        return;
    }

    free(buffer->data);
    buffer->data = NULL;
    buffer->size = 0;
}

uint16_t read_u16_le(const unsigned char *ptr)
{
    return (uint16_t)ptr[0] | ((uint16_t)ptr[1] << 8);
}

uint32_t read_u32_le(const unsigned char *ptr)
{
    return (uint32_t)ptr[0]
         | ((uint32_t)ptr[1] << 8)
         | ((uint32_t)ptr[2] << 16)
         | ((uint32_t)ptr[3] << 24);
}

uint64_t simple_checksum(const unsigned char *data, size_t len)
{
    uint64_t acc = 0xcbf29ce484222325ULL;
    size_t i;

    for (i = 0; i < len; ++i) {
        acc ^= data[i];
        acc *= 0x100000001b3ULL;
    }

    return acc;
}

const char *chunk_type_name(uint8_t type)
{
    switch (type) {
    case 1:
        return "raw";
    case 2:
        return "text";
    case 3:
        return "meta";
    case 4:
        return "index";
    default:
        return "unknown";
    }
}
