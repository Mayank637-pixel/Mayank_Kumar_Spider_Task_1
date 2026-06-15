#ifndef XAR_UTILS_H
#define XAR_UTILS_H

#include <stddef.h>
#include <stdint.h>

enum log_level {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
};

struct file_buffer {
    unsigned char *data;
    size_t size;
};

void log_set_level(enum log_level level);
void log_message(enum log_level level, const char *fmt, ...);

int read_file(const char *path, struct file_buffer *out);
void free_file_buffer(struct file_buffer *buffer);

uint16_t read_u16_le(const unsigned char *ptr);
uint32_t read_u32_le(const unsigned char *ptr);
uint64_t simple_checksum(const unsigned char *data, size_t len);
const char *chunk_type_name(uint8_t type);

#endif
