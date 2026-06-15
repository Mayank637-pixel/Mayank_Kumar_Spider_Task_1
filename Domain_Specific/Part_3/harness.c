#include <stdint.h>
#include <stddef.h>
#include <archive.h>
#include <archive_entry.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    struct archive *a;
    struct archive_entry *entry;
    const void *buff;
    size_t buff_size;
    int64_t offset;
    int r;

    a = archive_read_new();

    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    archive_read_open_memory(a, data, size);

    while ((r = archive_read_next_header(a, &entry))
            == ARCHIVE_OK)
    {
        while ((r = archive_read_data_block(
                    a,
                    &buff,
                    &buff_size,
                    &offset))
                == ARCHIVE_OK)
        {
            
        }
    }

    archive_free(a);
    return 0;
}
