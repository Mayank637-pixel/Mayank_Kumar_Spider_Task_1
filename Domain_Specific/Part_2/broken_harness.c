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

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 0;

    uint8_t buf[65536];
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (!init_license_system())
        return 0;

    validate_license(buf, len);

    return 0;
}
