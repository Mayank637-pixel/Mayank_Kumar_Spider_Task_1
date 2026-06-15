#include "parser.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--debug] <file.xar>\n"
            "\n"
            "Inspect a proprietary XAR archive and print a summary of its\n"
            "global metadata and chunk records.\n",
            prog);
}

static int parse_args(int argc, char **argv, const char **path)
{
    int i;

    *path = NULL;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--debug") == 0) {
            log_set_level(LOG_DEBUG);
            continue;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 1;
        }
        if (*path != NULL) {
            log_message(LOG_ERROR, "unexpected extra argument '%s'", argv[i]);
            return -1;
        }
        *path = argv[i];
    }

    if (*path == NULL) {
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *path;
    struct file_buffer input;
    struct xar_archive archive;
    int rc;

    rc = parse_args(argc, argv, &path);
    if (rc != 0) {
        return rc > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (read_file(path, &input) != 0) {
        return EXIT_FAILURE;
    }

    rc = xar_parse_buffer(&archive, input.data, input.size);
    if (rc != 0) {
        log_message(LOG_ERROR, "unable to parse archive '%s'", path);
        xar_free_archive(&archive);
        free_file_buffer(&input);
        return EXIT_FAILURE;
    }

    xar_print_summary(&archive);
    xar_free_archive(&archive);
    free_file_buffer(&input);
    return EXIT_SUCCESS;
}
