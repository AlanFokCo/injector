/* libFuzzer harness: /proc/<pid>/maps line parser (pure function). */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "proc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 16384) return 0;
    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    proc_map_t m;
    memset(&m, 0xA5, sizeof(m));
    (void)proc__parse_maps_line(buf, &m);

    /* unterminated / oversized line must not be read past `size` */
    memset(&m, 0, sizeof(m));
    (void)proc__parse_maps_line("", &m);
    free(buf);
    return 0;
}
