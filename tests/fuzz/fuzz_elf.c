/* libFuzzer harness: hostile ELF files fed to libinjector's ELF parsers. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "injector.h"
#include "injector_internal.h"

static char tmppath[] = "/tmp/fuzz_elf_XXXXXX";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (1u << 20)) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/tmp/fuzz_elf_%d", (int)getpid());
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;
    ssize_t w = write(fd, data, size);
    close(fd);
    if (w < 0 || (size_t)w != size) { unlink(path); return 0; }

    int machine = -1;
    (void)injector__read_elf_machine(path, &machine);

    size_t bias = 0;
    for (size_t map_start = 0; map_start <= (size_t)0x7f0000000000ULL; map_start = map_start ? map_start * 4096 : 4096) {
        (void)injector__elf_load_bias(path, map_start, &bias);
        if (map_start > (size_t)1 << 48) break;
    }

    static const char *const names[] = {"dlopen", "dlerror", "dlsym", "malloc", "free", "__libc_dlopen_mode"};
    size_t addrs[6] = {0};
    (void)injector__elf_find_symbols(path, (size_t)0x7f1234560000ULL, names, addrs, 6);

    unlink(path);
    (void)tmppath;
    return 0;
}
