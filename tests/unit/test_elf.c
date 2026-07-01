#include "minunit.h"
#include "injector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>

/* Internal helper exposed for testing (declared in src/linux/injector_internal.h). */
int injector__elf_find_symbols(const char *path, size_t libc_addr,
                               const char *const names[], size_t addrs[], size_t n);

/* Build a tiny shared object exporting two known symbols, then resolve them in
 * a single pass through injector__elf_find_symbols. */
int test_elf_resolve_known_symbols(void) {
    const char *src =
        "int my_sym_one(void) { return 1; }\n"
        "int my_sym_two(void) { return 2; }\n";

    FILE *f = fopen("/tmp/inj_elf_src.c", "w");
    MU_ASSERT(f != NULL);
    MU_ASSERT(fputs(src, f) != EOF);
    MU_ASSERT(fclose(f) == 0);

    if (system("cc -shared -fPIC -o /tmp/inj_elf_fixture.so /tmp/inj_elf_src.c") != 0) {
        /* No compiler available: skip, not fail. */
        unlink("/tmp/inj_elf_src.c");
        return 0;
    }

    const char *names[] = { "my_sym_one", "my_sym_two", "does_not_exist" };
    size_t addrs[3] = {0};
    int rv = injector__elf_find_symbols("/tmp/inj_elf_fixture.so", 0, names, addrs, 3);
    MU_ASSERT(rv == 0);
    MU_ASSERT(addrs[0] != 0);  /* my_sym_one found */
    MU_ASSERT(addrs[1] != 0);  /* my_sym_two found */
    MU_ASSERT(addrs[2] == 0);  /* does_not_exist not found */

    /* Sanity-check the fixture itself via dlopen: the exported functions must
     * work when loaded. (We do not compare addresses: with libc_addr=0 the
     * resolver returns st_value, whereas dlsym returns the runtime load
     * address, which differs for PIE/ASLR objects.) */
    void *h = dlopen("/tmp/inj_elf_fixture.so", RTLD_LAZY | RTLD_LOCAL);
    MU_ASSERT(h != NULL);
    if (h != NULL) {
        int (*p1)(void) = (int (*)(void))(uintptr_t)dlsym(h, "my_sym_one");
        int (*p2)(void) = (int (*)(void))(uintptr_t)dlsym(h, "my_sym_two");
        MU_ASSERT(p1 != NULL);
        MU_ASSERT(p2 != NULL);
        if (p1 != NULL) MU_ASSERT(p1() == 1);
        if (p2 != NULL) MU_ASSERT(p2() == 2);
        dlclose(h);
    }

    unlink("/tmp/inj_elf_src.c");
    unlink("/tmp/inj_elf_fixture.so");
    return 0;
}
