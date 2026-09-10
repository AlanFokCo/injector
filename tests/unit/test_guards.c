/* test_guards.c - regression tests for the input-validation and NULL-handle
 * guards added during the hardening pass.
 *
 * These are the cheap, always-safe invariants: they must hold without attaching
 * to anything, so they run in every `make unit` invocation and in CI.
 *
 * DELIBERATELY NOT TESTED HERE: that injector_attach() refuses pid 1. It does
 * refuse it, and that guard matters enormously - attaching patches an int3
 * trampoline into the target's libc, and when systemd executed one the test
 * host died with "Kernel panic - not syncing: Attempted to kill init!". But an
 * automated test can only verify the guard by *calling* attach(1), which means
 * that if the guard ever regressed the test itself would panic the machine
 * running it. A test that can destroy its own CI runner is worse than no test,
 * so the guard is covered by review plus the non-intrusive pid checks below
 * (injector_target_info / injector_can_attach accept pid 1 by design: they only
 * read /proc).
 */
#include "minunit.h"
#include "injector.h"
#include "../src/linux/proc.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* A NULL handle used to be dereferenced unconditionally, which killed the whole
 * process - uncatchable, and reachable from every language binding after the
 * caller closed its handle. Every entry point must now refuse it. */
int test_null_handle_is_refused(void) {
    void *handle = NULL;
    size_t addr = 0;
    intptr_t retval = 0;
    char buf[16];
    injector_module_t mods[2];

    MU_ASSERT(injector_detach(NULL) != 0);
    MU_ASSERT(injector_inject(NULL, "/nonexistent.so", &handle) != 0);
    MU_ASSERT(injector_uninject(NULL, (void *)0x1000) != 0);
    MU_ASSERT(injector_uninject_all(NULL) != 0);
    MU_ASSERT(injector_remote_func_addr(NULL, (void *)0x1000, "f", &addr) != 0);
    MU_ASSERT(injector_remote_call(NULL, &retval, 0x1000) != 0);
    MU_ASSERT(injector_resolve_symbol(NULL, NULL, "malloc", (uintptr_t *)&addr) != 0);
    MU_ASSERT(injector_read_mem(NULL, 0x1000, buf, sizeof(buf)) != 0);
    MU_ASSERT(injector_write_mem(NULL, 0x1000, buf, sizeof(buf)) != 0);
    MU_ASSERT(injector_list_modules(NULL, mods, 2) < 0);
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    MU_ASSERT(injector_inject_in_cloned_thread(NULL, "/nonexistent.so", &handle) != 0);
#endif
    MU_ASSERT(injector_invoke(NULL, "/nonexistent.so", "f", NULL, 0, NULL) != 0);
    /* last_error(NULL) is the documented way to read the thread-local message,
     * so it must be safe and must never return NULL. */
    MU_ASSERT(injector_last_error(NULL) != NULL);
    return 0;
}

/* attach must not leave a dangling caller pointer behind on failure. */
int test_failed_attach_nulls_the_handle(void) {
    injector_t *inj = (injector_t *)0xdeadbeef;   /* poison: must be overwritten */
    int rv = injector_attach(&inj, (injector_pid_t)999999);
    MU_ASSERT(rv != 0);
    MU_ASSERT(inj == NULL);
    return 0;
}

/* pid <= 0 is meaningless for attach and dangerous for signals: kill(0, 0)
 * succeeds and a negative pid means "the whole process group". */
int test_nonpositive_pid_rejected(void) {
    injector_target_info_t info;
    MU_ASSERT(injector_target_info(0, &info) != 0);
    MU_ASSERT(injector_target_info(-1, &info) != 0);
    MU_ASSERT(injector_can_attach(0) == 0);
    MU_ASSERT(injector_can_attach(-1) == 0);
    return 0;
}

/* A zero-length output buffer used to make `n - 1` wrap to SIZE_MAX: readlink()
 * would be handed an unbounded size and the comm loop would write out of
 * bounds. */
int test_proc_zero_length_buffer(void) {
    char canary[8];
    memset(canary, 'X', sizeof(canary));
    /* point at the middle so any write is visible */
    char *out = &canary[4];
    out[0] = 'Y';
    MU_ASSERT(proc__read_link("/proc/self/exe", out, 0) == -1);
    MU_ASSERT(out[0] == '\0' || out[0] == 'Y');   /* either untouched or NUL */
    MU_ASSERT(canary[0] == 'X' && canary[7] == 'X');

    out[0] = 'Y';
    MU_ASSERT(proc__read_comm(getpid(), out, 0) == -1);
    MU_ASSERT(canary[0] == 'X' && canary[7] == 'X');
    return 0;
}

/* A path longer than proc_map_t.path used to be silently truncated, which lost
 * the " (deleted)" suffix and made the caller trust a stale libc mapping. */
int test_proc_long_path_still_detects_deleted(void) {
    char line[2048];
    char path[1200];
    memset(path, 'a', sizeof(path));
    path[0] = '/';
    path[sizeof(path) - 1] = '\0';
    snprintf(line, sizeof(line),
             "7f0000000000-7f0000100000 r-xp 00000000 fd:01 99 %s (deleted)\n", path);
    proc_map_t m;
    MU_ASSERT(proc__parse_maps_line(line, &m) == 0);
    MU_ASSERT(m.deleted == 1);
    MU_ASSERT(m.path[sizeof(m.path) - 1] == '\0');      /* always terminated */
    MU_ASSERT(strlen(m.path) < sizeof(m.path));
    MU_ASSERT(strstr(m.path, "(deleted)") == NULL);     /* suffix stripped */
    return 0;
}
