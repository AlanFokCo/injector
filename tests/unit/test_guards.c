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
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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

/* --- a pid that is *proven* not to exist --------------------------------
 *
 * This test used to attach to a hardcoded 999999 on the assumption that no
 * such process exists. That assumption is false in general: pid_max is
 * routinely raised to 4194304, so any fixed number can be a live process, and
 * injector_attach() against a live process patches an int3 trampoline into
 * *its* libc. Attaching to the wrong victim is how this project panicked its
 * host kernel twice. So the victim pid is discovered at run time instead, and
 * if it cannot be shown to be free the test fails loudly rather than guessing
 * or skipping.
 *
 * Two things make "shown to be free" harder than it looks:
 *   - a live thread's TID has NO /proc/<tid> entry (only /proc/<tgid>/task/<tid>),
 *     and injector_attach() does not require a thread-group leader, so a
 *     /proc-only check can pick a TID and PTRACE_ATTACH to it would *succeed*
 *     on somebody else's thread. kill(pid, 0) does see TIDs, hence both
 *     conditions in pid_is_unused();
 *   - "check, then attach" is a TOCTOU pair: a fork() landing on the pid in
 *     between makes this test ptrace a real process. The value of pid_max
 *     itself is the race-free choice, because the kernel only allocates pids
 *     in [1, pid_max - 1], so it is never a process, never a thread, and can
 *     never be handed out after we have checked it.
 */
static long read_pid_max(void)
{
    FILE *f = fopen("/proc/sys/kernel/pid_max", "r");
    long v = 0;

    if (f == NULL) {
        return 0;
    }
    if (fscanf(f, "%ld", &v) != 1) {
        v = 0;
    }
    fclose(f);
    return v;
}

/* "Unused" means both: kill(pid, 0) fails with ESRCH (EPERM would mean it
 * exists but belongs to somebody else), and /proc/<pid> is absent. */
static int pid_is_unused(pid_t pid)
{
    char path[64];

    if (pid <= 1) {
        return 0;                       /* never even consider pid 0/1 */
    }
    if (kill(pid, 0) == 0) {
        return 0;
    }
    if (errno != ESRCH) {
        return 0;
    }
    snprintf(path, sizeof(path), "/proc/%ld", (long)pid);
    return access(path, F_OK) != 0;
}

/* Returns a pid that is confirmed unused, or -1.
 *
 * The preferred answer is pid_max itself: the kernel never allocates it (see
 * the block comment above), so the caller's injector_attach() cannot be raced
 * by a fork() into attaching to a live process or thread. The bounded scans
 * below are a fallback for when pid_max is unreadable or fails the double
 * check; they keep both conditions - which is what excludes live threads - but
 * they do leave a very small check-then-attach window. */
static pid_t find_free_pid(void)
{
    long pid_max = read_pid_max();
    long p, lo, tried;

    if (pid_max <= 2) {
        pid_max = 32768;                /* probe unavailable: kernel default */
    }
    if (pid_max > 4194304L) {
        pid_max = 4194304L;             /* PID_MAX_LIMIT */
    }
    /* Race-free path, taken on every sane Linux: pid_max is never handed out. */
    if (pid_is_unused((pid_t)pid_max)) {
        return (pid_t)pid_max;
    }
    /* Fallback: scan downwards from the top of the range - those pids are the
     * least likely to be handed out, and the loop can never walk past 2. */
    lo = pid_max - 1 - 65536;
    if (lo < 2) {
        lo = 2;
    }
    for (p = pid_max - 1, tried = 0; p > lo && tried < 65536; p--, tried++) {
        if (pid_is_unused((pid_t)p)) {
            return (pid_t)p;
        }
    }
    /* Last resort, bounded so it cannot spin on a crowded machine. */
    for (p = 2, tried = 0; p < pid_max && tried < 4096; p++, tried++) {
        if (pid_is_unused((pid_t)p)) {
            return (pid_t)p;
        }
    }
    return (pid_t)-1;
}

/* attach must not leave a dangling caller pointer behind on failure. */
int test_failed_attach_nulls_the_handle(void) {
    injector_t *inj = (injector_t *)0xdeadbeef;   /* poison: must be overwritten */
    long pid_max = read_pid_max();
    pid_t victim = find_free_pid();
    int rv;

    if (victim == (pid_t)-1) {
        fprintf(stderr,
                "    cannot prove any pid is unused (pid_max=%ld): refusing to "
                "attach to a guessed one\n", pid_max);
        return 1;
    }
    MU_ASSERT(victim > 1);
    MU_ASSERT(victim != getpid());
    if (pid_max > 2) {
        /* <= rather than <: find_free_pid() deliberately prefers pid_max
         * itself, which the kernel never allocates, so the victim normally
         * *is* pid_max. */
        MU_ASSERT((long)victim <= pid_max);
    }
    /* Re-confirm immediately before attaching. On the pid_max path this is
     * belt and braces - nothing could have been allocated there since
     * find_free_pid() looked. On the scan fallback it narrows, but does not
     * close, the check-then-attach window. */
    MU_ASSERT(pid_is_unused(victim));

    rv = injector_attach(&inj, (injector_pid_t)victim);
    if (rv == 0) {
        fprintf(stderr, "    attach to unused pid %ld unexpectedly succeeded\n",
                (long)victim);
        injector_detach(inj);
        return 1;
    }
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

/* The canary is checked in full, with the offending index reported. Only
 * canary[0] and canary[7] used to be inspected, but `out` points at canary[4],
 * so a one- or two-byte overrun lands in canary[5]/canary[6] and went
 * completely unnoticed - and the read_comm half did not even look at out[0]. */
static int canary_intact(const char *canary, const char *what)
{
    int i;

    for (i = 0; i < 8; i++) {
        if (i == 4) {
            continue;                   /* that byte is out[0], checked below */
        }
        if (canary[i] != 'X') {
            fprintf(stderr,
                    "    %s(n=0) wrote out of bounds: canary[%d] (== out[%d]) "
                    "is '%c' (0x%02x), expected 'X'\n", what, i, i - 4,
                    (canary[i] >= 32 && canary[i] < 127) ? canary[i] : '.',
                    (unsigned char)canary[i]);
            return 0;
        }
    }
    return 1;
}

/* out[0] may legitimately be left as the 'Y' we wrote, or be set to '\0';
 * anything else means the zero-length guard did not hold. */
static int out_byte_untouched(char c, const char *what)
{
    if (c == '\0' || c == 'Y') {
        return 1;
    }
    fprintf(stderr,
            "    %s(n=0) modified out[0]: got '%c' (0x%02x), expected 'Y' or '\\0'\n",
            what, (c >= 32 && c < 127) ? c : '.', (unsigned char)c);
    return 0;
}

/* A zero-length output buffer used to make `n - 1` wrap to SIZE_MAX: readlink()
 * would be handed an unbounded size and the comm loop would write out of
 * bounds. Both halves below hand the parsers a buffer that starts in the middle
 * of an 8-byte canary array, so any write at all is visible. */
int test_proc_zero_length_buffer(void) {
    char canary[8];
    char *out;
    int rv;

    /* --- proc__read_link --- */
    memset(canary, 'X', sizeof(canary));
    out = &canary[4];                   /* point at the middle so any write is visible */
    out[0] = 'Y';
    rv = proc__read_link("/proc/self/exe", out, 0);
    MU_ASSERT(rv == -1);
    MU_ASSERT(out_byte_untouched(out[0], "proc__read_link"));
    MU_ASSERT(canary_intact(canary, "proc__read_link"));

    /* --- proc__read_comm --- */
    memset(canary, 'X', sizeof(canary));
    out = &canary[4];
    out[0] = 'Y';
    rv = proc__read_comm(getpid(), out, 0);
    MU_ASSERT(rv == -1);
    MU_ASSERT(out_byte_untouched(out[0], "proc__read_comm"));
    MU_ASSERT(canary_intact(canary, "proc__read_comm"));
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
