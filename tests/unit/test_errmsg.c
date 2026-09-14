#include "minunit.h"
#include "injector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

/* Defined in run.c. Same extern test_elf.c uses: a test that cannot set itself
 * up must be COUNTED, because minunit.h treats `return 0` as a pass. */
extern int tests_skipped;

/* A pid that provably does not exist, so injector_attach() cannot be talked
 * into attaching to a live process.
 *
 * MINOR 8: this test used to fork() a child, reap it, and then attach to the
 * pid it had just freed - the "guess which pids exist" pattern that 3672ee3
 * deliberately removed from test_guards.c. Two things followed from guessing:
 *   - if the kernel handed that pid to somebody else in the meantime,
 *     injector_attach() SUCCEEDED, `MU_ASSERT(rv != 0)` failed, and the test
 *     returned without injector_detach() - leaving an unrelated process
 *     ptrace-stopped for as long as the runner lived;
 *   - a fork() failure did `return 0`, i.e. a silent PASS invisible to
 *     tests_skipped, against this repo's explicit no-silent-skips policy.
 *
 * Mirrors find_free_pid() in test_guards.c: the kernel never allocates pid_max
 * itself, so asking for it is race-free rather than a guess. That helper is
 * file-static in a file this suite does not own, hence the local copy rather
 * than a call. */
static pid_t unused_pid(void)
{
    char buf[32] = {0,};
    char path[64];
    long pid_max = 0;
    FILE *f;

    f = fopen("/proc/sys/kernel/pid_max", "r");
    if (f != NULL) {
        if (fgets(buf, sizeof(buf), f) == NULL) {
            buf[0] = '\0';
        }
        fclose(f);
        pid_max = strtol(buf, NULL, 10);
    }
    if (pid_max <= 2) {
        return (pid_t)-1;               /* unreadable: refuse to guess a pid */
    }
    if (pid_max > 4194304L) {
        pid_max = 4194304L;             /* PID_MAX_LIMIT */
    }
    /* Confirm nothing is wearing it before claiming it is free. */
    snprintf(path, sizeof(path), "/proc/%ld", pid_max);
    if (access(path, F_OK) == 0) {
        return (pid_t)-1;
    }
    return (pid_t)pid_max;
}

int test_error_after_failed_attach(void) {
    injector_t *inj = NULL;
    pid_t victim = unused_pid();
    const char *e;
    int rv;

    if (victim == (pid_t)-1) {
        /* MINOR 8: not `return 0`. A counted skip is what run.c reports in its
         * summary, and run.c fails the whole suite on any counted skip unless
         * the caller opts in with INJECTOR_ALLOW_SKIP=1 - so this can no longer
         * look like a pass. */
        fprintf(stderr, "  skip: test_error_after_failed_attach (cannot prove a "
                        "pid is unused; refusing to attach to a guessed one)\n");
        tests_skipped++;
        return 0;
    }
    MU_ASSERT(victim > 1);              /* never pid 0/1: attach must not reach them */
    rv = injector_attach(&inj, victim); /* ESRCH -> INJERR_NO_PROCESS */
    if (rv == 0) {
        /* Should be impossible: `victim` is pid_max, which the kernel never
         * allocates. If it ever does happen, DETACH first - returning with the
         * handle attached is exactly what used to strand a live process in a
         * ptrace stop. */
        fprintf(stderr, "    attach to unused pid %ld unexpectedly succeeded\n",
                (long)victim);
        injector_detach(inj);
        return 1;
    }
    MU_ASSERT(inj == NULL);
    e = injector_error(); /* thread-local fallback must survive */
    MU_ASSERT(e != NULL && e[0] != '\0');
    MU_ASSERT(strstr(e, "No such process") != NULL);
    return 0;
}
