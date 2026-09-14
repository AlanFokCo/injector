#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>

/* Yama's PR_SET_PTRACER, for headers old enough not to define it. The value is
 * the kernel's ABI, not a glibc one, so it is stable. */
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

#define DLLEXPORT

#define SLEEP_SECS 6

DLLEXPORT int exit_value = 0;
DLLEXPORT volatile int probe_val = 7;

int main()
{
    int i;

    /* Opt this process out of Yama's ptrace_scope restriction. With the common
     * default of 1, PTRACE_ATTACH is limited to a process's own descendants, so
     * who started the target decides whether it can be injected into at all:
     *
     *   tests/test-prog forks this program itself, so it is the parent and
     *   Yama is satisfied - every arch pair in `make check` works either way.
     *
     *   The CI steps that drive cmd/injector against a target started by the
     *   SHELL are not so lucky: injector and this process are siblings, and
     *   Yama answers PTRACE_ATTACH with EPERM. That is not a bug in the
     *   injector and not something it can work around - it is the kernel
     *   refusing, correctly, to let one user process trace another that has not
     *   agreed to it. It reproduces on any host with ptrace_scope=1 when run as
     *   an unprivileged user, and root hides it entirely (CAP_SYS_PTRACE
     *   bypasses Yama), which is why it survived so long on a development box
     *   that was always root.
     *
     * This is a throwaway test fixture whose whole purpose is to be injected
     * into, so agreeing to be traced by anyone is exactly right here. Best
     * effort and deliberately unchecked: with no Yama in the kernel the prctl
     * fails with EINVAL, and that must not stop the target from running. */
    (void)prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    /* Use loop instead of sleep(SLEEP_SECS) because
     * it may be interrupted on Linux.
     */
    for (i = 0; i < SLEEP_SECS; i++) {
        sleep(1);
		printf("target exit after %i seconds\n", SLEEP_SECS - i);
    }
	printf("exit...\n");
    return exit_value;
}
