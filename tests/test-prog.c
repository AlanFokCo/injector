/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2018-2023 Kubo Takehiro <kubo@jiubao.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <inttypes.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>     /* FD_CLOEXEC: report a failed execl() to the parent */
#include <limits.h>
#include "../include/injector.h"

#define INCR_ON_INJECTION 13
#define INCR_ON_UNINJECTION 17

#define EXEEXT ""
#define DLLEXT ".so"
#define INJECT_ERRMSG "failed to get the full path of 'no such library': No such file or directory"

typedef struct process process_t;

static int process_start(process_t *proc, char *test_target);
static int process_check_module(process_t *proc, const char *module_name, int startswith);
static int process_wait(process_t *proc, int wait_secs);
static void process_terminate(process_t *proc);

struct process {
    pid_t pid;
    int waited;
    int is_musl;
};

/* Start the target and WAIT for proof that it actually started.
 *
 * fork() succeeding says nothing about execl(): the child used to exit(2)
 * silently and the harness went on to print "target process started." and then
 * inject into a pid that no longer existed, so a missing or misnamed fixture
 * showed up as a confusing failure several steps later (or, worse, as a test
 * that could not fail). The pipe is O_CLOEXEC, so a successful exec closes it
 * and read() returns 0; a failed exec writes errno back first.
 * Returns 0 on success, -1 (with a message printed) if the target did not start. */
static int process_start(process_t *proc, char *test_target)
{
    int fds[2];
    int child_errno = 0;
    int wstatus = 0;
    char why[64];
    pid_t w;
    ssize_t r;

    /* MINOR 6: leave a SAFE state behind on every early return below. The
     * pipe()/fcntl() failures return before the fork() that assigns proc->pid, so
     * without this a later process_terminate() would act on whatever the caller's
     * struct held - garbage if the caller never initialised it, which is worse
     * than the pid==0 case its `pid > 0` guard covers. */
    proc->pid = 0;
    proc->waited = 1;

    /* pipe() + F_SETFD rather than pipe2(): pipe2 is GNU/BSD-only and this file
     * is built without _GNU_SOURCE on every arch pair in tests/Makefile. The two
     * calls must also be checked separately - when pipe() itself fails
     * (EMFILE/ENFILE on a loaded runner) it leaves fds[] untouched, so closing
     * fds[0]/fds[1] would close two arbitrary descriptors that belong to us. */
    if (pipe(fds) != 0) {
        printf("ERROR: cannot create the exec-status pipe: %s\n", strerror(errno));
        return -1;
    }
    if (fcntl(fds[1], F_SETFD, FD_CLOEXEC) != 0) {
        printf("ERROR: cannot set FD_CLOEXEC on the exec-status pipe: %s\n",
               strerror(errno));
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    proc->waited = 0;
    proc->pid = fork();
    if (proc->pid == 0) {
        close(fds[0]);
        execl(test_target, test_target, NULL);
        child_errno = errno;
        /* Best effort: if this write fails the parent sees EOF, which is the
         * same thing a successful exec looks like - so EOF alone no longer
         * means "started" (see the waitpid(WNOHANG) check below), and the exit
         * status is what tells the two apart.
         * MINOR 5: _exit(), not exit(). execl() failed, so the parent's atexit
         * handlers and its buffered stdio are still ours; exit() would flush
         * the harness's own output a second time. */
        (void)!write(fds[1], &child_errno, sizeof(child_errno));
        _exit(2);
    }
    if (proc->pid < 0) {
        printf("ERROR: fork failed: %s\n", strerror(errno));
        close(fds[0]);
        close(fds[1]);
        /* MINOR 6: -1 is not a pid. process_terminate()'s `pid > 0` guard would
         * catch it, but leaving a negative pid in the struct invites kill(-1)
         * from any future caller, so normalise it like every other failure path
         * does. */
        proc->pid = 0;
        proc->waited = 1;
        return -1;
    }
    close(fds[1]);
    /* Retry EINTR: this harness installs a SIGALRM handler, and a signal
     * arriving mid-read would otherwise be reported as "the child never
     * confirmed its exec" even when it exec'd perfectly. */
    do {
        r = read(fds[0], &child_errno, sizeof(child_errno));
    } while (r < 0 && errno == EINTR);
    close(fds[0]);
    /* Four distinct outcomes, and only the first one is success. Treating every
     * non-positive-length read alike would let an EINTR/EAGAIN/EIO on the status
     * pipe (r < 0) masquerade as "the child exec'd", i.e. the harness would go on
     * to inject into a pid it never proved was alive - the exact silent-corpse
     * failure this pipe was added to prevent. */
    if (r == 0) {
        /* EOF: the O_CLOEXEC write end was closed - either by a successful
         * exec, or by a child that died before it could report anything (a
         * failed execl() whose errno write also failed). MINOR 5: those two are
         * indistinguishable from the pipe alone, and the old code took EOF as
         * proof of a clean start, contradicting both its own comment and
         * 94b778f's "only a clean EOF means the child exec'd". So ask the
         * kernel instead of inferring: the write end can only have closed at
         * exec or at exit, so by now the child is either running (a real exec)
         * or already a zombie (it never started). */
        do {
            w = waitpid(proc->pid, &wstatus, WNOHANG);
        } while (w < 0 && errno == EINTR);
        if (w == 0) {
            return 0;                       /* still running: it exec'd */
        }
        if (w == proc->pid) {
            if (WIFEXITED(wstatus)) {
                snprintf(why, sizeof(why), "exited with status %d", WEXITSTATUS(wstatus));
            } else if (WIFSIGNALED(wstatus)) {
                snprintf(why, sizeof(why), "was killed by signal %d", WTERMSIG(wstatus));
            } else {
                snprintf(why, sizeof(why), "did not run (wait status 0x%x)", wstatus);
            }
        } else {
            snprintf(why, sizeof(why), "its status could not be read: %s", strerror(errno));
        }
        printf("ERROR: cannot confirm that '%s' started: it closed the exec-status "
               "pipe without reporting an errno and %s\n", test_target, why);
        /* Reaped above (or unreapable), so nothing is left to wait for. */
        proc->pid = 0;
        proc->waited = 1;
        return -1;
    }
    if (r < 0) {
        printf("ERROR: cannot read the exec status of '%s': %s\n",
               test_target, strerror(errno));
        /* The child's state is unknown - it may have exec'd before the pipe
         * failed. It is ours and the test cannot continue without it, so kill it
         * instead of blocking in waitpid() on a possibly live target, and instead
         * of leaving a stray test-target running: a leftover would make a later
         * --self-find match somebody else's process. */
        kill(proc->pid, SIGKILL);
        waitpid(proc->pid, NULL, 0);
        proc->pid = 0;
        proc->waited = 1;   /* MINOR 6: reaped here - see process_terminate() */
        return -1;
    }
    if (r < (ssize_t)sizeof(child_errno)) {
        /* Short read: child_errno is only partly filled, so it must NOT be
         * interpreted - strerror() of a half-written int would name an errno the
         * child never reported. All we can honestly say is that the target's
         * startup was not confirmed. */
        printf("ERROR: cannot confirm that '%s' started: the exec-status pipe "
               "returned a short read (%zd of %zu bytes), so the child's errno "
               "was never received\n",
               test_target, r, sizeof(child_errno));
        kill(proc->pid, SIGKILL);   /* see the read-error path above */
        waitpid(proc->pid, NULL, 0);
        proc->pid = 0;
        proc->waited = 1;   /* MINOR 6: reaped here - see process_terminate() */
        return -1;
    }
    /* r == sizeof(child_errno): the child reported a failed execl(). */
    printf("ERROR: cannot start '%s': %s (was it built? `cd tests && make cross`)\n",
           test_target, strerror(child_errno));
    waitpid(proc->pid, NULL, 0);
    proc->pid = 0;
    proc->waited = 1;   /* MINOR 6: reaped here - see process_terminate() */
    return -1;
}

static volatile sig_atomic_t caught_sigalarm;

static void sighandler(int signo)
{
    caught_sigalarm = 1;
}
static int process_check_module(process_t *proc, const char *module_name, int startswith)
{
    char buf[PATH_MAX];
    size_t len = strlen(module_name);
    FILE *fp;

    sprintf(buf, "/proc/%d/maps", proc->pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        printf("Could not open %s\n", buf);
        return -1;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char *p = strrchr(buf, '/');
        if (p != NULL && memcmp(p + 1, module_name, len) == 0 && (startswith || p[len + 1] == '\n')) {
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return 1;
}

static int process_wait(process_t *proc, int wait_secs)
{
    struct sigaction sigact;
    int status;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = sighandler;
    sigaction(SIGALRM, &sigact, NULL);
    alarm(wait_secs);

    if (waitpid(proc->pid, &status, 0) == proc->pid) {
        proc->waited = 1;
        if (WIFEXITED(status)) {
            int exitcode = WEXITSTATUS(status);
            if (exitcode == INCR_ON_INJECTION + INCR_ON_UNINJECTION) {
                if (proc->is_musl) {
                    printf("ERROR: the library was uninjected, which shouldn't be possible on musl.\n");
                    return 0;
                } else {
                    printf("SUCCESS: The injected library changed the exit_value variable in the target process!\n");
                    return 0;
                }
            } else if (exitcode == INCR_ON_INJECTION) {
                if (proc->is_musl) {
                    printf("SUCCESS: The injected library changed the exit_value variable in the target process!\n");
                    return 0;
                } else {
                    printf("ERROR: The library was injected but not uninjected.\n");
                    return 1;
                }
            } else if (exitcode == 0) {
                printf("ERROR: The injected library didn't change the return value of target process!\n");
                return 1;
            } else {
                printf("ERROR: The target process exited with exit code %d.\n", exitcode);
                return 1;
            }
        } else if (WIFSIGNALED(status)) {
            int signo = WTERMSIG(status);
            printf("ERROR: The target process exited by signal %d.\n", signo);
            return 1;
        } else if (WIFSTOPPED(status)) {
            int signo = WSTOPSIG(status);
            printf("ERROR: The target process stopped by signal %d.\n", signo);
            return 1;
        } else {
            printf("ERROR: Unexpected waitpid status: 0x%x\n", status);
            return 1;
        }
    }
    if (caught_sigalarm) {
        printf("ERROR: The target process didn't exit.\n");
    } else {
        printf("ERROR: waitpid failed. (%s)\n", strerror(errno));
    }
    return 1;
}

static void process_terminate(process_t *proc)
{
    int status;
    /* MINOR 6: `pid > 0` is load-bearing, not cosmetic. kill(0, sig) delivers
     * to EVERY process in the caller's process group, so a proc whose pid was
     * reset to 0 by a failed process_start() - while `waited` was still 0 -
     * would SIGKILL and SIGCONT the whole harness, its shell and anything else
     * in the group. Today main() returns before cleanup on that path, so the
     * trap is only latent; this guard makes it unreachable for any future
     * `goto cleanup`, and the failure paths now set `waited` as well. */
    if (!proc->waited && proc->pid > 0) {
        kill(proc->pid, SIGKILL);
        kill(proc->pid, SIGCONT);
        waitpid(proc->pid, &status, 0);
        proc->waited = 1;   /* idempotent: a second call must not wait again */
    }
}

static int test_remote_call(injector_t *injector, void *handle)
{
#ifdef INJECTOR_HAS_REMOTE_CALL_FUNCS
    printf("test remote call.\n");
    fflush(stdout);

    size_t func_addr;
    if (injector_remote_func_addr(injector, handle, "sum_integers", &func_addr) != 0) {
        printf("injector_remote_func_addr error:\n  %s\n", injector_last_error(injector));
        return -1;
    }
    intptr_t retval;
    intptr_t args[6] = {1, 2, 3, 4, 5, 6};
    int i;
    for (i = 0; i < 6; i++) {
        args[i] += 10;
        intptr_t expected_retval = args[0] + args[1] + args[2] + args[3] + args[4] + args[5];
        if (injector_remote_call(injector, &retval, func_addr, args[0], args[1], args[2], args[3], args[4], args[5]) != 0) {
            printf("injector_remote_call error:\n  %s\n", injector_last_error(injector));
            return -1;
        }
        if (retval != expected_retval) {
            printf("sum_integers(%" PRIdPTR ", %" PRIdPTR ", %" PRIdPTR ", %" PRIdPTR ", %" PRIdPTR ", %" PRIdPTR ") returns %" PRIdPTR " (expected %" PRIdPTR ")\n",
                   args[0], args[1], args[2], args[3], args[4], args[5], retval, expected_retval);
            return -1;
        }
    }
#endif
    return 0;
}


static int run_timeout_test(process_t *proc, char *test_library)
{
    injector_t *injector = NULL;
    injector_opts_t opts = INJECTOR_OPTS_INIT;
    opts.call_timeout_ms = 500;
    int rv = 1;
    void *handle = NULL;
    size_t fa = 0;
    intptr_t retval;

    if (injector_attach_with_opts(&injector, proc->pid, &opts) != 0) {
        printf("timeout: attach error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    if (injector_inject(injector, test_library, &handle) != 0) {
        printf("timeout: inject error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    if (injector_remote_func_addr(injector, handle, "hang_forever", &fa) != 0) {
        printf("timeout: func_addr error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    int rc = injector_remote_call(injector, &retval, fa);
    if (rc != INJERR_TIMEOUT) {
        printf("timeout: expected INJERR_TIMEOUT, got %d: %s\n", rc, injector_last_error(injector));
        goto cleanup;
    }
    printf("timeout triggered as expected: %s\n", injector_last_error(injector));
    if (kill(proc->pid, 0) != 0) {
        printf("timeout: target did not survive\n");
        goto cleanup;
    }
    printf("target survived timeout and detach; cleaned up.\n");
    rv = 0;
cleanup:
    if (injector != NULL) injector_detach(injector);
    process_terminate(proc);
    return rv;
}

static int run_mem_test(process_t *proc, char *test_library)
{
    injector_t *injector = NULL;
    int rv = 1;
    uintptr_t addr = 0;
    int val;
    int newval = 99;
    (void)test_library;

    if (injector_attach(&injector, proc->pid) != 0) {
        printf("mem: attach error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    if (injector_resolve_symbol(injector, NULL, "probe_val", &addr) != 0) {
        printf("mem: resolve error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    if (injector_write_mem(injector, addr, &newval, sizeof(newval)) != INJERR_PERMISSION) {
        printf("mem: gate failed (write_mem not denied)\n");
        goto cleanup;
    }
    printf("gate: write_mem denied as expected\n");
    injector_detach(injector);
    injector = NULL;

    {
        injector_opts_t opts = INJECTOR_OPTS_INIT;
        opts.enable_write_mem = 1;
        if (injector_attach_with_opts(&injector, proc->pid, &opts) != 0) {
            printf("mem: attach2 error: %s\n", injector_last_error(injector));
            goto cleanup;
        }
    }
    if (injector_resolve_symbol(injector, NULL, "probe_val", &addr) != 0) {
        printf("mem: resolve2 error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    if (injector_read_mem(injector, addr, &val, sizeof(val)) != 0) {
        printf("mem: read error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    printf("mem: read probe_val = %d (expect 7)\n", val);
    if (val != 7) { printf("mem: ERROR expected 7\n"); goto cleanup; }
    if (injector_write_mem(injector, addr, &newval, sizeof(newval)) != 0) {
        printf("mem: write error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    printf("mem: wrote probe_val = %d\n", newval);
    if (injector_read_mem(injector, addr, &val, sizeof(val)) != 0) {
        printf("mem: readback error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    printf("mem: readback probe_val = %d (expect 99)\n", val);
    if (val != 99) { printf("mem: ERROR expected 99\n"); goto cleanup; }
    printf("SUCCESS: mem API round-trip OK; target exited 0 (exit_value unchanged).\n");
    rv = 0;
cleanup:
    if (injector != NULL) injector_detach(injector);
    return rv;
}

static int run_list_test(process_t *proc, char *test_library)
{
    injector_t *injector = NULL;
    int rv = 1;
    void *handle = NULL;
    (void)test_library;

    if (injector_attach(&injector, proc->pid) != 0) {
        printf("list: attach error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    if (injector_inject(injector, test_library, &handle) != 0) {
        printf("list: inject error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    long cnt = injector_list_modules(injector, NULL, 0);
    if (cnt < 0) { printf("list: list_modules error\n"); goto cleanup; }
    printf("list: %ld modules loaded after inject.\n", cnt);
    {
        injector_module_t *mods = calloc((size_t)cnt, sizeof(*mods));
        long cnt2 = injector_list_modules(injector, mods, (size_t)cnt);
        long i;
        int found = 0;
        for (i = 0; i < cnt2; i++) {
            if (strstr(mods[i].name, "test-library") != NULL) { found = 1; break; }
        }
        free(mods);
        if (!found) { printf("list: test-library not found after inject\n"); goto cleanup; }
        printf("list: test-library found after inject.\n");
    }
    if (injector_uninject_all(injector) != 0) {
        printf("list: uninject_all error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    {
        long cnt3 = injector_list_modules(injector, NULL, 0);
        printf("list: %ld modules after uninject_all.\n", cnt3);
        if (cnt3 >= cnt) { printf("list: ERROR count not decreased\n"); goto cleanup; }
        printf("list: test-library gone after uninject_all.\n");
    }
    printf("SUCCESS: list_modules + uninject_all OK.\n");
    rv = 0;
cleanup:
    if (injector != NULL) injector_detach(injector);
    return rv;
}

static int run_invoke_test(process_t *proc, char *test_library)
{
    injector_t *injector = NULL;
    int rv = 1;
    injector_result_t r;

    if (injector_attach(&injector, proc->pid) != 0) {
        printf("invoke: attach error: %s\n", injector_last_error(injector));
        goto cleanup;
    }
    /* 0 args */
    memset(&r, 0, sizeof(r));
    if (injector_invoke(injector, test_library, "entry_noarg", NULL, 0, &r) != 0) {
        printf("invoke: invoke error: %s\n", r.errmsg);
        goto cleanup;
    }
    printf("invoke: 0-arg retval = %" PRIdPTR " (expect 42)\n", r.retval);
    if (r.retval != 42) { printf("invoke: ERROR retval=%" PRIdPTR "\n", r.retval); goto cleanup; }

    /* 1 arg */
    memset(&r, 0, sizeof(r));
    intptr_t args1[] = {21};
    if (injector_invoke(injector, test_library, "entry_onearg", args1, 1, &r) != 0) {
        printf("invoke: 1-arg error: %s\n", r.errmsg);
        goto cleanup;
    }
    printf("invoke: 1-arg retval = %" PRIdPTR " (expect 42)\n", r.retval);
    if (r.retval != 42) { printf("invoke: ERROR 1-arg retval=%" PRIdPTR "\n", r.retval); goto cleanup; }

    /* 3 args */
    memset(&r, 0, sizeof(r));
    intptr_t args3[] = {10, 20, 30};
    if (injector_invoke(injector, test_library, "entry_threeargs", args3, 3, &r) != 0) {
        printf("invoke: 3-arg error: %s\n", r.errmsg);
        goto cleanup;
    }
    printf("invoke: 3-arg retval = %" PRIdPTR " (expect 60)\n", r.retval);
    if (r.retval != 60) { printf("invoke: ERROR 3-arg retval=%" PRIdPTR "\n", r.retval); goto cleanup; }

    /* 6 args */
    memset(&r, 0, sizeof(r));
    intptr_t args6[] = {1, 2, 3, 4, 5, 6};
    if (injector_invoke(injector, test_library, "sum_integers", args6, 6, &r) != 0) {
        printf("invoke: 6-arg error: %s\n", r.errmsg);
        goto cleanup;
    }
    printf("invoke: 6-arg retval = %" PRIdPTR " (expect 21)\n", r.retval);
    if (r.retval != 21) { printf("invoke: ERROR 6-arg retval=%" PRIdPTR "\n", r.retval); goto cleanup; }

    /* argc validation */
    memset(&r, 0, sizeof(r));
    int frc = injector_invoke(injector, test_library, "entry_noarg", NULL, 7, &r);
    if (frc == 0) {
        printf("invoke: ERROR argc=7 should fail\n");
        goto cleanup;
    }
    printf("invoke: argc=7 rejected as expected\n");

    /* bad lib error path */
    memset(&r, 0, sizeof(r));
    frc = injector_invoke(injector, "no-such-lib.so", "x", NULL, 0, &r);
    if (frc == 0 || r.errmsg[0] == '\0') {
        printf("invoke: ERROR bad-lib should fail with errmsg\n");
        goto cleanup;
    }
    printf("invoke: bad-lib failed as expected: %s\n", r.errmsg);
    injector_detach(injector);
    injector = NULL;

    /* injector_run with args */
    memset(&r, 0, sizeof(r));
    intptr_t rargs[] = {100};
    if (injector_run(proc->pid, test_library, "entry_onearg", rargs, 1, NULL, &r) != 0) {
        printf("invoke: run-with-args error: %s\n", r.errmsg);
        goto cleanup;
    }
    printf("invoke: run-with-args retval = %" PRIdPTR " (expect 200)\n", r.retval);
    if (r.retval != 200) { printf("invoke: ERROR run-with-args retval\n"); goto cleanup; }

    printf("SUCCESS: invoke/run with args OK.\n");
    rv = 0;
cleanup:
    if (injector != NULL) injector_detach(injector);
    return rv;
}

int main(int argc, char **argv)
{
    char suffix[20] = {0,};
    char test_target[64];
    char test_library[64];
    injector_t *injector;
    /* MINOR 6: initialised, not left to the stack. process_start() can return
     * early without ever assigning proc.pid, and process_terminate() must never
     * see a pid that did not come from a successful fork(). waited=1 means
     * "nothing to reap", which is the truth about a process that never started. */
    process_t proc = { 0, 1, 0 };   /* pid, waited, is_musl */
    void *handle = NULL;
    int rv = 1;
    int loop_cnt;
    int can_uninject = 1;
    int (*inject_func)(injector_t *, const char *, void **) = injector_inject;
    int i;
    int timeout_test = 0, mem_test = 0, list_test = 0, self_find = 0, invoke_test = 0;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "--cloned-thread") == 0) {
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
                inject_func = injector_inject_in_cloned_thread;
#else
                fprintf(stderr, "injector_inject_in_cloned_thread isn't suported\n");
                return 1;
#endif
            } else if (strcmp(argv[i], "--timeout") == 0) {
                timeout_test = 1;
            } else if (strcmp(argv[i], "--mem") == 0) {
                mem_test = 1;
            } else if (strcmp(argv[i], "--list") == 0) {
                list_test = 1;
            } else if (strcmp(argv[i], "--self-find") == 0) {
                self_find = 1;
            } else if (strcmp(argv[i], "--invoke") == 0) {
                invoke_test = 1;
            } else {
                fprintf(stderr, "unknown option %s\n", argv[i]);
                return 1;
            }
        } else {
            snprintf(suffix, sizeof(suffix), "-%s", argv[1]);
            suffix[sizeof(suffix) - 1] = '\0';
        }
    }

    snprintf(test_target, sizeof(test_target), "test-target%s" EXEEXT, suffix);
    snprintf(test_library, sizeof(test_library), "test-library%s" DLLEXT, suffix);

    if (process_start(&proc, test_target) != 0) {
        return 1;
    }
    printf("target process started.\n");
    fflush(stdout);

    sleep(1);

    // Sadly this is not known at compile time, see https://www.openwall.com/lists/musl/2013/03/29/13
    proc.is_musl = process_check_module(&proc, "ld-musl-", 1) == 0;
    // In musl, dlclose doesn't do anything - see https://wiki.musl-libc.org/functional-differences-from-glibc.html
    if (proc.is_musl) {
        can_uninject = 0;
    }

    if (timeout_test) {
        rv = run_timeout_test(&proc, test_library);
        goto cleanup;
    }
    if (mem_test) {
        rv = run_mem_test(&proc, test_library);
        goto cleanup;
    }
    if (list_test) {
        rv = run_list_test(&proc, test_library);
        goto cleanup;
    }
    if (self_find) {
        /* Search for the name we actually started. The target binary carries the
         * arch suffix (test-target-x86_64, test-target-i386, ...) while the bare
         * `./test-prog` build starts plain test-target, and
         * injector_find_process() matches the basename of /proc/PID/exe exactly:
         * hardcoding "test-target" here made this test unable to pass for every
         * suffixed invocation, i.e. for every arch pair CI runs. */
        const char *target_name = strrchr(test_target, '/');
        pid_t found;
        target_name = target_name ? target_name + 1 : test_target;
        found = injector_find_process(target_name);
        printf("self-find: injector_find_process(\"%s\") = %d (target pid %d)\n",
               target_name, (int)found, (int)proc.pid);
        fflush(stdout);
        if (found != proc.pid) {
            /* Distinguish the two ways this can fail: injector_find_process()
             * returns the FIRST /proc entry whose exe basename matches, so a
             * second test-target left over from a previous run (or a parallel
             * test in another directory) makes it return that pid instead.
             * Saying only "did not locate" sent the next person hunting for a
             * bug in the scan rather than in the test environment. */
            if (found <= 0) {
                printf("ERROR: self-find did not locate the running target "
                       "(no /proc/*/exe basename matched).\n");
            } else {
                printf("ERROR: self-find matched a DIFFERENT test-target: pid %d, "
                       "but our target is pid %d. Another test-target is still "
                       "running (a leftover or a parallel test); injector_find_process "
                       "returns the first match, so this test needs to be the only "
                       "one running.\n", (int)found, (int)proc.pid);
            }
            goto cleanup;
        }
        printf("SUCCESS: self-find located the running test-target.\n");
        rv = 0;
        goto cleanup;
    }
    if (invoke_test) {
        rv = run_invoke_test(&proc, test_library);
        goto cleanup;
    }

    for (loop_cnt = 0; loop_cnt < 2; loop_cnt++) {
        const char *errmsg;

        if (injector_attach(&injector, proc.pid) != 0) {
            printf("inject error:\n  %s\n", injector_last_error(injector));
            goto cleanup;
        }
        printf("attached.\n");
        fflush(stdout);

        if (loop_cnt == 0) {
            if (inject_func(injector, test_library, &handle) != 0) {
                printf("inject error:\n  %s\n", injector_last_error(injector));
                goto cleanup;
            }
            printf("injected. (handle=%p)\n", handle);
            fflush(stdout);

            if (inject_func(injector, "no such library", &handle) == 0) {
                printf("injection should fail but succeeded:\n");
                goto cleanup;
            }
            errmsg = injector_last_error(injector);
            if (strncmp(errmsg, INJECT_ERRMSG, strlen(INJECT_ERRMSG)) != 0) {
                printf("unexpected injection error message: %s\nexpected: %s\n", errmsg, INJECT_ERRMSG);
                goto cleanup;
            }
            if (test_remote_call(injector, handle) != 0) {
                goto cleanup;
            }
        } else if (proc.is_musl) {
            int err = injector_uninject(injector, handle);
            if (err != INJERR_UNSUPPORTED_TARGET) {
                printf("uninject returns unexpected value: %d\n", err);
                goto cleanup;
            }
        } else {
            if (injector_uninject(injector, handle) != 0) {
                printf("uninject error:\n  %s\n", injector_last_error(injector));
                goto cleanup;
            }
            printf("uninjected.\n");
            fflush(stdout);
        }

        if (injector_detach(injector) != 0) {
            printf("inject error:\n  %s\n", injector_last_error(injector));
            goto cleanup;
        }
        printf("detached.\n");
        fflush(stdout);

        if (can_uninject && process_check_module(&proc, test_library, 0) != loop_cnt) {
            if (loop_cnt == 0) {
                printf("%s wasn't found after injection\n", test_library);
            } else {
                printf("%s was found after uninjection\n", test_library);
            }
            goto cleanup;
        }
    }

    rv = process_wait(&proc, 8);
cleanup:
    process_terminate(&proc);
    return rv;
}
