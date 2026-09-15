/* test_handles.c - the two per-thread resource tables and ptrace's thread
 * affinity, driven black-box against throwaway targets.
 *
 * What is covered here that had no automated test at all:
 *
 *   1. ptrace.c's FP-state slots. fp_slot_acquire() deliberately does NOT evict:
 *      a non-free slot always belongs to a handle that is attached right now,
 *      and stealing it would leave that target's FP/vector state unrestorable.
 *      So the FP_SLOTS+1'th attach on one thread must be REFUSED - before any
 *      register is touched - with INJERR_OTHER/EMFILE and a message that names
 *      the remedy, and the refused target must be left runnable and untraced.
 *   2. remote_call.c's desync table. A marker for a LIVE pid is never evicted
 *      either; when DESYNC_SLOTS is full the new marker is dropped and
 *      `desync_lossy` latches, which makes injector__handle_is_desynced()
 *      answer "desynced" for EVERY pid in that thread. Latching is permanent by
 *      design (no later event can prove the pid that lost its marker safe), and
 *      both functions are exported non-static, so the whole thing is testable
 *      without desyncing a real target.
 *   3. Thread affinity. ptrace tracer ownership is per-thread, so a handle
 *      driven from another thread cannot work; every ptrace-issuing operation
 *      must refuse up front and name both tids. Also asserted: what the refusal
 *      does NOT fix - the target stays stopped and traced, and is only released
 *      when the thread that attached detaches it or exits.
 *
 * ONE THREAD, and why that is a requirement rather than a preference: the FP
 * slots and the desync table are both `__thread`. Marks and assertions about
 * them have to happen on the same thread or the test proves nothing - a marker
 * stored in a helper thread's table is invisible to the main thread's
 * is_desynced(), and an attach in one thread takes its FP slot out of another
 * thread's four. Parts 1 and 2 therefore run entirely on the thread that calls
 * test_handle_limits_and_affinity(); part 3 uses helper threads only where two
 * threads are the thing under test, and it too does each handle's work on one
 * thread at a time. Nothing is delegated to a thread that then hides the state:
 * every assertion below reads the table the marks were written to.
 *
 * SAFETY. Every target is a child this test forks itself (never pid 1, never a
 * pid it does not own), no target is exec'd, and every child is SIGKILLed and
 * reaped before this function returns - including on the assertion-failure
 * paths, which is why the parts below count failures instead of returning early
 * the way MU_ASSERT does. A target left ptrace-stopped is killed rather than
 * waited on, and no wait in here is unbounded.
 */
#include "minunit.h"
#include "injector.h"

#include <dlfcn.h>      /* RTLD_DEFAULT */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h> /* SYS_gettid */
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* remote_call.c exports both non-static so that ptrace.c and injector.c can
 * reach them; they are not in injector_internal.h, so declare them the way
 * those translation units declare each other's internals. */
void injector__handle_mark_desynced(pid_t pid);
int injector__handle_is_desynced(pid_t pid);

/* These two bounds live in the .c files, not in a header, so they are spelled
 * out here. That is deliberate: the tests below probe the boundary itself, so a
 * change to either constant turns into a failed assertion naming the number
 * that was expected, rather than a silently weaker test. */
#define FP_SLOTS_EXPECTED     4    /* ptrace.c:     #define FP_SLOTS      4   */
#define DESYNC_SLOTS_EXPECTED 40   /* remote_call.c:#define DESYNC_SLOTS  40  */

/* Counted, not returned-early: see SAFETY above. */
static int checks_run;
static int checks_failed;

/* Per-part delta, printed so a failure is attributable to the part that made
 * it: the three parts assert very different things and a bare total is not
 * enough to tell a wedged FP slot from a latched desync table. */
#define PART_BEGIN() do { part_base = checks_run; part_bad = checks_failed; } while (0)
#define PART_END(name) do {                                                \
        fprintf(stderr, "    %-24s %2d checks, %d failed\n", (name),       \
                checks_run - part_base, checks_failed - part_bad);          \
    } while (0)
static int part_base;
static int part_bad;

#define CHECK(cond) do {                                                   \
        checks_run++;                                                      \
        if (!(cond)) {                                                     \
            checks_failed++;                                               \
            fprintf(stderr, "    assert failed: %s (%s:%d)\n",             \
                    #cond, __FILE__, __LINE__);                            \
        }                                                                  \
    } while (0)

static pid_t this_tid(void)
{
#ifdef SYS_gettid
    long t = syscall(SYS_gettid);
    return (t > 0) ? (pid_t)t : 0;
#else
    return 0;
#endif
}

/* A throwaway target: a fork of this test process that does nothing. Not
 * exec'd, so it has this binary's own libc mapping (which is what an attach
 * resolves symbols in), and it is our child, so both Yama's ptrace_scope=1 and
 * the reaping at the end are satisfied. Returns -1 on failure. */
static pid_t spawn_sleeper(void)
{
    pid_t p = fork();
    if (p == 0) {
        /* pause() only: async-signal-safe, no stdio, no exit handlers, so this
         * child cannot interfere with the parent's atexit state or buffers. */
        for (;;) {
            pause();
        }
    }
    return p;
}

/* SIGKILL and reap one of our own children. Bounded: a stopped tracee still
 * takes SIGKILL, so this cannot hang, and a child that is already gone is
 * reaped with WNOHANG. */
static void kill_and_reap(pid_t p)
{
    int i;

    if (p <= 1) {
        return;                      /* never signal pid 1, not even by accident */
    }
    kill(p, SIGKILL);
    for (i = 0; i < 200; i++) {
        int st = 0;
        pid_t w = waitpid(p, &st, WNOHANG);
        if (w == p || (w == -1 && errno == ECHILD)) {
            return;
        }
        usleep(10000);
    }
    /* Not reaped in 2s: it is still ours and still SIGKILLed, so the parent's
     * eventual exit reaps it. Reported rather than hidden. */
    fprintf(stderr, "    warning: pid %d was not reaped within 2s\n", (int)p);
}

/* State and TracerPid from /proc/<pid>/status. 0 on success. */
static int proc_status(pid_t p, char *state, long *tracerpid)
{
    char path[64], line[256];
    FILE *f;
    int got_state = 0, got_tracer = 0;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)p);
    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (state != NULL && !got_state && strncmp(line, "State:", 6) == 0) {
            const char *v = line + 6;
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            *state = *v;
            got_state = 1;
        } else if (tracerpid != NULL && !got_tracer && strncmp(line, "TracerPid:", 10) == 0) {
            *tracerpid = strtol(line + 10, NULL, 10);
            got_tracer = 1;
        }
    }
    fclose(f);
    return (state == NULL || got_state) && (tracerpid == NULL || got_tracer) ? 0 : -1;
}

/* ---------------------------------------------------------------- part 1 ---
 * The FP-slot EMFILE refusal. All five attaches happen on THIS thread, because
 * the slots are __thread: from anywhere else the count would start at zero. */
static void part_fp_slots(void)
{
    pid_t kids[FP_SLOTS_EXPECTED + 1];
    injector_t *inj[FP_SLOTS_EXPECTED];
    injector_t *fifth = NULL;
    int i, nkids = 0, ninj = 0;
    int rv;

    PART_BEGIN();

    for (i = 0; i < FP_SLOTS_EXPECTED + 1; i++) {
        kids[i] = spawn_sleeper();
        if (kids[i] <= 1) {
            CHECK(kids[i] > 1);
            kids[i] = 0;
            continue;
        }
        nkids++;
    }
    if (nkids < FP_SLOTS_EXPECTED + 1) {
        fprintf(stderr, "    could not fork %d targets; FP-slot part not run\n",
                FP_SLOTS_EXPECTED + 1);
        for (i = 0; i < FP_SLOTS_EXPECTED + 1; i++) {
            kill_and_reap(kids[i]);
        }
        PART_END("fp-slot refusal (not run)");
        return;
    }

    /* The first FP_SLOTS attaches must all succeed. */
    for (i = 0; i < FP_SLOTS_EXPECTED; i++) {
        inj[i] = NULL;
        rv = injector_attach(&inj[i], kids[i]);
        if (rv != 0) {
            fprintf(stderr, "    attach #%d (pid %d) failed rv=%d: %s\n", i + 1,
                    (int)kids[i], rv, injector_last_error(inj[i]));
        }
        CHECK(rv == 0);
        CHECK(inj[i] != NULL);
        if (rv == 0) {
            ninj++;
        }
    }

    /* The FP_SLOTS+1'th must be REFUSED, with the specific error: not merely
     * non-zero, and not a generic failure. INJERR_OTHER is the code the refusal
     * documents (nothing here is the target's capability, and no allocation
     * failed), and the message has to name the FP slots and the remedy.
     * errno is deliberately NOT asserted: error_exit runs injector_detach()
     * after the refusal, and PTRACE_DETACH leaves its own errno behind. */
    fifth = (injector_t *)(size_t)0x1;   /* must be NULLed, not left dangling */
    rv = injector_attach(&fifth, kids[FP_SLOTS_EXPECTED]);
    CHECK(rv == INJERR_OTHER);
    CHECK(fifth == NULL);
    {
        /* Attach-phase errors land in the thread-local buffer, because
         * current_inj stays NULL until the attach succeeds - hence NULL here. */
        const char *msg = injector_last_error(NULL);
        CHECK(msg != NULL);
        if (msg != NULL) {
            CHECK(strstr(msg, "FP-state slots") != NULL);
            CHECK(strstr(msg, "already holds") != NULL);
            CHECK(strstr(msg, "Detach one of this thread's handles") != NULL);
            /* It must not claim the TARGET is at fault. */
            CHECK(strstr(msg, "unsupported") == NULL);
        }
    }

    /* The refused target must be left runnable and untraced: the attach unwound
     * through PTRACE_DETACH, so it is neither stopped nor holding a TracerPid.
     * Leaving it in state 't' would be exactly the wedged target this suite is
     * not allowed to produce. */
    {
        char st = '?';
        long tp = -1;
        CHECK(proc_status(kids[FP_SLOTS_EXPECTED], &st, &tp) == 0);
        CHECK(st == 'S' || st == 'R');
        CHECK(tp == 0);
    }

    /* The four accepted handles must still WORK - a slot table that had been
     * disturbed would show up here, not in the attach. A remote dlsym is the
     * strongest cheap proof: it patches the trampoline, hijacks the registers
     * and restores both, which is what the FP slots exist to protect. */
    for (i = 0; i < ninj; i++) {
        size_t addr = 0;
        rv = injector_remote_func_addr(inj[i], RTLD_DEFAULT, "getpid", &addr);
        if (rv != 0) {
            fprintf(stderr, "    remote_func_addr on handle #%d failed rv=%d: %s\n",
                    i + 1, rv, injector_last_error(inj[i]));
        }
        CHECK(rv == 0);
        CHECK(addr != 0);
    }

    /* Detaching one frees a slot, and the previously refused attach then
     * succeeds - i.e. the refusal was about the table being full, not about the
     * target. */
    if (ninj > 0) {
        CHECK(injector_detach(inj[0]) == 0);
        inj[0] = NULL;
        fifth = NULL;
        rv = injector_attach(&fifth, kids[FP_SLOTS_EXPECTED]);
        if (rv != 0) {
            fprintf(stderr, "    re-attach after detach failed rv=%d: %s\n", rv,
                    injector_last_error(fifth));
        }
        CHECK(rv == 0);
        if (rv == 0) {
            CHECK(injector_detach(fifth) == 0);
        }
        /* Sweep every slot and skip the empty ones, rather than indexing
         * 1..ninj-1: ninj counts SUCCESSES, so if an early attach failed the
         * successful handles sit at higher indices and inj[1..ninj-1] can be
         * NULL or the wrong element. Detaching a NULL handle would add a
         * spurious CHECK failure on top of the real one and hide it. */
        for (i = 0; i < FP_SLOTS_EXPECTED; i++) {
            if (inj[i] == NULL) {
                continue;           /* that attach failed: nothing to detach */
            }
            CHECK(injector_detach(inj[i]) == 0);
            inj[i] = NULL;
        }
    }

    /* Every target back to runnable and untraced, then reaped. */
    for (i = 0; i < FP_SLOTS_EXPECTED + 1; i++) {
        char st = '?';
        long tp = -1;
        if (proc_status(kids[i], &st, &tp) == 0) {
            CHECK(st != 'T' && st != 't');
            CHECK(tp == 0);
        }
        kill_and_reap(kids[i]);
    }
    PART_END("fp-slot refusal");
}

/* ---------------------------------------------------------------- part 3 ---
 * Thread affinity. Run before part 2, because part 2 permanently latches this
 * thread's desync table and a latched thread refuses every remote call - which
 * would make the "the first four still work" style checks above and the
 * successful attach here fail for an unrelated reason. */
struct aff_ctx {
    pid_t target;
    injector_t *inj;
    pid_t a_tid;          /* the thread that attached */
    pid_t b_tid;          /* the thread that must be refused */
    int phase;            /* 0 init, 1 attached, 2 B done, 3 A may finish */
    int op;               /* 0 = remote call, 1 = detach */
    int b_rc;
    char b_msg[512];
    int a_rc;
};

static void *affinity_thread(void *arg)
{
    struct aff_ctx *c = arg;
    int rv;

    c->a_tid = this_tid();
    rv = injector_attach(&c->inj, c->target);
    c->a_rc = rv;
    c->phase = 1;
    if (rv != 0) {
        return NULL;
    }
    while (c->phase != 2) {
        usleep(2000);
    }
    if (c->op == 0) {
        /* This thread owns the handle: detach it properly, so the target is
         * left restored and runnable. */
        c->a_rc = injector_detach(c->inj);
        c->inj = NULL;
        c->phase = 3;
    } else {
        /* Deliberately exit WITHOUT detaching: injector_detach() from thread B
         * has already been refused and has destroyed the handle, so the only
         * thing left that can release the target is this thread going away.
         * What that does is asserted by the caller. */
        c->phase = 3;
    }
    return NULL;
}

static void *affinity_wrong_thread(void *arg)
{
    struct aff_ctx *c = arg;
    const char *msg;
    size_t addr = 0;

    c->b_tid = this_tid();
    if (c->op == 0) {
        c->b_rc = injector_remote_func_addr(c->inj, RTLD_DEFAULT, "getpid", &addr);
    } else {
        c->b_rc = injector_detach(c->inj);
        if (c->b_rc == 0) {
            c->inj = NULL;      /* it really did detach: the assertions will say so */
        }
    }
    /* Which buffer holds the message depends on the call: injector_detach()
     * clears current_inj before doing anything (so that its errors do not
     * dangle after it frees the handle) and therefore reports through the
     * THREAD-LOCAL buffer, while injector_remote_func_addr() sets current_inj
     * to the handle and reports through the handle's. Reading the handle's
     * buffer after a detach - even a refused one - would be a use-after-free. */
    msg = (c->op == 1) ? injector_last_error(NULL) : injector_last_error(c->inj);
    snprintf(c->b_msg, sizeof(c->b_msg), "%s", msg ? msg : "");
    return NULL;
}

static void part_affinity(int op)
{
    struct aff_ctx c;
    pthread_t ta, tb;
    int i;
    char label[48];

    PART_BEGIN();
    snprintf(label, sizeof(label), "affinity (op=%s)", op == 0 ? "call" : "detach");
    memset(&c, 0, sizeof(c));
    c.op = op;
    c.target = spawn_sleeper();
    if (c.target <= 1) {
        CHECK(c.target > 1);
        PART_END(label);
        return;
    }
    if (pthread_create(&ta, NULL, affinity_thread, &c) != 0) {
        fprintf(stderr, "    pthread_create failed; affinity part (op=%d) not run\n", op);
        /* Must COUNT as a failure. The harness tallies only checks_failed, so a
         * part that returns without running a single CHECK is a vacuous PASS:
         * under a thread limit (EAGAIN) this suite would report "0 failed" while
         * asserting nothing about affinity at all. Same reason both fork-failure
         * paths above do CHECK. */
        CHECK(0 /* pthread_create for the attaching thread */);
        kill_and_reap(c.target);
        PART_END(label);
        return;
    }
    for (i = 0; i < 1000 && c.phase != 1; i++) {
        usleep(2000);
    }
    CHECK(c.phase == 1);
    CHECK(c.a_rc == 0);
    CHECK(c.inj != NULL);
    if (c.phase != 1 || c.a_rc != 0 || c.inj == NULL) {
        c.phase = 2;
        pthread_join(ta, NULL);
        kill_and_reap(c.target);
        PART_END(label);
        return;
    }
    CHECK(c.a_tid != this_tid());     /* a real second thread, not this one */

    if (pthread_create(&tb, NULL, affinity_wrong_thread, &c) != 0) {
        fprintf(stderr, "    pthread_create failed; affinity part (op=%d) not run\n", op);
        CHECK(0 /* pthread_create for the WRONG thread - the refusal never tested */);
        c.phase = 2;
        pthread_join(ta, NULL);
        /* Nothing can be detached from here; thread A exiting is what releases
         * the target, and kill_and_reap() covers the rest. */
        kill_and_reap(c.target);
        PART_END(label);
        return;
    }
    pthread_join(tb, NULL);

    /* The specific refusal: INJERR_OTHER, errno-free assertion aside, with a
     * message that names BOTH tids and says why - not the ESRCH-flavoured
     * "PTRACE_SETREGS error: No such process" this used to produce. */
    CHECK(c.b_rc == INJERR_OTHER);
    CHECK(strstr(c.b_msg, "per-THREAD") != NULL);
    {
        char want[64];
        /* Not a bare "thread %d". The refusal message contains the word
         * "thread" three times and the OWNER's tid twice ("attached by thread
         * %d" and "Drive this handle ... from thread %d"), and one tid can be a
         * numeric prefix of the other (1234 inside 12345), so a bare substring
         * can be satisfied by the wrong field's occurrence - both checks could
         * pass off a single number. Anchor each needle to the text surrounding
         * its own field. */
        snprintf(want, sizeof(want), "attached by thread %d and ptrace tracer", (int)c.a_tid);
        CHECK(strstr(c.b_msg, want) != NULL);
        snprintf(want, sizeof(want), "This is thread %d, from which the kernel", (int)c.b_tid);
        CHECK(strstr(c.b_msg, want) != NULL);
    }
    CHECK(c.b_tid != 0 && c.b_tid != c.a_tid);

    /* What the refusal does NOT fix, asserted rather than assumed: the target is
     * still stopped and still traced by thread A. */
    {
        char st = '?';
        long tp = -1;
        if (op == 0 && proc_status(c.target, &st, &tp) == 0) {
            CHECK(st == 't' || st == 'T');
            CHECK(tp == (long)c.a_tid);
        }
    }

    c.phase = 2;
    pthread_join(ta, NULL);

    if (op == 0) {
        /* Thread A owns the handle and detaches it: the target must come back
         * runnable and untraced. */
        CHECK(c.a_rc == 0);
    } else {
        /* The handle is gone (injector_detach destroys it whether or not the
         * detach worked) and thread A has now exited without detaching. The
         * kernel releases a tracee when its tracer thread exits; assert that,
         * bounded, because it is the only recovery the message advertises. */
        int released = 0;
        for (i = 0; i < 300; i++) {
            char st = '?';
            long tp = -1;
            if (proc_status(c.target, &st, &tp) != 0) {
                released = 1;      /* gone entirely: also released */
                break;
            }
            if (tp == 0 && st != 't' && st != 'T') {
                released = 1;
                break;
            }
            usleep(10000);
        }
        CHECK(released == 1);
    }
    kill_and_reap(c.target);
    PART_END(label);
}

/* ---------------------------------------------------------------- part 2 ---
 * The 40-slot desync latch. LAST, and on this thread: latching is permanent, so
 * after this runs this thread can make no remote call at all - which is the
 * point of the latch. Any test added after this one that attaches for real must
 * run on its own thread or it will be refused with the lossy-table message.
 *
 * Only LIVE pids are marked, because desync_reclaim_dead() drops a marker whose
 * pid is provably gone: marking dead pids would never fill the table and the
 * latch would never engage, i.e. the test would pass while proving nothing. */
static void part_desync_latch(void)
{
    enum { N = DESYNC_SLOTS_EXPECTED };
    pid_t kids[N + 1];
    pid_t unmarked;
    int i, live = 0;

    PART_BEGIN();

    for (i = 0; i <= N; i++) {
        kids[i] = spawn_sleeper();
        if (kids[i] > 1) {
            live++;
        } else {
            kids[i] = 0;
        }
    }
    unmarked = spawn_sleeper();
    if (live <= N || unmarked <= 1) {
        fprintf(stderr, "    could not fork %d targets; desync part not run\n", N + 2);
        CHECK(live > N);
        for (i = 0; i <= N; i++) {
            kill_and_reap(kids[i]);
        }
        kill_and_reap(unmarked);
        PART_END("desync latch (not run)");
        return;
    }

    /* Pre-latch behaviour: below DESYNC_SLOTS markers, a pid that was never
     * marked is NOT reported desynced. Without this the latch assertions below
     * would also pass on a table that simply answers yes to everything. */
    injector__handle_mark_desynced(kids[0]);
    CHECK(injector__handle_is_desynced(kids[0]) == 1);
    CHECK(injector__handle_is_desynced(unmarked) == 0);
    for (i = 1; i < N - 1; i++) {
        injector__handle_mark_desynced(kids[i]);
    }
    CHECK(injector__handle_is_desynced(kids[N - 2]) == 1);
    CHECK(injector__handle_is_desynced(unmarked) == 0);      /* N-1 markers, no latch */

    /* Exactly DESYNC_SLOTS live markers: the table is full but not lossy yet. */
    injector__handle_mark_desynced(kids[N - 1]);
    CHECK(injector__handle_is_desynced(kids[N - 1]) == 1);
    CHECK(injector__handle_is_desynced(unmarked) == 0);

    /* The DESYNC_SLOTS+1'th live pid: nothing may be evicted, so the new marker
     * is dropped and desync_lossy latches - from here on EVERY pid in this
     * thread is reported desynced, including one that was never marked. */
    injector__handle_mark_desynced(kids[N]);
    CHECK(injector__handle_is_desynced(unmarked) == 1);
    CHECK(injector__handle_is_desynced(kids[N]) == 1);

    /* Stickiness is the whole point: no later event can prove the pid that lost
     * its marker safe, so killing every marked pid - which frees every slot via
     * desync_reclaim_dead() - must NOT clear the latch. */
    for (i = 0; i <= N; i++) {
        if (kids[i] > 1) {
            kill(kids[i], SIGKILL);
        }
    }
    for (i = 0; i <= N; i++) {
        if (kids[i] > 1) {
            int st = 0;
            waitpid(kids[i], &st, 0);
            kids[i] = 0;
        }
    }
    CHECK(injector__handle_is_desynced(unmarked) == 1);
    CHECK(injector__handle_is_desynced(kids[0]) == 1);

    /* And a later mark, now that slots are free again, still does not clear it. */
    injector__handle_mark_desynced(unmarked);
    CHECK(injector__handle_is_desynced(unmarked) == 1);

    kill_and_reap(unmarked);
    PART_END("desync latch");
}

int test_handle_limits_and_affinity(void)
{
    checks_run = 0;
    checks_failed = 0;

    part_fp_slots();
    part_affinity(0);   /* remote call from the wrong thread */
    part_affinity(1);   /* detach from the wrong thread */
    part_desync_latch();

    fprintf(stderr, "    test_handles: %d checks, %d failed\n", checks_run, checks_failed);
    return (checks_failed != 0) ? 1 : 0;
}
