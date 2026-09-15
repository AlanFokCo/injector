/* Harness for injector__nonstop_orphan_kill(): the scan that finds and SIGKILLs
 * a CLONE_VM helper whose pid was lost with the target.
 *
 * WHY THIS FILE EXISTS. That function is exported non-static precisely so a
 * harness can drive it, because its interesting branches - zero match, unique
 * match, ambiguous match, and each "decline" - cannot be reached deterministically
 * through the public API: they need a chosen number of mm-sharers at a chosen
 * instant. Until now no harness was committed, so 0 unit checks touched it and
 * deleting any of its safety gates was a green `make unit`. Every gate below is
 * asserted, including the two that stop the scan killing something it should not:
 *
 *   - a CLONE_VM sharer that is NOT our helper (what a vfork()/posix_spawn()/
 *     system()/popen() child of the target looks like) must be VETOED by the
 *     recorded-pid check and must survive. kcmp(KCMP_VM)==0 alone matches it.
 *   - a missing pre-clone start stamp (t0_ticks == 0) or an unknown
 *     thread-group leader must DECLINE the scan, because those are exactly the
 *     two gates that keep the target's own process out of the candidate set.
 *
 * SAFETY. Nothing here ptraces anything, and no candidate can be a bystander:
 * the scan only ever considers a process that shares THIS process's mm (our own
 * clone(CLONE_VM) children) or that reads back our nonce at our scratch address.
 * Every child is a throwaway we created, and every child is killed and reaped
 * inside its own case, so a later case can never see a stray mm-sharer and
 * mistake it for ambiguity. pid <= 1 is never passed as a target.
 *
 * Determinism: every assertion below holds whether or not kcmp(2) is usable
 * (it needs CONFIG_CHECKPOINT_RESTORE and ptrace permission). Where the two
 * discriminators disagree about the ROUTE to a verdict they still agree on the
 * verdict, so no case counts a skip - the suite treats a skip as a failure. */

/* clone(2), CLONE_VM and MAP_STACK are all GNU extensions on Linux. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "minunit.h"
#include "injector_internal.h"

#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Exported non-static for this harness; not part of the public ABI, and not in
 * injector_internal.h. Mirrors the definition in src/linux/injector.c. */
int injector__nonstop_orphan_kill(injector_t *inj, pid_t target, pid_t target_tgid,
                                  unsigned long long t0_ticks, int pidns_shared,
                                  unsigned long long nonce, pid_t *found_out,
                                  char *note, size_t note_len);

#define SCAN_SCRATCH_BYTES 16      /* injector.c: NONSTOP_SCRATCH_BYTES */
#define FAKE_PAGE_SIZE     4096
#define CHILD_STACK_SIZE   (256 * 1024)

static int checks_run;
static int checks_failed;
static int part_base;
static int part_bad;

#define PART_BEGIN() do { part_base = checks_run; part_bad = checks_failed; } while (0)
#define PART_END(name) do {                                                \
        fprintf(stderr, "    %-26s %2d checks, %d failed\n", (name),       \
                checks_run - part_base, checks_failed - part_bad);         \
    } while (0)

/* Counted, never returned-early: a part that bails out without a CHECK is a
 * vacuous PASS, because the suite tallies only checks_failed. */
#define CHECK(cond) do {                                                   \
        checks_run++;                                                      \
        if (!(cond)) {                                                     \
            checks_failed++;                                               \
            fprintf(stderr, "    assert failed: %s (%s:%d)\n",             \
                    #cond, __FILE__, __LINE__);                            \
        }                                                                  \
    } while (0)

/* ------------------------------------------------------------------ helpers */

static unsigned char *fake_page;
static injector_t fake;

/* "Now" in the units /proc/<pid>/stat field 22 uses, matching
 * nonstop_boot_ticks(): USER_HZ ticks since boot. */
static unsigned long long boot_ticks(void)
{
    double up = 0.0;
    long hz;
    FILE *f = fopen("/proc/uptime", "r");

    if (f == NULL) {
        return 0;
    }
    if (fscanf(f, "%lf", &up) != 1) {
        fclose(f);
        return 0;
    }
    fclose(f);
    hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0) {
        hz = 100;
    }
    return (unsigned long long)(up * (double)hz);
}

static pid_t own_tgid(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    pid_t tgid = 0;

    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "Tgid:", 5) == 0) {
            tgid = (pid_t)strtol(line + 5, NULL, 10);
            break;
        }
    }
    fclose(f);
    return tgid;
}

/* 0 = gone, else the /proc state character ('R','S','D','Z','T','t','X'). */
static char proc_state(pid_t p)
{
    char path[64];
    FILE *f;
    int ch;

    if (p <= 0) {
        return 0;
    }
    snprintf(path, sizeof(path), "/proc/%d/status", (int)p);
    f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }
    while ((ch = fgetc(f)) != EOF) {
        if (ch == '\n') {
            break;
        }
    }
    /* Second line is "State:\tX (desc)". Skip to it. */
    {
        char line[256];
        if (fgets(line, sizeof(line), f) != NULL) {
            char *v = strchr(line, ':');
            fclose(f);
            if (v != NULL) {
                v++;
                while (*v == ' ' || *v == '\t') {
                    v++;
                }
                return *v;
            }
            return 0;
        }
    }
    fclose(f);
    return 0;
}

/* Alive and not a zombie: what "the scan left it alone" must mean. A SIGKILLed
 * child we have not reaped yet is a zombie, so kill(pid,0) still succeeds and
 * would report a dead child as alive. */
static int running(pid_t p)
{
    char st = proc_state(p);
    return (st != 0 && st != 'Z' && st != 'X');
}

/* kill(2) only QUEUES the signal, so sampling running() once immediately after
 * the scan can still see the victim in 'S'/'R'. Poll, bounded: a killed child
 * reaches 'Z' within milliseconds, and 2 s is far beyond that while still
 * failing loudly if the scan ever stops killing what it names. */
static int wait_not_running(pid_t p, int timeout_ms)
{
    int waited = 0;

    while (waited < timeout_ms) {
        if (!running(p)) {
            return 1;
        }
        {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 10 * 1000 * 1000;
            nanosleep(&ts, NULL);
        }
        waited += 10;
    }
    return !running(p);
}

static int vm_child_main(void *arg)
{
    struct timespec ts;
    (void)arg;
    ts.tv_sec = 0;
    ts.tv_nsec = 200 * 1000 * 1000;
    /* Touch nothing: this child SHARES our mm, so it must not write to any of
     * the test's own storage. Sleep until the scan kills it or the case does. */
    for (;;) {
        nanosleep(&ts, NULL);
    }
    return 0;
}

/* A CLONE_VM child of this process: the same thing the target's helper is, and
 * the same thing a vfork()/posix_spawn() child of the target looks like to the
 * scan. *stack_out receives the mapping so the caller can free it after reaping. */
static pid_t spawn_vm_child(unsigned char **stack_out)
{
    unsigned char *stack = mmap(NULL, CHILD_STACK_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    pid_t p;

    *stack_out = NULL;
    if (stack == MAP_FAILED) {
        return -1;
    }
    p = (pid_t)clone(vm_child_main, stack + CHILD_STACK_SIZE,
                     CLONE_VM | SIGCHLD, NULL);
    if (p <= 0) {
        munmap(stack, CHILD_STACK_SIZE);
        return -1;
    }
    *stack_out = stack;
    return p;
}

static void kill_and_reap(pid_t p, unsigned char *stack)
{
    if (p > 0) {
        int i;
        kill(p, SIGKILL);
        for (i = 0; i < 200; i++) {
            if (waitpid(p, NULL, WNOHANG) == p) {
                break;
            }
            {
                struct timespec ts;
                ts.tv_sec = 0;
                ts.tv_nsec = 5 * 1000 * 1000;
                nanosleep(&ts, NULL);
            }
        }
        waitpid(p, NULL, 0);
    }
    if (stack != NULL) {
        munmap(stack, CHILD_STACK_SIZE);
    }
}

/* Write the { nonce, settid } pair the kernel would have recorded at the scratch
 * address via CLONE_PARENT_SETTID. Because the child shares our mm, writing it
 * here is exactly what the child will read back. */
static void arm_scratch(unsigned long long nonce, long long settid)
{
    unsigned char *at = fake_page + FAKE_PAGE_SIZE - SCAN_SCRATCH_BYTES;
    memcpy(at, &nonce, sizeof(nonce));
    memcpy(at + sizeof(nonce), &settid, sizeof(settid));
}

/* ------------------------------------------------------------------- cases */

/* 1. No usable discriminator at all: DECLINE, and say why in full. The tail of
 *    this note is what note[192] used to truncate away, so asserting it pins
 *    the buffer size as well as the branch. */
static void case_no_discriminator(void)
{
    char note[1024];
    pid_t found = 0x5a5a;
    int rv;

    PART_BEGIN();
    note[0] = '\0';
    rv = injector__nonstop_orphan_kill(&fake, getpid(), 0 /* leader unknown */,
                                       boot_ticks(), 0 /* pidns not shared */,
                                       0 /* not armed */, &found, note, sizeof(note));
    CHECK(rv == -1);
    CHECK(found == 0);                       /* out-param zeroed, not left alone */
    CHECK(strstr(note, "declined, nothing killed") != NULL);
    CHECK(strstr(note, "killing that would be worse") != NULL);
    PART_END("no discriminator");
}

/* 2. Unknown thread-group leader with a REAL mm-sharer present: the leader is
 *    the one sharer guaranteed to exist and guaranteed to kcmp-match, so it
 *    cannot be left in the candidate set. Must decline and spare the child. */
static void case_unknown_tgid_declines(void)
{
    char note[1024];
    unsigned char *stack = NULL;
    pid_t found = 0x5a5a;
    pid_t child;
    int rv;

    PART_BEGIN();
    child = spawn_vm_child(&stack);
    CHECK(child > 1);
    if (child <= 1) {
        PART_END("unknown tgid (not run)");
        return;
    }
    note[0] = '\0';
    /* nonce != 0 but pidns NOT shared: the recorded-pid discriminator is
     * unavailable across namespaces, so kcmp is the only route to a kill here -
     * and it must be refused, because the leader is unknown. */
    rv = injector__nonstop_orphan_kill(&fake, getpid(), 0, boot_ticks(), 0,
                                       0x1234u, &found, note, sizeof(note));
    CHECK(rv == -1);
    CHECK(found == 0);
    CHECK(running(child));                   /* the sharer survived */
    CHECK(strstr(note, "thread-group leader could not be read") != NULL);
    kill_and_reap(child, stack);
    PART_END("unknown tgid declines");
}

/* 3. t0_ticks == 0 (/proc/uptime unreadable) switches the start-stamp gate OFF.
 *    Scanning anyway would leave "shares the target's mm" as the only test,
 *    which the target's OWN leader satisfies - so it must decline instead. */
static void case_missing_t0_declines(void)
{
    char note[1024];
    unsigned char *stack = NULL;
    pid_t found = 0x5a5a;
    pid_t child;
    pid_t tgid = own_tgid();
    int rv;

    PART_BEGIN();
    child = spawn_vm_child(&stack);
    CHECK(child > 1);
    CHECK(tgid > 1);
    if (child <= 1 || tgid <= 1) {
        kill_and_reap(child, stack);
        PART_END("missing t0 (not run)");
        return;
    }
    arm_scratch(0xdeadbeefu, (long long)child);   /* fully armed and unique */
    note[0] = '\0';
    rv = injector__nonstop_orphan_kill(&fake, getpid(), tgid, 0 /* no t0 */,
                                       1, 0xdeadbeefu, &found, note, sizeof(note));
    CHECK(rv == -1);
    CHECK(found == 0);
    CHECK(running(child));                   /* armed, unique, and STILL spared */
    CHECK(strstr(note, "start-time reference") != NULL);
    kill_and_reap(child, stack);
    PART_END("missing t0 declines");
}

/* 4. The case the scan exists for: one genuine helper, uniquely identified,
 *    killed. Positively asserted so the gates above cannot all be satisfied by
 *    a scan that simply never kills anything. */
static void case_unique_helper_is_killed(void)
{
    char note[1024];
    unsigned char *stack = NULL;
    pid_t found = 0;
    pid_t tgid = own_tgid();
    unsigned long long t0 = boot_ticks();
    unsigned long long nonce = 0xa1b2c3d4e5f60718ull;
    pid_t child;
    int rv;

    PART_BEGIN();
    CHECK(t0 != 0);
    CHECK(tgid > 1);
    child = spawn_vm_child(&stack);
    CHECK(child > 1);
    if (child <= 1 || t0 == 0 || tgid <= 1) {
        kill_and_reap(child, stack);
        PART_END("unique helper (not run)");
        return;
    }
    /* What CLONE_PARENT_SETTID records: our own pid, in the shared mm. */
    arm_scratch(nonce, (long long)child);
    note[0] = '\0';
    rv = injector__nonstop_orphan_kill(&fake, getpid(), tgid, t0, 1, nonce,
                                       &found, note, sizeof(note));
    CHECK(rv == 1);
    CHECK(found == child);
    /* Actually killed, not just named: rv==1 only proves kill(2) returned 0. */
    CHECK(wait_not_running(child, 2000));
    CHECK(strstr(note, "killed") != NULL);
    kill_and_reap(child, stack);
    PART_END("unique helper killed");
}

/* 5. THE WRONG-KILL REGRESSION PIN. A CLONE_VM sharer whose recorded pid is
 *    somebody else's is a vfork()/posix_spawn()/system()/popen() child of the
 *    target - not our helper. kcmp(KCMP_VM) matches it, it is a /proc-visible
 *    leader, it is not a zombie and it started after t0, so it clears every
 *    other gate; without the recorded-pid veto it is the UNIQUE match and gets
 *    SIGKILLed. It must survive. */
static void case_imposter_sharer_is_vetoed(void)
{
    char note[1024];
    unsigned char *stack = NULL;
    pid_t found = 0x5a5a;
    pid_t tgid = own_tgid();
    unsigned long long t0 = boot_ticks();
    unsigned long long nonce = 0x0f1e2d3c4b5a6978ull;
    pid_t imposter;
    int rv;

    PART_BEGIN();
    imposter = spawn_vm_child(&stack);
    CHECK(imposter > 1);
    CHECK(t0 != 0);
    CHECK(tgid > 1);
    if (imposter <= 1 || t0 == 0 || tgid <= 1) {
        kill_and_reap(imposter, stack);
        PART_END("imposter veto (not run)");
        return;
    }
    /* Armed with a pid that is not the candidate's: either a helper that was
     * never created (settid still 0) or one that has already exited. */
    arm_scratch(nonce, (long long)999999);
    note[0] = '\0';
    rv = injector__nonstop_orphan_kill(&fake, getpid(), tgid, t0, 1, nonce,
                                       &found, note, sizeof(note));
    CHECK(rv == 0);                          /* no match, nothing killed */
    CHECK(found == 0);
    CHECK(running(imposter));                /* <-- the target's own subprocess */
    CHECK(strstr(note, "no match, nothing killed") != NULL);
    CHECK(strstr(note, "vetoed by the recorded-pid check") != NULL);
    kill_and_reap(imposter, stack);
    PART_END("imposter sharer vetoed");
}

/* 6. Two sharers and no armed nonce: ambiguous under kcmp, discriminator-less
 *    without it. Both routes DECLINE, and neither child may die - killing the
 *    wrong one of two is worse than leaking ours. */
static void case_ambiguous_declines(void)
{
    char note[1024];
    unsigned char *s1 = NULL, *s2 = NULL;
    pid_t found = 0x5a5a;
    pid_t tgid = own_tgid();
    unsigned long long t0 = boot_ticks();
    pid_t c1, c2;
    int rv;

    PART_BEGIN();
    c1 = spawn_vm_child(&s1);
    c2 = spawn_vm_child(&s2);
    CHECK(c1 > 1);
    CHECK(c2 > 1);
    CHECK(tgid > 1);
    if (c1 <= 1 || c2 <= 1 || tgid <= 1) {
        kill_and_reap(c1, s1);
        kill_and_reap(c2, s2);
        PART_END("ambiguous (not run)");
        return;
    }
    note[0] = '\0';
    rv = injector__nonstop_orphan_kill(&fake, getpid(), tgid, t0, 1, 0,
                                       &found, note, sizeof(note));
    CHECK(rv == -1);
    CHECK(found == 0);
    CHECK(running(c1));
    CHECK(running(c2));
    CHECK(strstr(note, "declined, nothing killed") != NULL);
    kill_and_reap(c1, s1);
    kill_and_reap(c2, s2);
    PART_END("ambiguous declines");
}

/* 7. A fork() child holds a COW COPY of the armed page, so it reads back our
 *    nonce. It must still be rejected: its recorded pid is not its own. */
static void case_fork_child_not_matched(void)
{
    char note[1024];
    pid_t found = 0x5a5a;
    pid_t tgid = own_tgid();
    unsigned long long t0 = boot_ticks();
    unsigned long long nonce = 0x1122334455667788ull;
    pid_t kid;
    int rv;

    PART_BEGIN();
    arm_scratch(nonce, (long long)0);        /* helper never created */
    kid = fork();
    if (kid == 0) {
        for (;;) {
            sleep(1);
        }
        _exit(0);
    }
    CHECK(kid > 1);
    CHECK(tgid > 1);
    if (kid <= 1 || tgid <= 1) {
        if (kid > 1) {
            kill_and_reap(kid, NULL);
        }
        PART_END("fork child (not run)");
        return;
    }
    note[0] = '\0';
    rv = injector__nonstop_orphan_kill(&fake, getpid(), tgid, t0, 1, nonce,
                                       &found, note, sizeof(note));
    CHECK(rv == 0);
    CHECK(found == 0);
    CHECK(running(kid));                     /* COW copy did not make it a match */
    kill_and_reap(kid, NULL);
    PART_END("fork child not matched");
}

/* 8. Nothing may be left behind: a stray mm-sharer would make every later case
 *    ambiguous, so assert the process table is clean of our children. */
static void case_no_strays(void)
{
    pid_t self = getpid();
    DIR *d = opendir("/proc");
    struct dirent *ent;
    int strays = 0;

    PART_BEGIN();
    CHECK(d != NULL);
    if (d == NULL) {
        PART_END("no strays (not run)");
        return;
    }
    while ((ent = readdir(d)) != NULL) {
        char path[320];           /* NAME_MAX for d_name, plus the prefix */
        FILE *f;
        long ppid = -1;
        char line[256];

        if (ent->d_name[0] < '1' || ent->d_name[0] > '9') {
            continue;
        }
        if ((pid_t)strtol(ent->d_name, NULL, 10) == self) {
            continue;
        }
        snprintf(path, sizeof(path), "/proc/%s/status", ent->d_name);
        f = fopen(path, "r");
        if (f == NULL) {
            continue;
        }
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, "PPid:", 5) == 0) {
                ppid = strtol(line + 5, NULL, 10);
                break;
            }
        }
        fclose(f);
        if (ppid == (long)self) {
            strays++;
            fprintf(stderr, "    stray child of this test still alive: pid %s\n",
                    ent->d_name);
        }
    }
    closedir(d);
    CHECK(strays == 0);
    PART_END("no strays left");
}

/* 9. Buffer sizing, as a tested invariant. nonstop_orphan_report() - the only
 *    caller in the library - hands this function a fixed note buffer, and that
 *    buffer used to be 192 bytes, which truncated EVERY verdict mid-sentence:
 *    the "killed / no match / declined" prefix survived and the actionable
 *    reason did not. That wrapper is static and only reachable through a failed
 *    NONSTOP clone, so it cannot be driven from here; what CAN be pinned is the
 *    property its buffer size depends on - how long the longest note actually
 *    is. If a future edit grows the messages past the wrapper's buffer, or
 *    shrinks the buffer, this fails and names both numbers. */
static void case_note_length_bounds(void)
{
    char note[2048];
    pid_t found = 0;
    size_t len;
    int rv;

    PART_BEGIN();
    memset(note, 0, sizeof(note));
    /* The decline with neither discriminator interpolates why_kcmp and
     * why_settid and is the longest note this function emits. */
    rv = injector__nonstop_orphan_kill(&fake, getpid(), 0, boot_ticks(), 0, 0,
                                       &found, note, sizeof(note));
    CHECK(rv == -1);
    len = strlen(note);
    fprintf(stderr, "    longest decline note: %u bytes\n", (unsigned)len);
    /* 192 was the old buffer: the note MUST be longer, or the truncation this
     * pins never existed and the bound is meaningless. */
    CHECK(len > 192);
    /* 768 is the current wrapper buffer: the note MUST fit, with room to spare. */
    CHECK(len < 768);
    /* And the part that used to be cut off must be present. */
    CHECK(strstr(note, "killing that would be worse") != NULL);
    PART_END("note length bounds");
}

int test_orphan_scan_gates(void)
{
    checks_run = 0;
    checks_failed = 0;

    fake_page = mmap(NULL, FAKE_PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fake_page == MAP_FAILED) {
        fprintf(stderr, "    cannot mmap the fake data page: %s\n", strerror(errno));
        checks_run++;
        checks_failed++;
        return 1;
    }
    memset(&fake, 0, sizeof(fake));
    fake.data = (size_t)(uintptr_t)fake_page;
    fake.data_size = FAKE_PAGE_SIZE;
    fake.pid = getpid();

    case_no_discriminator();
    case_unknown_tgid_declines();
    case_missing_t0_declines();
    case_unique_helper_is_killed();
    case_imposter_sharer_is_vetoed();
    case_ambiguous_declines();
    case_fork_child_not_matched();
    case_note_length_bounds();
    case_no_strays();

    munmap(fake_page, FAKE_PAGE_SIZE);
    fake_page = NULL;

    fprintf(stderr, "    test_orphan_scan: %d checks, %d failed\n",
            checks_run, checks_failed);
    return (checks_failed != 0) ? 1 : 0;
}
