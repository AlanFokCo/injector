/* -*- indent-tabs-mode: nil -*-
 *
 * libFuzzer harness for src/linux/proc.c - drives ALL THREE exported entry
 * points of src/linux/proc.h from one single fuzz input.
 *
 * COVERAGE
 *   1. proc__parse_maps_line() - the pure line parser, fed
 *        (a) the whole A segment as ONE line (newlines included, so the
 *            strchr(p, '\n') tail logic runs),
 *        (b) A + " (deleted)", A + "\n", A + " (deleted)\n" - the raw-tail
 *            deleted-marker logic (MINOR 10 in proc.c) with and without a
 *            trailing newline, and past the 512-byte truncation point,
 *        (c) a WHOLE maps file: A split on '\n' and parsed line by line, both
 *            with the terminator stripped and with it left on the line.
 *      proc_map_t is filled with 0xA5 before EVERY call, so an uninitialised or
 *      over-long write into m.path, or a "-1 that still claims a path", shows up
 *      as an invariant violation instead of passing unnoticed.
 *
 *   2. proc__read_link() - driven through a REAL symlink the harness recreates
 *      every iteration at <mkdtemp dir>/link, where the directory is a private
 *      0700 $TMPDIR/inj_fuzz_proc_XXXXXX made once per process (default
 *      $TMPDIR=/tmp). mkdtemp() rather than a pid-suffixed name: a pid is reused
 *      across boots and across users, so on a shared host with a sticky /tmp a
 *      leftover of someone else's run made our own unlink() fail with EACCES and
 *      turned a healthy campaign into a FUZZ_PROC_ENV abort. A random 0700
 *      directory cannot be pre-occupied or touched by another user at all.
 *      The length
 *      argument n is swept over 0, 1, 2, bufsz-1, bufsz, bufsz+1, SIZE_MAX and
 *      three fuzz-derived values; targets of length PATH_MAX-1 and PATH_MAX are
 *      built explicitly (truncation path / ENAMETOOLONG), and the ENOENT branch
 *      is swept as well.
 *
 *   3. proc__read_comm() - the pid is ALWAYS this process, or a pid that
 *      provably does not exist (-1, INT_MIN). Fuzz-derived pids are never used:
 *      they would read unrelated processes, which is non-deterministic (a saved
 *      crash would not replay, and 'make regress' would go green on a real bug)
 *      and pokes at processes this harness has no business touching. The comm
 *      content is made deterministic - and interesting - by renaming THIS process
 *      with prctl(PR_SET_NAME) from the payload on every iteration. No fork: a
 *      child would have to be reaped and would still be a race, whereas prctl on
 *      self is one syscall and exactly reproducible. That lets the harness assert
 *      the EXACT expected output, including names with spaces, newlines, embedded
 *      NULs and non-ASCII bytes.
 *
 * OUTPUT-BUFFER GUARDING (the interesting part for read_link/read_comm)
 *   For every n <= bufsz the callee gets malloc(n) with one extra canary byte at
 *   index n, pre-filled with 0xA5. So: a write at index n trips the canary (and
 *   is reported even with ASan off), a write beyond n+1 is an ASan
 *   heap-buffer-overflow, and the 0xA5 fill proves nothing was written past the
 *   NUL terminator. n > bufsz (bufsz+1, SIZE_MAX, fuzz-derived huge values) uses
 *   a static buffer wrapped in 16-byte pre/post canaries; lying about the size is
 *   deliberate - both callees must be bounded by the DATA they read, never by n.
 *   Contract checked after every call: 0/-1 only; rc==0 => NUL-terminated inside
 *   n, exact expected content; rc==-1 => out[0]=='\0' for n>0, and NOTHING
 *   written for n==0 (that is what proc__read_link already guarantees and what
 *   the n==0 guard in proc__read_comm claims to guarantee).
 *
 * FAILURE POLICY: an invariant violation calls abort(), which libFuzzer reports
 * as a deadly signal and saves as an artifact - the input becomes a reproducible
 * crashes/proc__*.bin. Nothing here returns silently. Environment problems that
 * would silently delete coverage are loud too, in two tiers - and the tiers
 * matter, because collapsing them makes one of the two gates wrong:
 *
 *   FUZZ_PROC_DEGRADED - the ENVIRONMENT could not support the comm oracle at
 *     all: /proc/<pid>/comm was unreadable, or a name just set with prctl did
 *     not read back. proc__read_comm's must-succeed and exact-content
 *     expectations are dropped for the whole run, so the documented contract was
 *     NOT verified. 'make regress' fails on this, and 'make fuzz' echoes it and
 *     emits a make-level warning. This is the case that used to exit 0 having
 *     asserted nothing about comm.
 *
 *   FUZZ_PROC_NOTE - informational: THIS INPUT made the harness skip some
 *     symlink iterations because symlink(2) refused it (EINVAL/ENAMETOOLONG).
 *     That is an ordinary consequence of fuzzing long paths, not a hole in the
 *     machine, and the rest of the iteration still ran. Echoed and counted, but
 *     never a failure on its own: if it were, the first reproducer checked in
 *     with a long-path mode bit would redden 'make regress' permanently with no
 *     defect behind it, and a gate that cries wolf gets ignored.
 *
 * An unusable $TMPDIR or a failing prctl is neither tier - it aborts with the
 * errno, because without them nothing can run at all.
 *
 * COVERAGE COUNTERS - a third marker, FUZZ_PROC_COVERAGE, and unlike the two
 *   tiers above it is informational and never a gate. Every call to each of the
 *   three entry points is counted, and cleanup() prints the three totals on one
 *   line next to the final skip summary. They exist because nothing else in this
 *   file can prove the entry points were reached at all: a harness that silently
 *   stopped calling proc__read_link() would still satisfy every canary, both
 *   floors and both make targets, because all of those are properties of calls
 *   that happened. They are deliberately NOT a floor - a single-input replay runs
 *   one iteration, and an iteration whose mode bits skip the long-target cases
 *   legitimately makes zero proc__read_link() calls, so "must be > 0" would mint
 *   a false red in the one target that has to stay trustworthy. Read the trend;
 *   do not gate on it. See report_coverage().
 *
 * TWO FATAL LABELS, and both abort(): FUZZ_PROC_INVARIANT means the code under
 * test broke its contract, FUZZ_PROC_ENV means the machine did (an unusable
 * $TMPDIR, a harness path that does not fit g_dir or g_link, an allocation that
 * failed).
 * The split is labelling only - an environmental failure is never downgraded to
 * a pass, because 'make regress' treats libFuzzer's "ERROR: libFuzzer" deadly
 * signal as the failure marker and abort() always produces it. Without the
 * distinct label an environmental abort looks exactly like a parser defect and
 * its artifact gets checked into crashes/ as a bogus reproducer.
 *
 * INPUT LAYOUT (byte-level; no FuzzedDataProvider - this is C)
 *   data[0]   mode bitmask: which optional scenarios this input runs
 *   data[1]   ratio 0..255: share of the payload that becomes A
 *   data[2..] payload, cut into A | B | C
 *               A = ratio/255 of the payload -> text (maps lines, symlink
 *                   target bytes, this process' new comm)
 *               B = half of what is left    -> numbers (nhint, mixed into the
 *                   n sweep and the long-target length)
 *               C = the rest                -> filler cycled into long targets
 *   Inputs above FP_MAX_INPUT are CLAMPED to their first FP_MAX_INPUT bytes
 *   instead of being skipped, so an oversized artifact still replays
 *   deterministically.
 *   size == 0 / size == 1 / huge sizes are all safe: the segments simply come
 *   out empty and the always-on boundary sweeps still run.
 *
 * Per-iteration resources: exactly one symlink inside exactly one mkdtemp()
 * directory in $TMPDIR. The symlink is unlinked before each recreation, and both
 * it and the directory are removed by cleanup() from atexit AND by every fail*()
 * immediately before its abort() - so an abnormal death (every invariant, and an
 * environmental one) leaves nothing behind either. Only libFuzzer's own
 * -timeout path can leak them, because it tears the worker down with _Exit() and
 * runs no atexit handler; those leftovers are inert, being inside a directory no
 * other user can write to. No forked children, no fds held open, every malloc
 * freed.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>

#if defined(__linux__)
#include <sys/prctl.h>
#else
/* This harness only ever builds on Linux (the Makefile links every .c in src/linux).
 * The stub exists so 'clang -fsyntax-only' on a non-Linux host still
 * type-checks the prctl() call site instead of compiling it out silently; it
 * aborts rather than pretending to have renamed anything. */
#define PR_SET_NAME 15
static int prctl(int option, ...) { (void)option; abort(); return -1; }
#endif

#include "proc.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define FP_MAX_INPUT   16384u             /* clamp, do not skip */
#define FP_MAX_LINES   64u                /* maps lines parsed per multi-line pass */
#define FP_CANARY_LEN  16u
#define FP_LINK_BUF    (PATH_MAX + 64)    /* > longest symlink the kernel accepts */
#define FP_COMM_BUF    64u                /* > TASK_COMM_LEN (16) */
#define FP_CANARY      0x5Au
#define FP_PREFILL     0xA5u
/* Capacity of sweep()'s stack array of candidate output sizes. It MUST equal the
 * number of cand_put() calls in n_candidates() below. That equality cannot be
 * checked at compile time, so cand_put() re-checks the bound on EVERY write and
 * aborts instead of writing past the end of the array: the two counts drifted
 * apart once already (12 slots declared, 10 emitted) and the next three candidates
 * would have smashed sweep()'s stack frame silently. Bump BOTH together. */
#define FP_NCAND       10u

/* mode bits (data[0]) */
#define FP_M_DEL       0x01u  /* A + " (deleted)"            */
#define FP_M_NL        0x02u  /* A + "\n"                    */
#define FP_M_DELNL     0x04u  /* A + " (deleted)\n"          */
#define FP_M_LINES     0x08u  /* multi-line pass, '\n' stripped */
#define FP_M_LINESNL   0x10u  /* multi-line pass, '\n' kept     */
#define FP_M_TGTLEN    0x20u  /* symlink target of fuzz-derived length */
#define FP_M_TGTLONG   0x40u  /* symlink target of length PATH_MAX-1   */
#define FP_M_TGTOVER   0x80u  /* symlink target of length PATH_MAX (ENAMETOOLONG) */

static char g_dir[PATH_MAX];    /* private 0700 mkdtemp() dir holding g_link */
static char g_link[PATH_MAX];   /* the harness' own symlink path, inside g_dir */
static char g_ltgt[PATH_MAX + 1]; /* scratch for the long synthetic targets */
static int  g_ready;
static int  g_atexit_done;   /* atexit(cleanup) registered in THIS process? */
static pid_t g_owner;           /* pid g_link was built for (fork safety) */
static int  g_proc_ok = 1;      /* /proc/<pid>/comm readable? */
/* symlink(2) refusals that make make_link() skip an iteration. Counted so the
 * skipped read_link coverage cannot vanish silently - reported by report_skips(),
 * reached both from the fuzz loop (maybe_report_skips) and from atexit. */
static unsigned long g_skip_inval;      /* EINVAL: empty target or embedded NUL */
static unsigned long g_skip_toolong;    /* ENAMETOOLONG: target >= PATH_MAX     */
/* Progress of the exit-independent skip report: g_skip_reported is the total the
 * last printed line carried (so atexit does not repeat it verbatim), g_skip_next
 * the total that triggers the next line - 1, then 10x growth. */
static unsigned long g_skip_reported;
static unsigned long g_skip_next = 1;
static int  g_comm_exact = 1;   /* comm oracle trustworthy?   */
/* Calls per entry point, printed by report_coverage() at exit. Informational
 * only - see the COVERAGE COUNTERS block at the top for why there is no floor. */
static unsigned long g_calls_maps;
static unsigned long g_calls_link;
static unsigned long g_calls_comm;

typedef struct { char pre[FP_CANARY_LEN]; char buf[FP_LINK_BUF]; char post[FP_CANARY_LEN]; } link_holder_t;
typedef struct { char pre[FP_CANARY_LEN]; char buf[FP_COMM_BUF]; char post[FP_CANARY_LEN]; } comm_holder_t;
static link_holder_t g_lh;
static comm_holder_t g_ch;

/* Best-effort removal of the harness' own symlink and its private directory.
 * Called from cleanup() (atexit) and from every fail*() just before abort(), so
 * neither a clean exit nor an abort() leaves anything behind in a shared
 * $TMPDIR. That is best effort, not a guarantee, and the two exceptions are
 * worth naming: libFuzzer's unit-timeout path tears the process down with
 * _Exit(), and a SIGKILL from outside tears it down with no handler at all -
 * neither runs atexit, and neither gives fail*() a chance to run, so that
 * process's directory survives it. The directory is 0700 and ours, so what
 * survives is one empty directory per such death, not a symlink another user's
 * run could trip over, which was the failure this design exists to prevent.
 * Never fatal and never diagnostic: it runs on the way out, unlink("") and
 * rmdir() on a directory that is not ours both fail harmlessly, and a failure
 * here must not mask the message that is about to be printed. */
static void harness_unlink(void)
{
    if (!g_ready)
        return;
    (void)unlink(g_link);
    (void)rmdir(g_dir);
}

static void fail(const char *what, const char *who) __attribute__((noreturn));
static void fail(const char *what, const char *who)
{
    fprintf(stderr, "FUZZ_PROC_INVARIANT: %s [%s]\n", what, who);
    fflush(stderr);
    harness_unlink();
    abort();
}

static void fail_sys(const char *what) __attribute__((noreturn));
static void fail_sys(const char *what)
{
    fprintf(stderr, "FUZZ_PROC_ENV: %s failed: %s (set TMPDIR to a writable dir "
                    "if this is about the symlink)\n", what, strerror(errno));
    fflush(stderr);
    harness_unlink();
    abort();
}

/* Fatal, exactly like fail() - only the printed label differs. See the FAILURE
 * POLICY block at the top: an environmental problem must still abort so that
 * libFuzzer prints "ERROR: libFuzzer" (which 'make regress' greps for) and the
 * run cannot be mistaken for a clean one, but it must not claim to be an
 * invariant violation in the code under test. */
static void fail_env(const char *what, const char *who) __attribute__((noreturn));
static void fail_env(const char *what, const char *who)
{
    fprintf(stderr, "FUZZ_PROC_ENV: %s [%s]\n", what, who);
    fflush(stderr);
    harness_unlink();
    abort();
}

/* The one place that formats the quiet tier's marker: callers hand it the
 * message body and never spell out "FUZZ_PROC_NOTE" themselves, so the string
 * both make targets grep for cannot drift between call sites. */
static void note(const char *what)
{
    fprintf(stderr, "FUZZ_PROC_NOTE: %s\n", what);
    fflush(stderr);
}

/* The louder of the two tiers: see the FAILURE POLICY block at the top of this
 * file. A degraded run verified LESS than the documented contract, so
 * 'make regress' refuses to count it and 'make fuzz' warns. Kept distinct from
 * note() precisely so that an input-dependent symlink skip can never be mistaken
 * for an environment that cannot test comm at all. */
static void degraded(const char *what)
{
    fprintf(stderr, "FUZZ_PROC_DEGRADED: %s\n", what);
    fflush(stderr);
}

static int filled(const void *p, size_t n, unsigned char v)
{
    const unsigned char *q = (const unsigned char *)p;
    size_t i;
    for (i = 0; i < n; i++)
        if (q[i] != v)
            return 0;
    return 1;
}

/* ------------------------------------------------------------------ split -- */

typedef struct {
    uint8_t mode;
    const uint8_t *a; size_t alen;
    const uint8_t *b; size_t blen;
    const uint8_t *c; size_t clen;
    size_t nhint;
} split_t;

static void split_input(const uint8_t *data, size_t size, split_t *s)
{
    size_t off = 0, rem, plen;
    uint8_t ratio = 0;
    size_t i;

    s->mode = 0;
    if (size > off) { s->mode = data[off]; off++; }
    if (size > off) { ratio = data[off]; off++; }
    plen = size - off;
    s->a = data + off;
    s->alen = (size_t)(((uint64_t)plen * (uint64_t)ratio) / 255u);
    s->b = s->a + s->alen;
    rem = plen - s->alen;
    s->blen = rem / 2u;
    s->c = s->b + s->blen;
    s->clen = rem - s->blen;

    s->nhint = 0;
    for (i = 0; i < s->blen && i < 8u; i++)
        s->nhint = s->nhint * 251u + (size_t)s->b[i];
}

/* --------------------------------------------------------------- checks ---- */

typedef struct {
    const char *who;
    size_t bufsz;                 /* size of the static fallback buffer */
    char *sbuf, *spre, *spost;
    int want_rc;                  /* 0: succeed for n>0; -1: must fail; 2: either */
    int allow_empty;              /* rc==0 with out[0]=='\0' is legal */
    int int_bufsiz;               /* the syscall's size argument is an int, see
                                   * check_out(): n==1 and n>INT_MAX are special */
    const char *expect;           /* exact content when rc==0, or NULL */
} sweep_cfg;

typedef int (*sweep_fn)(void *ctx, char *out, size_t n);

static void check_expect(const sweep_cfg *cfg, size_t n, const char *p, size_t l)
{
    size_t el = strlen(cfg->expect);

    if (n > el) {                       /* the whole string fits in n */
        if (l != el)
            fail("returned a string of the wrong length", cfg->who);
        if (el != 0 && memcmp(p, cfg->expect, el) != 0)
            fail("returned the wrong content", cfg->who);
    } else if (n == 0) {
        /* ORDERING DEPENDENCY, guarded rather than trusted. The truncation branch
         * below computes n - 1, which for n == 0 wraps to SIZE_MAX and would
         * report "truncated to the wrong length" - a bogus crashes/proc__*.bin
         * reproducer blaming the parser for a harness arithmetic wrap. Today this
         * is unreachable only because check_out() fails first on rc == 0 && n == 0
         * ("returned 0 for a zero-length buffer") and never calls check_expect();
         * reordering that block, or calling check_expect() from anywhere else,
         * would expose the wrap. Assert the precondition explicitly instead of
         * relying on a caller's statement order. Labelled FUZZ_PROC_ENV: a broken
         * harness invariant is the machine's fault, not proc.c's. */
        fail_env("check_expect() reached with n == 0, which its truncation branch "
                 "cannot evaluate (n - 1 would wrap to SIZE_MAX)", cfg->who);
    } else {                            /* must be the prefix, packed to n-1 */
        if (l != n - 1)
            fail("truncated to the wrong length", cfg->who);
        if (l != 0 && memcmp(p, cfg->expect, l) != 0)
            fail("truncated to the wrong content", cfg->who);
    }
}

static void check_out(const sweep_cfg *cfg, int rc, size_t n, const char *p, size_t cap)
{
    size_t l = (cap != 0) ? strnlen(p, cap) : 0;
    size_t i, from;

    if (cap != 0 && l >= cap)
        fail("output is not NUL-terminated inside the buffer it was given", cfg->who);
    if (rc != 0 && rc != -1)
        fail("return value is neither 0 nor -1", cfg->who);
    /* readlink(2) takes an *int* bufsiz, so for the link case two sizes are
     * special and neither is a defect in the code under test:
     *   n == 1  -> bufsiz 0, and do_readlinkat() answers EINVAL for bufsiz <= 0,
     *              so proc__read_link() normally fails and empties out instead of
     *              returning an empty string (the assertion below accepts either
     *              answer, and says why);
     *   n > INT_MAX -> bufsiz is the truncated low 32 bits, which may be
     *              negative (EINVAL again) or an arbitrary positive count, in
     *              which case only that many bytes are copied.
     * For those the exact-content contract is relaxed, but every memory-safety
     * invariant below still holds in full. proc__read_comm() has no syscall size
     * argument at all, so it keeps the ordinary expectations everywhere. */
    const int int_trunc = (cfg->int_bufsiz != 0) && n > (size_t)INT_MAX;

    if (cfg->int_bufsiz != 0 && n == 1) {
        /* n == 1 hands readlink(2) a bufsiz of 0. POSIX requires EINVAL for a
         * non-positive bufsiz and Linux/glibc/musl all deliver it, so rc == -1
         * is the expected answer - but that is a property of the LIBC, not of
         * proc.c. A libc that merely differs here (answers 0 and stores nothing
         * but the NUL) is not a defect in the code under test, and hard-asserting
         * -1 would let that one difference abort the campaign and bury every real
         * parser bug behind a spurious crash. Deliberately relaxed to "failed, or
         * succeeded with an empty string".
         * Nothing memory-safety related is relaxed: NUL-termination inside n, the
         * prefill past the terminator, the "nothing at all is written when n == 0"
         * rule (enforced by sweep()'s canary byte at index n) and rc == 0 with a
         * NON-empty out all still assert in full - the last via check_expect()
         * below, which for n == 1 demands a string of length exactly n - 1 == 0.
         * tests/unit/test_guards.c carries the identical relaxation. */
        if (!(rc == -1 || (rc == 0 && l == 0)))
            fail("n == 1 must fail (POSIX EINVAL for readlink bufsiz 0) or return "
                 "an empty string", cfg->who);
    } else if (!int_trunc) {
        if (cfg->want_rc == -1 && rc != -1)
            fail("succeeded where the contract says it must fail", cfg->who);
        if (cfg->want_rc == 0 && n > 0 && rc != 0)
            fail("failed where the contract says it must succeed", cfg->who);
    }

    if (rc == 0) {
        if (n == 0)
            fail("returned 0 for a zero-length buffer", cfg->who);
        /* n == 1 legally yields an empty string: readlink() was handed a
         * bufsiz of 0, so there was no room for anything but the NUL. The
         * exact-content check below still verifies that truncation. */
        if (l == 0 && n >= 2 && !cfg->allow_empty && !int_trunc)
            fail("returned 0 but left out empty", cfg->who);
        if (cfg->expect != NULL && !int_trunc)
            check_expect(cfg, n, p, l);
    } else if (n > 0 && l != 0) {
        fail("returned -1 but left a string in out", cfg->who);
    }

    /* nothing may be written past the terminator (past out[0] on failure) */
    from = (l < cap) ? l + 1 : cap;
    for (i = from; i < cap; i++)
        if (p[i] != (char)FP_PREFILL)
            fail("wrote past the NUL terminator of out", cfg->who);
}

/* One bound-checked write into the candidate array. 'cap' is the array's real
 * capacity, passed down by sweep() instead of being assumed here, so a candidate
 * list that outgrows its backing array fails loudly on the write that would
 * overflow rather than corrupting sweep()'s stack frame. */
static void cand_put(size_t *out, size_t *k, size_t cap, size_t v)
{
    if (*k >= cap)
        /* A harness bug, not a parser defect: labelled FUZZ_PROC_ENV so the
         * artifact libFuzzer saves is not mistaken for a crashes/proc__*.bin
         * reproducer (see the FAILURE POLICY block at the top). */
        fail_env("n_candidates() emitted more values than FP_NCAND slots", "sweep");
    out[(*k)++] = v;
}

/* Emits the candidate output sizes and returns how many; never more than cap.
 * KEEP THE NUMBER OF cand_put() CALLS == FP_NCAND (see the comment there). */
static size_t n_candidates(size_t bufsz, size_t nhint, size_t *out, size_t cap)
{
    size_t k = 0;

    cand_put(out, &k, cap, 0);                      /* n-1 wrap hazard */
    cand_put(out, &k, cap, 1);
    cand_put(out, &k, cap, 2);
    cand_put(out, &k, cap, bufsz - 1);
    cand_put(out, &k, cap, bufsz);                  /* exact fit */
    cand_put(out, &k, cap, bufsz + 1);              /* one past: never trusted */
    cand_put(out, &k, cap, SIZE_MAX);               /* the classic n-1 == SIZE_MAX wrap */
    cand_put(out, &k, cap, nhint % (bufsz + 2u));
    cand_put(out, &k, cap, nhint & 0xFFu);
    cand_put(out, &k, cap, nhint);                  /* arbitrary huge value */
    return k;
}

static void sweep(const sweep_cfg *cfg, sweep_fn fn, void *ctx, size_t nhint)
{
    size_t cand[FP_NCAND];
    size_t nc = n_candidates(cfg->bufsz, nhint, cand, FP_NCAND);
    size_t i, j;

    for (i = 0; i < nc; i++) {
        size_t n = cand[i];
        char *p, *blk = NULL;
        size_t cap;
        int rc;

        if (n <= cfg->bufsz) {
            blk = (char *)malloc(n + 1);
            if (blk == NULL)
                /* Environmental, not a parser defect - but still fatal. */
                fail_env("out of memory for the output buffer", cfg->who);
            memset(blk, FP_PREFILL, n);
            blk[n] = (char)FP_CANARY;
            p = blk;
            cap = n;
        } else {
            memset(cfg->sbuf, FP_PREFILL, cfg->bufsz);
            memset(cfg->spre, FP_CANARY, FP_CANARY_LEN);
            memset(cfg->spost, FP_CANARY, FP_CANARY_LEN);
            p = cfg->sbuf;
            cap = cfg->bufsz;
        }

        rc = fn(ctx, p, n);

        if (blk != NULL) {
            if (blk[n] != (char)FP_CANARY)
                fail("wrote past the end of the buffer it was told it had", cfg->who);
        } else {
            for (j = 0; j < FP_CANARY_LEN; j++)
                if (cfg->spre[j] != (char)FP_CANARY || cfg->spost[j] != (char)FP_CANARY)
                    fail("smashed the canary bytes around the output buffer", cfg->who);
        }
        check_out(cfg, rc, n, p, cap);
        free(blk);
    }
}

/* ------------------------------------------------- 1. parse_maps_line ------ */

static void maps_once(const char *line, const char *tag)
{
    static const char suffix[] = " (deleted)";
    const size_t slen = sizeof(suffix) - 1;
    proc_map_t m;
    int rc;
    size_t l;

    memset(&m, FP_PREFILL, sizeof(m));
    g_calls_maps++;
    rc = proc__parse_maps_line(line, &m);

    if (rc == 0) {
        /* The invariant that actually holds is "m.path contains a NUL inside the
         * array", i.e. it is a valid C string within its bounds. The commonly
         * quoted "m.path[sizeof(m.path)-1] == '\0'" is NOT one: proc.c copies
         * only the bytes of the path and terminates those, it never zero-fills
         * the remainder, so path[511] legitimately still holds our 0xA5 prefill
         * for every path shorter than 511 bytes. Checking the tail byte would
         * abort the campaign on the first short path. */
        l = strnlen(m.path, sizeof(m.path));
        if (l >= sizeof(m.path))
            fail("m.path has no NUL inside the array", tag);
        if (l == 0)
            fail("returned 0 with an empty path", tag);
        if (m.deleted != 0 && m.deleted != 1)
            fail("m.deleted is neither 0 nor 1", tag);
        /* The path must appear verbatim in the line: catches any mangled or
         * invented byte without restating the parser's own logic. True whether
         * or not the copy was truncated and whether or not a marker was
         * stripped - both only ever remove a tail. */
        if (strstr(line, m.path) == NULL)
            fail("m.path is not a substring of the line it was parsed from", tag);
        if (m.deleted && l >= slen && memcmp(m.path + l - slen, suffix, slen) == 0) {
            /* A leftover marker at the END of m.path is legitimate in exactly one
             * situation: the mapped file's own name ends with " (deleted)", so the
             * kernel printed the marker TWICE and removing one occurrence is the
             * correct answer (stripping both would corrupt the file name). The
             * parser removes at most one, so a path that still ends with the
             * marker implies the line carried it twice, adjacently - assert that
             * instead of the blanket "must not end with the marker", which was
             * wrong and aborted the campaign within seconds on inputs like
             * "/tmp/x (deleted) (deleted)". A parser that forgot to strip at all
             * still fails here, because then the line carries the marker once.
             *
             * The exemption is deliberately LOCAL: scanning the whole line for
             * " (deleted) (deleted)" let a doubled marker anywhere - inside a
             * pathological pathname, say - suppress this detection even when the
             * parser forgot to strip the real one. What must hold instead is that
             * the marker the parser removed is the one sitting immediately AFTER
             * the prefix it kept, because m.path is always a contiguous prefix of
             * the raw path: truncation and marker-stripping only ever cut from the
             * end. So assert on "m.path followed by the marker" - which is that
             * tail window and nothing else. No alignment guess is needed (strstr
             * would find the FIRST occurrence of m.path, which a crafted header
             * can spoof), and a parser that forgot to strip still fails: then
             * m.path is the whole raw path and nothing follows it but the newline.
             * dbl[] is sized so the concatenation always fits: l < sizeof(m.path)
             * is asserted above and slen + 1 == sizeof(suffix). */
            char dbl[sizeof(m.path) + sizeof(suffix)];

            memcpy(dbl, m.path, l);
            memcpy(dbl + l, suffix, slen);
            dbl[l + slen] = '\0';
            if (strstr(line, dbl) == NULL)
                fail("deleted mapping kept the ' (deleted)' suffix in m.path, and "
                     "the line does not carry that suffix a second time right "
                     "after the path prefix", tag);
        }
    } else if (rc == -1) {
        /* -1 must not claim a path: either leave m.path alone or empty it */
        if (!filled(m.path, sizeof(m.path), FP_PREFILL) && m.path[0] != '\0')
            fail("returned -1 but left a usable path in m.path", tag);
    } else {
        fail("return value is neither 0 nor -1", tag);
    }
}

static void maps_lines(char *buf, size_t len, char *scratch, size_t scratchcap,
                       int keep_nl, const char *tag)
{
    size_t off = 0, count = 0;

    while (off <= len && count < FP_MAX_LINES) {
        const char *nl = (const char *)memchr(buf + off, '\n', len - off);
        size_t end = nl ? (size_t)(nl - buf) : len;
        size_t llen = end - off;

        if (keep_nl && nl != NULL) {
            if (llen + 2 > scratchcap)
                /* Not a silent break: "cannot happen" is a claim about the
                 * harness itself (every caller passes cap == len + 2, and llen is
                 * a length inside len), and this harness' rule is that nothing
                 * returns without a diagnostic. If it ever does happen the
                 * '\n'-keeping pass would quietly parse nothing at all, which is
                 * lost coverage wearing a green result. */
                fail("harness invariant broken: the '\\n'-keeping scratch buffer "
                     "is too small for the line it must hold (cap must be "
                     "len + 2), so that whole pass would be skipped", tag);
            memcpy(scratch, buf + off, llen);
            scratch[llen] = '\n';
            scratch[llen + 1] = '\0';
            maps_once(scratch, tag);
        } else {
            buf[end] = '\0';                 /* in-place, buffer has slack */
            maps_once(buf + off, tag);
        }
        count++;
        if (nl == NULL)
            break;
        off = end + 1;
    }
}

static void test_maps(const split_t *s)
{
    char *buf, *scratch = NULL;

    buf = (char *)malloc(s->alen + 32u);
    if (buf == NULL)
        fail_env("out of memory for the maps buffer", "maps");
    /* Length-guarded: with an empty input libFuzzer may legally pass data == NULL,
     * and memcpy() with a NULL argument is UB even for a zero length - which
     * -fsanitize=undefined -fno-sanitize-recover=all turns into an abort, so the
     * 0-byte reproducer (the required regression artifact for the n == 0 guard in
     * proc__read_comm) would replay as a spurious crash. LLVMFuzzerTestOneInput
     * also substitutes a static dummy byte, so this is the second of two belts. */
    if (s->alen)
        memcpy(buf, s->a, s->alen);

    /* always: the degenerate empty line and the whole segment as one line */
    maps_once("", "maps:empty");
    buf[s->alen] = '\0';
    maps_once(buf, "maps:whole-A");

    if (s->mode & FP_M_DEL) {
        memcpy(buf + s->alen, " (deleted)", 10u);
        buf[s->alen + 10u] = '\0';
        maps_once(buf, "maps:A+(deleted)");
    }
    if (s->mode & FP_M_NL) {
        buf[s->alen] = '\n';
        buf[s->alen + 1u] = '\0';
        maps_once(buf, "maps:A+nl");
    }
    if (s->mode & FP_M_DELNL) {
        memcpy(buf + s->alen, " (deleted)\n", 11u);
        buf[s->alen + 11u] = '\0';
        maps_once(buf, "maps:A+(deleted)+nl");
    }

    /* multi-line: whole maps file. The '\n'-keeping pass must run first, it is
     * the one that does not destroy the buffer. */
    if (s->mode & FP_M_LINESNL) {
        scratch = (char *)malloc(s->alen + 2u);
        if (scratch == NULL)
            fail_env("out of memory for the line scratch buffer", "maps");
        maps_lines(buf, s->alen, scratch, s->alen + 2u, 1, "maps:line+nl");
    }
    if (s->mode & FP_M_LINES)
        maps_lines(buf, s->alen, scratch, s->alen + 2u, 0, "maps:line");

    free(scratch);
    free(buf);
}

/* ------------------------------------------------------- 2. read_link ------ */

static int call_link(void *ctx, char *out, size_t n)
{
    g_calls_link++;
    return proc__read_link((const char *)ctx, out, n);
}

static void link_case(const char *target, int want_rc, size_t nhint, const char *tag)
{
    sweep_cfg cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.who = tag;
    cfg.bufsz = FP_LINK_BUF;
    cfg.sbuf = g_lh.buf;
    cfg.spre = g_lh.pre;
    cfg.spost = g_lh.post;
    cfg.want_rc = want_rc;
    cfg.allow_empty = 0;
    cfg.int_bufsiz = 1;              /* readlink(2) takes an int bufsiz */
    cfg.expect = (want_rc == 0) ? target : NULL;
    sweep(&cfg, call_link, (void *)g_link, nhint);
}

/* 0 == created, -1 == the target itself is unusable (skip this case) */
static int make_link(const char *target)
{
    if (unlink(g_link) != 0 && errno != ENOENT)
        fail_sys("unlink(harness symlink)");
    if (symlink(target, g_link) != 0) {
        int e = errno;
        /* A target with an embedded NUL, an empty target, or one at/over
         * PATH_MAX is rejected by symlink(2) itself: nothing to do with the
         * code under test, so skip instead of reporting a bug. */
        if (e == EINVAL || e == ENAMETOOLONG) {
            /* Counted, never silent: report_skips() prints one summary line when
             * the harness exits. These iterations really are lost read_link
             * coverage, and they vanish wholesale once a fuzz-derived target
             * prefix reaches PATH_MAX, which would otherwise look like a campaign
             * that simply stopped exercising long targets. */
            if (e == EINVAL)
                g_skip_inval++;
            else
                g_skip_toolong++;
            return -1;
        }
        errno = e;
        fail_sys("symlink(target)");
    }
    return 0;
}

/* NUL-free target of length min(want, cap-1), cycled from A (fallback C). */
static void build_target(char *dst, size_t cap, size_t want, const split_t *s)
{
    const uint8_t *src = s->alen ? s->a : s->c;
    size_t srclen = s->alen ? s->alen : s->clen;
    size_t len = (want < cap - 1) ? want : cap - 1;
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char ch = srclen ? src[i % srclen] : (unsigned char)'z';
        if (ch == 0)
            ch = (unsigned char)'z';   /* keep the target a valid C string */
        dst[i] = (char)ch;
    }
    dst[len] = '\0';
}

static void test_link(const split_t *s)
{
    static const char fallback[] = "inj_fuzz_fallback_target";
    char *tgt;
    size_t tlen = 0, tcap;

    /* room for A's C-prefix, and for the fallback target when A is empty or
     * starts with a NUL byte */
    tcap = s->alen + 1u;
    if (tcap < sizeof(fallback))
        tcap = sizeof(fallback);
    tgt = (char *)malloc(tcap);
    if (tgt == NULL)
        fail_env("out of memory for the symlink target", "read_link");
    while (tlen < s->alen && s->a[tlen] != 0)
        tlen++;
    if (tlen > 0) {
        memcpy(tgt, s->a, tlen);
        tgt[tlen] = '\0';
    } else {
        memcpy(tgt, fallback, sizeof(fallback));
    }

    if (make_link(tgt) == 0)
        link_case(tgt, 0, s->nhint, "read_link(A target)");

    if (s->mode & FP_M_TGTLEN) {
        build_target(g_ltgt, sizeof(g_ltgt), 1u + (s->nhint % (PATH_MAX - 1)), s);
        if (make_link(g_ltgt) == 0)
            link_case(g_ltgt, 0, s->nhint, "read_link(fuzz-length target)");
    }
    if (s->mode & FP_M_TGTLONG) {
        build_target(g_ltgt, sizeof(g_ltgt), (size_t)PATH_MAX - 1u, s);
        if (make_link(g_ltgt) == 0)
            link_case(g_ltgt, 0, s->nhint, "read_link(PATH_MAX-1 target)");
    }
    if (s->mode & FP_M_TGTOVER) {
        /* expected to be refused with ENAMETOOLONG; if a filesystem accepts it,
         * the sweep below still checks every truncation invariant. */
        build_target(g_ltgt, sizeof(g_ltgt), (size_t)PATH_MAX, s);
        if (make_link(g_ltgt) == 0)
            link_case(g_ltgt, 0, s->nhint, "read_link(PATH_MAX target)");
    }

    /* the error branch: the path we just removed cannot exist again (nothing else
     * can create it - it lives in our private 0700 directory), so readlink must
     * fail for every n and leave out empty. */
    if (unlink(g_link) != 0 && errno != ENOENT)
        fail_sys("unlink(harness symlink)");
    link_case(NULL, -1, s->nhint, "read_link(ENOENT)");

    free(tgt);
}

/* ------------------------------------------------------- 3. read_comm ------ */

static int call_comm(void *ctx, char *out, size_t n)
{
    g_calls_comm++;
    return proc__read_comm(*(const pid_t *)ctx, out, n);
}

static void comm_case(pid_t pid, const char *expect, int want_rc, size_t nhint,
                      const char *tag)
{
    sweep_cfg cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.who = tag;
    cfg.bufsz = FP_COMM_BUF;
    cfg.sbuf = g_ch.buf;
    cfg.spre = g_ch.pre;
    cfg.spost = g_ch.post;
    cfg.want_rc = want_rc;
    cfg.allow_empty = 1;
    cfg.expect = expect;
    sweep(&cfg, call_comm, (void *)&pid, nhint);
}

static void test_comm(const split_t *s)
{
    char nm[16], exp[16];
    size_t cl = (s->alen < 15u) ? s->alen : 15u;
    size_t nl, el = 0;
    pid_t self, none;

    memset(nm, 0, sizeof(nm));
    if (cl)                             /* s->a may be NULL: see test_maps() */
        memcpy(nm, s->a, cl);
    nm[15] = '\0';
    if (prctl(PR_SET_NAME, nm) != 0)
        fail_sys("prctl(PR_SET_NAME)");

    /* what /proc/self/comm must now contain: the stored name (strscpy stops at
     * the first NUL) cut at the first '\n', which is where the parser stops. */
    nl = strnlen(nm, sizeof(nm));
    while (el < nl && nm[el] != '\n') {
        exp[el] = nm[el];
        el++;
    }
    exp[el] = '\0';

    self = getpid();
    comm_case(self, g_comm_exact ? exp : NULL, g_proc_ok ? 0 : 2, s->nhint,
              "read_comm(self)");

    /* the fopen-failure branch, with a pid that cannot exist: /proc/-1/comm and
     * /proc/-2147483648/comm. Both also exercise snprintf into path[64]. */
    none = -1;
    comm_case(none, NULL, -1, s->nhint, "read_comm(pid -1)");
    /* Unconditional. This used to hang off FP_M_TGTOVER, a mode bit about
     * symlink target LENGTH, so only ~1/256 of the inputs reached the extreme
     * value that snprintf() formats into path[64]: INT_MIN is "-2147483648", the
     * longest pid string there is, i.e. "/proc/-2147483648/comm" - 22 chars plus
     * the NUL. That is a truncation-boundary case for the fopen-failure branch and
     * it must be covered by EVERY input, not by a lucky mode bit. */
    none = INT_MIN;
    comm_case(none, NULL, -1, s->nhint, "read_comm(pid INT_MIN)");
}

/* ------------------------------------------------------------- plumbing ---- */

/* One summary line, and only if something was actually skipped: how much
 * read_link coverage symlink(2) refusals cost, and why. 'when' only labels the
 * line - every spelling starts with FUZZ_PROC_NOTE, which is what lets
 * 'make regress' refuse a replay that lost coverage and 'make fuzz' grep a
 * campaign log for it.
 *
 * This must NOT depend on atexit, because two exit paths never run atexit
 * handlers. One is abort(): every fail*() here aborts, so a crashing run prints
 * the invariant instead - the louder and more useful of the two. The other is
 * libFuzzer's timeout path: a unit that exceeds -timeout is reported as
 * "SUMMARY: libFuzzer: timeout" and the process is torn down with _Exit(), so
 * neither atexit handlers nor __attribute__((destructor)) functions run.
 * Measured on the runner with a probe target instead of assumed: in all three
 * modes this Makefile uses - plain, -jobs/-workers and single-input replay - a
 * clean run always ran atexit and the destructor, and a timed-out run never did,
 * with or without -jobs. So -jobs is NOT what loses the summary, a hang is: the
 * atexit-only version could vanish in exactly the long, slow campaign that skips
 * the most coverage. maybe_report_skips() below is the exit-independent route.
 * Under -jobs each worker is its own process and prints its own lines; a worker's
 * stderr is dup2'd into its fuzz-N.log and also reaches the job's own stderr. */
static void report_skips(const char *when)
{
    unsigned long total = g_skip_inval + g_skip_toolong;
    char msg[768];
    int len;

    if (total == 0)
        return;
    /* Formatted here, emitted by note(): note() is the only place that spells the
     * FUZZ_PROC_NOTE marker, so the string 'make regress' and 'make fuzz' grep for
     * cannot drift between call sites. Truncation would silently shorten a line
     * whose whole job is to state an exact count, so it is fatal. */
    len = snprintf(msg, sizeof(msg),
            "%lu symlink iteration(s) SKIPPED (%s), so "
            "proc__read_link() never saw those targets: %lu x EINVAL (symlink(2) "
            "refused an empty target or one with an embedded NUL) and %lu x "
            "ENAMETOOLONG (target at or over PATH_MAX - expected once a "
            "fuzz-derived prefix grows that long). Every other case ran and all "
            "buffer guards applied to it.",
            total, when, g_skip_inval, g_skip_toolong);
    if (len < 0 || (size_t)len >= sizeof(msg))
        fail_env("skip summary does not fit its message buffer", "skips");
    note(msg);
    g_skip_reported = total;
}

/* End-of-run entry-point call counts, printed next to the final skip summary.
 *
 * INFORMATIONAL BY DESIGN - nothing gates on these numbers and 'make regress'
 * does not read them. They close a gap no assertion in this file can close: a
 * harness that stopped calling one of the three entry points altogether would
 * still satisfy every canary, both floors and both make targets, because all of
 * those are properties of calls that happened. The counters make vanished
 * coverage visible in the log instead of merely possible.
 *
 * A floor on them would be a false-red machine, so there is none: a single-input
 * replay runs exactly one iteration, and one iteration whose mode bits skip the
 * long-target cases legitimately produces zero proc__read_link() calls, so
 * "counter must be > 0" would redden 'make regress' on the checked-in 0-byte
 * reproducer for a reason that is not a defect. A trend read by a human (or a log
 * diff) is the right shape for this; a hard gate is not.
 *
 * Printed from cleanup(), so it shares report_skips()'s one limitation: a worker
 * killed by libFuzzer's -timeout path is torn down with _Exit() and prints
 * neither line. Unlike skipped coverage, this is not worth an exit-independent
 * route - the number a campaign cares about is the final one. */
static void report_coverage(void)
{
    char msg[384];
    int len;

    len = snprintf(msg, sizeof(msg),
            "entry-point calls in this process: proc__parse_maps_line=%lu "
            "proc__read_link=%lu proc__read_comm=%lu (informational - no floor, "
            "a zero can be a legitimate single-input or heavily-skipped run)",
            g_calls_maps, g_calls_link, g_calls_comm);
    if (len < 0 || (size_t)len >= sizeof(msg))
        fail_env("coverage summary does not fit its message buffer", "coverage");
    fprintf(stderr, "FUZZ_PROC_COVERAGE: %s\n", msg);
    fflush(stderr);
}

/* Called once per fuzz iteration, so the summary reaches the log however the
 * process dies - including a libFuzzer timeout, which runs no atexit handler. It
 * prints as soon as the first skip happens and again each time the total has
 * grown 10x, i.e. at most ~8 lines per worker, never one line per skip. */
static void maybe_report_skips(void)
{
    unsigned long total = g_skip_inval + g_skip_toolong;

    if (total == 0 || total < g_skip_next)
        return;
    report_skips("running total");
    g_skip_next = (total > ULONG_MAX / 10u) ? ULONG_MAX : total * 10u;
}

static void cleanup(void)
{
    /* The same removal every fail*() does before abort(): our own symlink and our
     * own mkdtemp() directory, and nothing of anybody else's. */
    harness_unlink();
    /* Exact final numbers, unless the last running-total line already carried
     * them - a short replay must not print the same summary twice. */
    if (g_skip_inval + g_skip_toolong != g_skip_reported)
        report_skips("final");
    /* Unconditional: zero counts are exactly the case worth seeing printed. */
    report_coverage();
}

static void ensure_ready(void)
{
    const char *tmp;

    /* Re-derive the paths whenever the pid changes: under libFuzzer's -fork mode
     * a child inherits the parent's state without exec, and two processes must
     * never share one symlink path (one would unlink the other's target and the
     * sweep would see a spurious ENOENT). The child then mkdtemp()s its OWN
     * directory and forgets the parent's - the parent is still alive and still
     * using it, so removing it would be a defect, and the parent's own cleanup()
     * remains responsible for it. */
    if (g_ready && g_owner == getpid())
        return;
    tmp = (getenv("TMPDIR") != NULL && getenv("TMPDIR")[0] != '\0')
              ? getenv("TMPDIR") : "/tmp";
    /* mkdtemp() creates it 0700 and fails rather than reusing an existing name, so
     * the path is collision-proof across pids, users and boots: the failure mode
     * this replaces was a pid-suffixed $TMPDIR name left behind by an abort() or a
     * libFuzzer -timeout _Exit(), which a DIFFERENT user's later run with a reused
     * pid could not unlink (EACCES) - turning a healthy campaign into a
     * FUZZ_PROC_ENV abort with no defect behind it. A $TMPDIR long enough to
     * overflow either buffer is a property of the machine, not of proc.c, so both
     * checks are FUZZ_PROC_ENV: fatal, but never checkable in as a parser
     * reproducer. Nothing here may pass silently. */
    if (snprintf(g_dir, sizeof(g_dir), "%s/inj_fuzz_proc_XXXXXX", tmp)
            >= (int)sizeof(g_dir))
        fail_env("harness dir template does not fit in g_dir ($TMPDIR too long)",
                 "init");
    if (mkdtemp(g_dir) == NULL)
        fail_sys("mkdtemp(harness dir)");
    /* The directory exists from this line onwards, so the flag that lets
     * harness_unlink() remove it has to be set NOW and not after the two checks
     * below. Set later, an abort from either of them left the directory in
     * $TMPDIR: harness_unlink() runs from fail_env() but returned immediately
     * because g_ready was still 0. g_link is still all zeroes at this point and
     * unlink("") fails with ENOENT, which harness_unlink() ignores by design.
     * g_atexit_done, not g_ready, guards the registration: a libFuzzer -fork
     * child re-enters this function with g_ready already 1 and must not register
     * a second handler, but it inherits the parent's via fork() anyway. */
    g_owner = getpid();
    g_ready = 1;
    if (snprintf(g_link, sizeof(g_link), "%s/link", g_dir) >= (int)sizeof(g_link))
        fail_env("symlink path does not fit in g_link ($TMPDIR too long)", "init");
    if (!g_atexit_done) {
        if (atexit(cleanup) != 0)
            fail_env("atexit(cleanup)", "init");
        g_atexit_done = 1;
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    char probe[64];

    (void)argc;
    (void)argv;
    ensure_ready();

    /* Calibrate the comm oracle once: rename ourselves to a known value and see
     * whether the parser reports exactly that. If /proc is not readable (a
     * container without it) or the comm we read back differs, say so on stderr
     * and stop demanding success/exact content - the memory-safety checks stay. */
    if (prctl(PR_SET_NAME, "injprobe") != 0)
        fail_sys("prctl(PR_SET_NAME) during init");
    memset(probe, FP_PREFILL, sizeof(probe));
    if (proc__read_comm(getpid(), probe, sizeof(probe)) != 0) {
        g_proc_ok = 0;
        g_comm_exact = 0;
        degraded("/proc/<pid>/comm is not readable here, so read_comm success "
                 "and content expectations are downgraded to 'either' for this "
                 "ENTIRE run; the n==0/-1 contract and all buffer guards still "
                 "run, but the comm contract is not being verified");
    } else if (strcmp(probe, "injprobe") != 0) {
        g_comm_exact = 0;
        degraded("read_comm did not return the name just set with prctl, so the "
                 "exact-content oracle is disabled for this ENTIRE run "
                 "(memory-safety checks still run)");
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* libFuzzer may legally call this with data == NULL when size == 0, and the
     * 0-byte input is exactly the reproducer this harness must keep replaying
     * cleanly. NULL would flow into split_input()'s pointer arithmetic and into
     * the memcpy()s in test_maps()/test_comm(); memcpy(dst, NULL, 0) is UB even
     * at length 0, and with -fsanitize=undefined -fno-sanitize-recover=all the
     * nonnull-argument check aborts - turning a required clean replay into a
     * spurious crash. Substitute one static dummy byte: every segment then comes
     * out empty exactly as before, and no pointer in this file is ever NULL. */
    static const uint8_t null_input[1] = { 0 };
    size_t eff = (size > FP_MAX_INPUT) ? (size_t)FP_MAX_INPUT : size;
    split_t s;

    if (data == NULL)
        data = null_input;

    ensure_ready();
    split_input(data, eff, &s);

    test_maps(&s);
    test_link(&s);
    test_comm(&s);
    /* Exit-independent coverage report: this is what makes the skip counters
     * survive a worker torn down by _Exit() (see report_skips()). */
    maybe_report_skips();
    return 0;
}
