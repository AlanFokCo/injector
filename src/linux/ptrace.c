/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2018 Kubo Takehiro <kubo@jiubao.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#define _GNU_SOURCE
#include "injector_internal.h"

#include <sys/uio.h>   /* process_vm_readv/writev, struct iovec */
#include <unistd.h>    /* getpagesize */
#include <errno.h>
#include <stdlib.h>  /* the one-off regset size probe */
#include <sys/syscall.h> /* SYS_gettid: the tid of the thread that attached */

#include <elf.h>   /* NT_PRSTATUS, NT_FPREGSET, NT_X86_XSTATE */

#if defined(__aarch64__) || defined(__riscv)
#define USE_REGSET
#endif

#ifndef NT_FPREGSET
#define NT_FPREGSET 2
#endif
#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif

/* FPU/vector state slots (see the block above injector__get_regs). */
typedef struct fp_slot fp_slot_t;
static void fp_slot_release(pid_t pid);

static int set_ptrace_error(const char *request_name)
{
    int err = errno;
    injector__set_errmsg("%s error : %s", request_name, strerror(errno));
    switch (err) {
    case EFAULT:
        return INJERR_INVALID_MEMORY_AREA;
    case EPERM:
        return INJERR_PERMISSION;
    case ESRCH:
        return INJERR_NO_PROCESS;
    }
    return INJERR_OTHER;
}

/* -------------------------------------------------------------------------
 * Thread affinity: which thread may drive a handle.
 *
 * ptrace tracer ownership is PER-THREAD, not per-process: PTRACE_ATTACH makes
 * the *calling task* the tracer, and from any other thread of this process the
 * kernel answers PTRACE_GETREGS/SETREGS/POKETEXT/DETACH for that tracee with
 * ESRCH, exactly as if we were not tracing it at all. Measured on Linux 6.8
 * (x86_64): attach in thread A, then from thread B both PTRACE_GETREGS and
 * PTRACE_DETACH return -1/ESRCH while /proc/<target>/status keeps reporting
 * `State: t (tracing stop)` and `TracerPid: <A's tid>`. So the target is left
 * stopped and traced, and every later operation on the handle fails with a
 * message about a process that plainly exists.
 *
 * What CAN be fixed is the silence, and that is what this does: every operation
 * that would issue a ptrace request refuses BEFORE issuing it, and says which
 * two threads are involved. What CANNOT be fixed is the ownership itself - there
 * is no request that moves a tracee to another tracer (PTRACE_SEIZE from thread
 * B fails EPERM while A still traces it, and A cannot hand the tracee over), so
 * a handle driven from the wrong thread cannot be detached from there. The
 * kernel does release the target when the tracer THREAD exits (measured: the
 * same target went to `State: S`, `TracerPid: 0` as soon as thread A returned
 * from its start routine without detaching), which is the recovery the message
 * below points at.
 *
 * owner_tid is set by injector__attach_internal() once PTRACE_ATTACH has
 * succeeded, and is 0 while the handle is not attached (or if the tid could not
 * be read, in which case there is nothing to compare against and the gate stays
 * silent rather than inventing a refusal).
 *
 * Nothing in this library ever crosses threads on its own - src/linux has no
 * pthread_create and no clone() of the LOCAL process (the two clone() calls it
 * makes run INSIDE the target, see injector.c) - so the single-threaded flow,
 * injector_inject_in_cloned_thread() and injector_invoke_nonstop() all issue
 * every ptrace request from the caller's own thread and never reach a refusal.
 * ---------------------------------------------------------------------- */

/* This thread's kernel tid. syscall(SYS_gettid) rather than glibc's gettid():
 * the wrapper is only guaranteed from glibc 2.30, and this also has to build
 * against musl and for -m32/-mx32. 0 means "could not be determined". */
pid_t injector__current_tid(void)
{
#ifdef SYS_gettid
    long t = syscall(SYS_gettid);
    return (t > 0) ? (pid_t)t : 0;
#else
    return 0;
#endif
}

/* 0 when this thread may issue ptrace requests for `injector`. Otherwise the
 * request is refused BEFORE anything is sent to the target: errmsg names both
 * tids, errno is ESRCH (what the kernel would have said), and INJERR_OTHER is
 * returned - the same code the FP-slot refusal uses for "we refuse, the target
 * is untouched". Declared at its call sites in injector.c and remote_call.c the
 * way injector__remote_call_reset() is declared in ptrace.c, because
 * injector_internal.h is not this change's to edit. */
int injector__owner_thread_check(const injector_t *injector, const char *op)
{
    pid_t owner = injector->owner_tid;
    pid_t me;

    if (owner == 0) {
        return 0;          /* not attached, or the attaching tid is unknown */
    }
    me = injector__current_tid();
    if (me == 0 || me == owner) {
        return 0;          /* the right thread, or no way to tell: do not refuse */
    }
    injector__set_errmsg("%s refused: this handle was attached by thread %d and ptrace tracer "
                         "ownership is per-THREAD, so only that thread can issue ptrace requests "
                         "for pid %d. This is thread %d, from which the kernel answers "
                         "PTRACE_GETREGS/SETREGS/POKETEXT/DETACH with ESRCH while the target stays "
                         "stopped and traced, so nothing was attempted and the target is untouched. "
                         "Drive this handle - injector_detach() included - from thread %d; if that "
                         "thread cannot be used, exiting it releases the target (the kernel detaches "
                         "a tracee when its tracer thread exits).",
                         op, (int)owner, (int)injector->pid, (int)me, (int)owner);
    errno = ESRCH;
    return INJERR_OTHER;
}

#ifdef INJECTOR_NO_PROCESS_VM
/* Force the ptrace fallback path for testing. */
static int read_vm(pid_t pid, size_t addr, void *buf, size_t len)
{
    (void)pid; (void)addr; (void)buf; (void)len;
    return -1;
}
static int write_vm(pid_t pid, size_t addr, const void *buf, size_t len)
{
    (void)pid; (void)addr; (void)buf; (void)len;
    return -1;
}
#else
/*
 * Bulk memory I/O via process_vm_readv/process_vm_writev. A single
 * process_vm_*v call fails (rather than doing a partial transfer) if the
 * requested range crosses an unmapped page, so chunk by page boundary: each
 * chunk stays within one page. The common injector case (paths, names,
 * shellcode) is a single chunk.
 *
 * Returns 0 on full success, -1 on any failure (caller falls back to ptrace).
 */
static int read_vm(pid_t pid, size_t addr, void *buf, size_t len)
{
    size_t off = 0;
    long page = getpagesize();
    while (off < len) {
        /* bytes from (addr+off) to the end of its current page; 0 if page-aligned */
        size_t to_page_end = (size_t)(-(long)(addr + off) & (page - 1));
        size_t chunk = len - off;
        if (to_page_end != 0 && chunk > to_page_end) {
            chunk = to_page_end;
        }
        struct iovec liov = { (char *)buf + off, chunk };
        struct iovec riov = { (void *)(addr + off), chunk };
        ssize_t r = process_vm_readv(pid, &liov, 1, &riov, 1, 0);
        if (r != (ssize_t)chunk) {
            return -1;
        }
        off += chunk;
    }
    return 0;
}
static int write_vm(pid_t pid, size_t addr, const void *buf, size_t len)
{
    size_t off = 0;
    long page = getpagesize();
    while (off < len) {
        size_t to_page_end = (size_t)(-(long)(addr + off) & (page - 1));
        size_t chunk = len - off;
        if (to_page_end != 0 && chunk > to_page_end) {
            chunk = to_page_end;
        }
        struct iovec liov = { (void *)((const char *)buf + off), chunk };
        struct iovec riov = { (void *)(addr + off), chunk };
        ssize_t r = process_vm_writev(pid, &liov, 1, &riov, 1, 0);
        if (r != (ssize_t)chunk) {
            return -1;
        }
        off += chunk;
    }
    return 0;
}
#endif /* INJECTOR_NO_PROCESS_VM */

int injector__ptrace(int request, pid_t pid, long addr, long data, const char *request_name)
{
    if (ptrace(request, pid, addr, data) != 0) {
        return set_ptrace_error(request_name);
    }
    return 0;
}

/* remote_call.c: forget a stale "waitpid protocol out of sync" mark; a fresh
 * attach re-establishes it. */
void injector__remote_call_reset(pid_t pid);

int injector__attach_process(const injector_t *injector)
{
    PTRACE_OR_RETURN(PTRACE_ATTACH, injector, 0, 0);
    /* Never inherit a slot from an earlier session on this pid: pids are
     * recycled, and a leftover slot would make injector__get_regs() skip
     * saving this process's FP state and injector__set_regs() write the old
     * process's FPREGSET/XSTATE into it. */
    fp_slot_release(injector->pid);
    injector__remote_call_reset(injector->pid);
    return 0;
}

int injector__detach_process(const injector_t *injector)
{
    /* Refuse BEFORE the FP slot is released and before PTRACE_DETACH is
     * attempted. From a thread other than the tracer's, DETACH fails ESRCH and
     * the target is left stopped and traced; releasing the slot first would
     * also clear it in the WRONG thread's table (the slots are __thread), i.e.
     * do nothing at all here while the attaching thread keeps a slot bound to a
     * pid whose handle injector_detach() is about to free. See the thread
     * affinity block above. */
    {
        int rv = injector__owner_thread_check(injector, "injector_detach");
        if (rv != 0) {
            return rv;
        }
    }
    /* Release the slot *before* PTRACE_DETACH and independently of its result.
     * PTRACE_OR_RETURN returns early on failure (typically after a KILL_THREAD
     * timeout, when the thread is dying), and a slot left bound to a dead pid
     * is picked up later by whichever process recycles that pid - which then
     * gets the dead one's FP/vector state restored into it. */
    fp_slot_release(injector->pid);
    PTRACE_OR_RETURN(PTRACE_DETACH, injector, 0, 0);
    /* NIT 6: the "waitpid protocol out of sync" mark is dropped only now that
     * PTRACE_DETACH has SUCCEEDED - deliberately unlike the FP slot above, which
     * must be released first and unconditionally. The ordering matters in the one
     * case that counts: when DETACH fails the target is still traced by us and
     * may still be carrying a trampoline, and the marker is the only record of
     * that. Clearing it before the DETACH - or regardless of its result - would
     * unmark a live, still-traced, possibly still-patched pid whose handle
     * injector_detach() is about to free, and remote_call.c would then hand that
     * pid back as usable. Keeping the marker on a failed detach costs one slot
     * until the pid dies (desync_reclaim_dead) or is re-attached
     * (injector__attach_process above), which is exactly what the slot is for.
     *
     * Otherwise the reasoning that made it safe to drop at all still holds: a
     * detached handle can make no remote call, a re-attach clears the mark
     * anyway, and this only runs when injector->attached is set - a second
     * PTRACE_ATTACH on an already-traced pid fails, and the attach error path
     * never reaches here - so it cannot clear the mark of another LIVE handle
     * on the same pid. injector__attach_process() above has no matching
     * ordering problem: it resets only after PTRACE_ATTACH returned 0, so a
     * failed attach leaves the table untouched. */
    injector__remote_call_reset(injector->pid);
    return 0;
}


/* -------------------------------------------------------------------------
 * FPU / SSE / AVX state save & restore.
 *
 * injector__get_regs()/injector__set_regs() can only carry the integer
 * register set (that is what their signature allows).  Saving/restoring just
 * NT_PRSTATUS means a thread stopped with live xmm/ymm/zmm registers would
 * resume with whatever dlopen()/dlsym() left in them, silently corrupting the
 * target's floating-point and vector state.  The FP state is therefore stashed
 * here, keyed by pid:
 *
 *   injector__get_regs()    saves it the FIRST time it is called for a pid,
 *                           i.e. right after PTRACE_ATTACH and before any
 *                           remote call hijacks the thread.  Later calls only
 *                           fetch the *result* registers of a remote call and
 *                           must not overwrite the saved state.
 *   injector__set_regs()    restores it, so after every remote call - and
 *                           finally at PTRACE_DETACH - the target has exactly
 *                           the FP/vector state it had when we attached.
 *   injector__detach_process() drops the slot.
 *
 * A regset the kernel or the target does not support is skipped: a missing
 * NT_X86_XSTATE (no XSAVE) or NT_FPREGSET must never fail the attach. A regset
 * that EXISTS but is larger than the slot's buffer is the opposite case and
 * does fail the attach: saving it truncated would be indistinguishable from
 * saving it whole, and the truncated half could not be written back, so the
 * remote call would leave the target's high vector registers clobbered.
 *
 * The slots are thread-local (__thread), matching the one-handle-per-thread
 * model that util.c's injector__set_current() and remote_call.c's desync_pids
 * table already use.  Per-thread storage means concurrent handles in different
 * threads cannot race on the table (no torn entries, no cross-thread eviction
 * of a LIVE handle's slot) without any locking; at most FP_SLOTS handles can
 * be attached *per thread* at the same time. The FP_SLOTS+1'th attach in one
 * thread fails cleanly (injector__get_regs() reports INJERR_OTHER/EMFILE before
 * any register is touched, and the attach unwinds through PTRACE_DETACH) rather
 * than evicting a slot: an evicted slot belongs to a handle that is STILL
 * attached, and that handle would then (a) skip its FP restore in
 * injector__set_regs() and (b) re-save whatever its next injector__get_regs()
 * finds - which, after a remote call hijacked the thread, is the CALLEE's
 * FP/vector state. Restoring that copy corrupts the target permanently, so the
 * table is deliberately allowed to run out. The remedy is injector_detach() on
 * one of the thread's handles, or one thread per handle.
 *
 * A handle must also be DETACHED on the thread that ATTACHED it. The slots are
 * thread-local, so fp_slot_release() clears the slot in the *detaching* thread's
 * copy only: detach from another thread and the attaching thread keeps a slot
 * occupied by a pid it no longer holds, with nothing left to ever free it. After
 * FP_SLOTS such handles that thread refuses every further attach with EMFILE,
 * and the message - correctly, but unhelpfully - points at the handles it can
 * still see. The one-handle-per-thread model (util.c's injector__set_current(),
 * remote_call.c's desync table) already requires attach and detach to pair up on
 * one thread; a leaked FP slot is the second reason, and the per-thread nature
 * of ptrace tracer ownership (block above) is the third and the one the kernel
 * enforces. That is now said where users read it - include/injector.h documents
 * the affinity contract on the affected entry points - and
 * injector__detach_process() refuses a cross-thread detach up front, so the slot
 * leak cannot be reached by accident any more. README.md still does not mention
 * it; that file is outside this change's write scope.
 * The slots themselves are not heap-allocated (the only
 * malloc is the one-off size probe in regset_probe(), freed before it
 * returns), so there is nothing to free:
 * the TLS block for a thread is released by the runtime when the thread exits,
 * and fp_slot_release() clears a slot as soon as its handle detaches.
 * (The slots are only reachable through attach/get_regs/set_regs/detach. The
 * first access - and hence the TLS allocation - happens on the thread that
 * attaches, and get_regs/set_regs necessarily run on that same thread because a
 * handle is driven by one thread at a time. detach is *required* to run there as
 * well, for the reason given above: it is what frees the slot.)
 * ---------------------------------------------------------------------- */
#define FP_SLOTS      4
#define FP_STATE_SIZE 1024   /* NT_FPREGSET: the x86 fxsave area is 512 bytes */
#define XSTATE_SIZE   16384  /* NT_X86_XSTATE: 2696 bytes for AVX-512 on Linux
                              * 6.8; enough for AMX (XTILEDATA ~8KiB) too */

/* The kernel answers PTRACE_GETREGSET with EIO both for "there is no such
 * regset" (ptrace_regset() cannot find the NT_*) and for "your iov_len is not a
 * multiple of the regset's granularity". regset_probe() has to read EIO as the
 * former - it is the ordinary no-XSAVE / no-FPU case - which is only sound while
 * the probe length stays a multiple of every granularity in use (1 for xstate,
 * up to 16 for the arch FP regsets). Both buffers are multiples of 16 and the
 * probe doubles them, so this holds; assert it, because getting it wrong means
 * concluding "the target has no FP state", saving nothing, restoring nothing,
 * and leaving its vector registers as the remote call left them. */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(FP_STATE_SIZE % 16 == 0 && XSTATE_SIZE % 16 == 0,
               "FP_STATE_SIZE and XSTATE_SIZE must stay multiples of 16 - see the "
               "EIO ambiguity documented in regset_probe()");
#else
/* Same check for a compiler without C11's _Static_assert. src/linux/Makefile
 * only *appends* to CFLAGS, so a caller- or environment-supplied -std=gnu99
 * survives and lands here; GCC and Clang accept _Static_assert as an extension
 * in that mode (measured: gcc 13.3, -std=gnu99 and -std=c99 both build the
 * C11 spelling), a strict C99 compiler does not. A negative array size is the
 * portable spelling of "this must be false". */
typedef char injector_fp_sizes_must_stay_multiples_of_16[
    (FP_STATE_SIZE % 16 == 0 && XSTATE_SIZE % 16 == 0) ? 1 : -1];
#endif

struct fp_slot {
    pid_t pid;            /* 0: free slot; !=0: an attached handle owns it */
    size_t fp_len;        /* valid bytes in fp[]; 0: regset unavailable */
    size_t xs_len;        /* valid bytes in xs[]; 0: regset unavailable */
    size_t oversize;      /* >0: a regset needs this many bytes, see below */
    unsigned int oversize_ntype; /* which NT_* did not fit */
    char fp[FP_STATE_SIZE];
    char xs[XSTATE_SIZE];
};

static __thread fp_slot_t fp_slots[FP_SLOTS];

static fp_slot_t *fp_slot_find(pid_t pid)
{
    int i;
    for (i = 0; i < FP_SLOTS; i++) {
        if (fp_slots[i].pid == pid) {
            return &fp_slots[i];
        }
    }
    return NULL;
}

/* Find the slot for `pid`, or take a FREE one for it. Returns NULL when all
 * FP_SLOTS slots are held by other, still-attached handles.
 *
 * Deliberately no least-recently-used eviction: a non-free slot always belongs
 * to a handle that is attached right now (fp_slot_release() runs in
 * injector__detach_process(), and injector__attach_process() drops a stale slot
 * left behind by a recycled pid). Stealing it would leave that handle unable to
 * restore its target's FP/vector state - see the block comment above. Callers
 * must treat NULL as "refuse this operation", never as "proceed without FP". */
static fp_slot_t *fp_slot_acquire(pid_t pid)
{
    fp_slot_t *s = fp_slot_find(pid);
    int i;

    if (s != NULL) {
        return s;
    }
    for (i = 0; i < FP_SLOTS; i++) {
        if (fp_slots[i].pid == 0) {
            s = &fp_slots[i];
            s->pid = pid;
            s->fp_len = 0;
            s->xs_len = 0;
            s->oversize = 0;
            s->oversize_ntype = 0;
            return s;
        }
    }
    return NULL;
}

static void fp_slot_release(pid_t pid)
{
    fp_slot_t *s = fp_slot_find(pid);
    if (s != NULL) {
        s->pid = 0;
        s->fp_len = 0;
        s->xs_len = 0;
        s->oversize = 0;
        s->oversize_ntype = 0;
    }
}

/* PTRACE_GETREGSET / PTRACE_SETREGSET for a single regset.
 *
 * Deliberately does NOT go through injector__ptrace(): an unsupported regset
 * is an ordinary condition here and must neither fail the operation nor plant
 * a message in the handle's (sticky) error buffer.
 * Returns 0 on success, -1 on failure (errno is left as ptrace set it). */
static int regset_op(int request, pid_t pid, unsigned int type, void *buf, size_t len, size_t *out_len)
{
    struct iovec iov;

    iov.iov_base = buf;
    iov.iov_len = len;
    if (ptrace(request, pid, (void *)(long)type, &iov) != 0) {
        return -1;
    }
    if (out_len != NULL) {
        *out_len = iov.iov_len;
    }
    return 0;
}

/* How many bytes does the kernel really want to hand back for this regset?
 *
 * ptrace() clamps the returned length to min(iov_len, regset->n * regset->size),
 * so a read that EXACTLY fills our buffer is ambiguous: it may be complete, or
 * the regset may be larger and have been silently truncated. The old
 * "len < sizeof(buf)" test resolved that ambiguity by throwing the state away,
 * which on a future kernel (an xstate >= XSTATE_SIZE) would leave the target's
 * AVX-512/AMX registers unrestored after every remote call.
 *
 * Asking with iov_len == 0 does not work either - the kernel clamps that to 0
 * and copies nothing. So read once into a temporary buffer twice the size we
 * can store: the clamped length it reports is the true size (or "at least
 * 2x", which is enough to decide). Reading a regset has no side effect on the
 * tracee. Returns 0 when the regset is unavailable. */
#define REGSET_SAVED         0   /* from the probe: the real size is known */
#define REGSET_UNAVAILABLE   1   /* the kernel/target genuinely has no such regset */
#define REGSET_OVERSIZE      2   /* it exists and does not fit the slot */
#define REGSET_PROBE_FAILED  3   /* it exists but we could not read it; errno says why */

static int regset_probe(pid_t pid, unsigned int type, size_t minimum, size_t *out_size)
{
    size_t probe = minimum * 2;
    struct iovec iov;
    void *buf;
    int saved_errno;

    *out_size = 0;
    buf = malloc(probe);
    if (buf == NULL) {
        /* Transient, and about US - not a fact about the target's hardware. It
         * must not be reported as "the target has a 32768-byte xstate, rebuild
         * with a larger XSTATE_SIZE", which is what folding it into the oversize
         * case would say. */
        errno = ENOMEM;
        return REGSET_PROBE_FAILED;
    }
    iov.iov_base = buf;
    iov.iov_len = probe;
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)type, &iov) != 0) {
        saved_errno = errno;
        free(buf);
        errno = saved_errno;
        /* "No such regset" is ordinary (a kernel without XSAVE, an unsupported
         * NT_*). Everything else - EPERM, EACCES, EFAULT, EINTR - means the
         * regset IS there and we failed to read it. Reporting that as
         * "unavailable" would skip the save, skip the restore, and let every
         * remote call leave the target's vector registers clobbered, which is
         * exactly the failure the oversize path exists to prevent. */
        if (saved_errno == EIO || saved_errno == ENXIO || saved_errno == EINVAL ||
            saved_errno == ENODEV || saved_errno == EOPNOTSUPP) {
            return REGSET_UNAVAILABLE;
        }
        return REGSET_PROBE_FAILED;
    }
    free(buf);
    if (iov.iov_len == 0) {
        return REGSET_UNAVAILABLE;
    }
    *out_size = iov.iov_len;
    return REGSET_SAVED;
}

/* Read one regset into dst (dstsz bytes). *out_len receives the valid length,
 * *out_need the size the kernel says the regset really has. */
static int fp_regset_read(pid_t pid, unsigned int type, void *dst, size_t dstsz,
                          size_t *out_len, size_t *out_need)
{
    size_t need = 0;
    size_t len = 0;
    int r;

    *out_len = 0;
    *out_need = 0;
    r = regset_probe(pid, type, dstsz, &need);
    if (r != REGSET_SAVED) {
        return r;                    /* UNAVAILABLE, or PROBE_FAILED with errno set */
    }
    *out_need = need;
    if (need > dstsz) {
        return REGSET_OVERSIZE;      /* cannot be saved whole -> caller must refuse */
    }
    errno = 0;   /* a stale ESRCH/EPERM from the probe must not be blamed here */
    if (regset_op(PTRACE_GETREGSET, pid, type, dst, need, &len) != 0) {
        /* It exists and it fits, but the read into the slot failed. Same
         * reasoning as the probe: never pretend there was nothing to save. */
        if (errno == 0) {
            errno = EIO;
        }
        return REGSET_PROBE_FAILED;
    }
    if (len == 0 || len > dstsz) {
        errno = EIO;   /* the kernel promised `need` bytes and did not deliver */
        return REGSET_PROBE_FAILED;
    }
    *out_len = len;
    return REGSET_SAVED;
}

/* Returns REGSET_SAVED when every regset that exists was saved whole, otherwise
 * the reason it could not be (REGSET_OVERSIZE or REGSET_PROBE_FAILED);
 * s->oversize_ntype always says which regset it was and s->oversize its size
 * when that size is known (0 for a failed probe). */
static int fp_state_save(pid_t pid, fp_slot_t *s)
{
    size_t need = 0;
    int r;

    s->fp_len = 0;
    s->xs_len = 0;
    s->oversize = 0;
    s->oversize_ntype = 0;

    r = fp_regset_read(pid, NT_FPREGSET, s->fp, sizeof(s->fp), &s->fp_len, &need);
    if (r == REGSET_OVERSIZE || r == REGSET_PROBE_FAILED) {
        s->oversize_ntype = NT_FPREGSET;
        s->oversize = (r == REGSET_OVERSIZE) ? need : 0;
        return r;
    }
#if defined(__x86_64__) || defined(__i386__)
    r = fp_regset_read(pid, NT_X86_XSTATE, s->xs, sizeof(s->xs), &s->xs_len, &need);
    if (r == REGSET_OVERSIZE || r == REGSET_PROBE_FAILED) {
        s->oversize_ntype = NT_X86_XSTATE;
        s->oversize = (r == REGSET_OVERSIZE) ? need : 0;
        return r;
    }
#endif
    return REGSET_SAVED;
}

/* Returns 0 on success, otherwise the errno of the first failed regset. */
static int fp_state_restore(pid_t pid, fp_slot_t *s)
{
    if (s->fp_len > 0 && regset_op(PTRACE_SETREGSET, pid, NT_FPREGSET, s->fp, s->fp_len, NULL) != 0) {
        return errno;
    }
#if defined(__x86_64__) || defined(__i386__)
    /* XSTATE last: on x86 it is a superset of the legacy FP state. */
    if (s->xs_len > 0 && regset_op(PTRACE_SETREGSET, pid, NT_X86_XSTATE, s->xs, s->xs_len, NULL) != 0) {
        return errno;
    }
#endif
    return 0;
}

int injector__get_regs(const injector_t *injector, struct user_regs_struct *regs)
{
    /* Refuse before the FP slot is touched: from a non-tracer thread the regset
     * reads below fail ESRCH anyway, but only after this thread has taken a
     * slot and saved nothing into it. See the thread affinity block above. */
    {
        int rv = injector__owner_thread_check(injector, "PTRACE_GETREGS");
        if (rv != 0) {
            return rv;
        }
    }
    /* Save the target's FP/vector state once per attach session, before any
     * remote call hijacks the thread. Subsequent calls (which read back the
     * result registers of a remote call) must not overwrite it. */
    if (fp_slot_find(injector->pid) == NULL) {
        fp_slot_t *s = fp_slot_acquire(injector->pid);
        int fr;
        if (s == NULL) {
            /* This thread already holds FP_SLOTS attached handles. Refuse BEFORE
             * any register is read or written, exactly like the oversize case
             * below, so the caller's error_exit unwinds the attach with
             * PTRACE_DETACH and leaves no stopped orphan behind. Hijacking the
             * thread without a slot to save its FP state into would corrupt the
             * target the first time a remote call's result-registers get_regs
             * re-saved the callee's FP state for it.
             * INJERR_OTHER + EMFILE: nothing here is the TARGET's capability
             * (so not UNSUPPORTED_TARGET) and no allocation failed (so not
             * NO_MEMORY); EMFILE is the standard "too many open handles of this
             * kind in this process" errno, and the message names the remedy. */
            injector__set_errmsg("cannot save the FP/vector state of pid %d: this thread already "
                                 "holds %d attached injector handles and all %d FP-state slots are "
                                 "in use by them; refusing to hijack its registers, because a "
                                 "handle without a saved FP/vector copy cannot restore them after "
                                 "a remote call. Detach one of this thread's handles first "
                                 "(injector_detach), or drive each handle from its own thread",
                                 (int)injector->pid, FP_SLOTS, FP_SLOTS);
            errno = EMFILE;
            return INJERR_OTHER;
        }
        fr = fp_state_save(injector->pid, s);
        if (fr != REGSET_SAVED) {
            /* Either the target has an extended FPU state we cannot store, or we
             * could not read the state it does have. In both cases it could never
             * be restored, and hijacking the thread anyway would clobber
             * registers the target is entitled to keep (AVX-512/AMX and above).
             * Refuse BEFORE any register is touched, and drop the slot so a later
             * attach re-probes instead of reusing a half-saved one. Keep errno
             * aside first: injector__set_errmsg() may clobber it. */
            int why = (errno != 0) ? errno : EIO;
            int rv;
            if (fr == REGSET_OVERSIZE) {
                why = E2BIG;
                /* s->oversize is a LOWER bound, not the exact size: regset_probe()
                 * reads into a buffer of 2*dstsz and the kernel clamps the reported
                 * length to it, so all we know is "at least this many". Say so, and
                 * do not promise that one particular rebuild size is enough. */
                injector__set_errmsg("pid %d has a regset (NT_%s) of at least %zu bytes that does "
                                     "not fit injector's %zu-byte save buffer; refusing to hijack "
                                     "its registers (rebuild with a larger XSTATE_SIZE/FP_STATE_SIZE "
                                     "- at least %zu bytes, and possibly more, since the probe "
                                     "stops at twice the buffer size)",
                                     (int)injector->pid,
                                     s->oversize_ntype == NT_X86_XSTATE ? "X86_XSTATE" : "FPREGSET",
                                     s->oversize,
                                     s->oversize_ntype == NT_X86_XSTATE ? (size_t)XSTATE_SIZE
                                                                        : (size_t)FP_STATE_SIZE,
                                     s->oversize);
            } else {
                injector__set_errmsg("cannot save the FP/vector state of pid %d (NT_%s): %s; "
                                     "refusing to hijack its registers, because without a saved "
                                     "copy the remote call would leave them clobbered",
                                     (int)injector->pid,
                                     s->oversize_ntype == NT_X86_XSTATE ? "X86_XSTATE" : "FPREGSET",
                                     strerror(why));
            }
            /* The same mapping set_ptrace_error() uses, so a caller sees one
             * vocabulary: EFAULT is a bad memory area and anything unrecognised
             * is INJERR_OTHER - not UNSUPPORTED_TARGET, which is reserved for the
             * one case that really is about the target's capabilities (a regset
             * too large to store) and tells the user to rebuild with a bigger
             * buffer. ENOMEM is ours, from the probe's allocation. */
            rv = (fr == REGSET_OVERSIZE) ? INJERR_UNSUPPORTED_TARGET :
                 (why == ESRCH) ? INJERR_NO_PROCESS :
                 (why == EPERM || why == EACCES) ? INJERR_PERMISSION :
                 (why == EFAULT) ? INJERR_INVALID_MEMORY_AREA :
                 (why == ENOMEM) ? INJERR_NO_MEMORY : INJERR_OTHER;
            fp_slot_release(injector->pid);
            errno = why;
            return rv;
        }
    }

#ifdef USE_REGSET
    struct iovec iovec = { regs, sizeof(*regs) };
    PTRACE_OR_RETURN(PTRACE_GETREGSET, injector, NT_PRSTATUS, (long)&iovec);
#else
    PTRACE_OR_RETURN(PTRACE_GETREGS, injector, 0, (long)regs);
#endif
    return 0;
}

int injector__set_regs(const injector_t *injector, const struct user_regs_struct *regs)
{
    fp_slot_t *s = fp_slot_find(injector->pid);
    int fp_errno;
    int rv;

    /* Refuse before anything is written. This is the FIRST ptrace request of
     * every remote call, so it is also where a handle driven from the wrong
     * thread now stops - with a message naming both tids rather than the
     * ESRCH-from-SETREGS one it used to produce. See the thread affinity block
     * above. */
    rv = injector__owner_thread_check(injector, "PTRACE_SETREGS");
    if (rv != 0) {
        return rv;
    }

    /* MINOR 3: mirror injector__get_regs()' refusal instead of writing the
     * integer registers and then silently skipping the FP/XSTATE restore. No
     * slot means there is no saved copy to write back, so returning success
     * here would leave the target's floating-point and vector state as whatever
     * the callee put there - the exact silent corruption the get_regs refusal
     * exists to prevent. Refuse BEFORE anything is written, so the target keeps
     * every register it currently has rather than a half-restored set.
     *
     * How reachable is a NULL slot here, honestly? Not at all under the
     * documented one-handle-per-thread model: the slot is acquired by
     * injector__get_regs() during the attach, in the very thread that
     * PTRACE_ATTACH made the tracer, and PTRACE_SETREGS only succeeds from that
     * same thread; nothing releases the slot in between. fp_slot_release() has
     * exactly two callers: injector__detach_process(), which injector_detach()
     * runs only AFTER this handle's last remote call, and get_regs' own refusal
     * paths, which a handle that got this far has already passed. So this is a
     * guard, not a live-bug fix - but a necessary one,
     * because the slots are __thread and a handle driven from a DIFFERENT
     * thread than the one that attached does find no slot.
     *
     * Measured for that cross-thread case (attach in thread A, injector_detach()
     * from thread B, Linux 6.8): before this guard the caller got rv=-3
     * INJERR_NO_PROCESS with "PTRACE_SETREGS error: No such process", because
     * SETREGS from a non-tracer thread fails ESRCH and PTRACE_OR_RETURN returned
     * first - so the silent FP skip did not actually happen there either, and
     * what the caller saw was a confusing error that named neither the FP state
     * nor the real cause. With the guard it got rv=-1 INJERR_OTHER and a message
     * about the missing FP slot, which was accurate but still not the cause.
     * injector__owner_thread_check() at the top of this function now answers
     * that case first, with the real one: both tids, and the fact that ptrace
     * ownership is per-thread. The FP-slot refusal below is therefore reachable
     * only from the thread that attached, which is where a NULL slot really does
     * mean "no saved FP state".
     * Note that in the cross-thread scenario the target is NOT left detached and
     * runnable - PTRACE_DETACH from the non-tracer thread fails ESRCH too, so it
     * stays traced and stopped (TracerPid non-zero, state 't'). No refusal can
     * fix that; the kernel only releases the target when the tracer thread
     * detaches it or exits (both measured - see the thread affinity block).
     *
     * Where a same-thread NULL slot ever did occur, the caller is
     * kick_then_wait_sigtrap(), which calls set_regs() BEFORE writing the
     * trampoline: nothing is patched, the tracee is still stopped, and the
     * error unwinds the handle through injector_detach() -> PTRACE_DETACH, so
     * the target is left detached and runnable. cleanup_restore_full() also
     * calls this and reports a failure in *regs_rv (which makes
     * cleanup_remote_call() mark the handle desynchronised) rather than
     * claiming the registers came back. */
    if (s == NULL) {
        injector__set_errmsg("cannot restore the FP/vector state of pid %d: this thread holds no "
                             "FP-state slot for it, so there is no saved copy to write back; "
                             "refusing to set its registers, because an integer-only restore "
                             "would leave the target's floating-point and vector state clobbered",
                             (int)injector->pid);
        errno = EMFILE;
        return INJERR_OTHER;
    }

#ifdef USE_REGSET
    struct iovec iovec = { (void*)regs, sizeof(*regs) };
    PTRACE_OR_RETURN(PTRACE_SETREGSET, injector, NT_PRSTATUS, (long)&iovec);
#else
    PTRACE_OR_RETURN(PTRACE_SETREGS, injector, 0, (long)regs);
#endif
    /* `s` is non-NULL here: the refusal above is the only other way out. */
    fp_errno = fp_state_restore(injector->pid, s);
    if (fp_errno != 0) {
        /* The integer registers are back but the FP/vector state is not:
         * that is a real restore failure, not something to swallow. */
        injector__set_errmsg("failed to restore the FPU/vector state of pid %d: %s",
                             injector->pid, strerror(fp_errno));
        errno = fp_errno;
        return (fp_errno == ESRCH) ? INJERR_NO_PROCESS :
               (fp_errno == EPERM) ? INJERR_PERMISSION : INJERR_OTHER;
    }
    return 0;
}

int injector__read(const injector_t *injector, size_t addr, void *buf, size_t len)
{
    pid_t pid = injector->pid;
    long word;
    char *dest = (char *)buf;

    if (len > 0 && read_vm(pid, addr, buf, len) == 0) {
        return 0;
    }
    /* fall back to word-at-a-time PTRACE_PEEKTEXT.
     * process_vm_readv() above is NOT ptrace-scoped - it needs
     * ptrace_may_access(), which any thread of this process has - so a read
     * from another thread usually succeeds and is deliberately left alone.
     * PEEKTEXT is a ptrace request and the kernel answers it ESRCH from any
     * thread but the tracer, so refuse here, before the first one. */
    {
        int rv = injector__owner_thread_check(injector, "PTRACE_PEEKTEXT");
        if (rv != 0) {
            return rv;
        }
    }
    errno = 0;
    while (len >= sizeof(long)) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        if (word == -1 && errno != 0) {
            return set_ptrace_error("PTRACE_PEEKTEXT");
        }
        *(long*)dest = word;
        addr += sizeof(long);
        dest += sizeof(long);
        len -= sizeof(long);
    }
    if (len != 0) {
        char *src = (char *)&word;
        errno = 0;
        word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        if (word == -1 && errno != 0) {
            return set_ptrace_error("PTRACE_PEEKTEXT");
        }
        while (len--) {
            *(dest++) = *(src++);
        }
    }
    return 0;
}

int injector__write(const injector_t *injector, size_t addr, const void *buf, size_t len)
{
    pid_t pid = injector->pid;
    const char *src = (const char *)buf;

    if (len > 0 && write_vm(pid, addr, buf, len) == 0) {
        return 0;
    }
    /* fall back to word-at-a-time PTRACE_POKETEXT - a ptrace request, so unlike
     * the process_vm_writev() above it only works from the tracer thread. */
    {
        int rv = injector__owner_thread_check(injector, "PTRACE_POKETEXT");
        if (rv != 0) {
            return rv;
        }
    }
    while (len >= sizeof(long)) {
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, addr, *(long*)src);
        addr += sizeof(long);
        src += sizeof(long);
        len -= sizeof(long);
    }
    if (len != 0) {
        long word;
        char *dest;
        /* errno is stale-nonzero after a failed write_vm(); PEEKTEXT only sets
         * it on error, so it must be cleared or a legitimate -1 data word
         * (0xFF-filled target memory) is misreported as a ptrace failure. */
        errno = 0;
        word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        dest = (char*)&word;
        if (word == -1 && errno != 0) {
            return set_ptrace_error("PTRACE_PEEKTEXT");
        }
        while (len--) {
            *(dest++) = *(src++);
        }
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, addr, word);
    }
    return 0;
}

int injector__continue(const injector_t *injector)
{
    {
        int rv = injector__owner_thread_check(injector, "PTRACE_CONT");
        if (rv != 0) {
            return rv;
        }
    }
    PTRACE_OR_RETURN(PTRACE_CONT, injector, 0, 0);
    return 0;
}