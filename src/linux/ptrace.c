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
    /* Release the slot *before* PTRACE_DETACH and independently of its result.
     * PTRACE_OR_RETURN returns early on failure (typically after a KILL_THREAD
     * timeout, when the thread is dying), and a slot left bound to a dead pid
     * is picked up later by whichever process recycles that pid - which then
     * gets the dead one's FP/vector state restored into it. */
    fp_slot_release(injector->pid);
    PTRACE_OR_RETURN(PTRACE_DETACH, injector, 0, 0);
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
 * of a LIVE handle's slot) without any locking; FP_SLOTS concurrent handles
 * *per thread* are supported and an overflow evicts that thread's least
 * recently used slot.  The slots themselves are not heap-allocated (the only
 * malloc is the one-off size probe in regset_probe(), freed before it
 * returns), so there is nothing to free:
 * the TLS block for a thread is released by the runtime when the thread exits,
 * and fp_slot_release() clears a slot as soon as its handle detaches.
 * (The slots are only reachable through attach/get_regs/set_regs/detach, all of
 * which run on the thread owning the handle, so the first access - and hence
 * the TLS allocation - always happens on the thread that uses it.)
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
_Static_assert(FP_STATE_SIZE % 16 == 0 && XSTATE_SIZE % 16 == 0,
               "FP_STATE_SIZE and XSTATE_SIZE must stay multiples of 16 - see the "
               "EIO ambiguity documented in regset_probe()");

struct fp_slot {
    pid_t pid;            /* 0: free slot */
    unsigned int seq;     /* LRU counter */
    size_t fp_len;        /* valid bytes in fp[]; 0: regset unavailable */
    size_t xs_len;        /* valid bytes in xs[]; 0: regset unavailable */
    size_t oversize;      /* >0: a regset needs this many bytes, see below */
    unsigned int oversize_ntype; /* which NT_* did not fit */
    char fp[FP_STATE_SIZE];
    char xs[XSTATE_SIZE];
};

static __thread fp_slot_t fp_slots[FP_SLOTS];
static __thread unsigned int fp_slot_seq;

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

static fp_slot_t *fp_slot_acquire(pid_t pid)
{
    fp_slot_t *s = fp_slot_find(pid);
    int i;

    if (s != NULL) {
        s->seq = ++fp_slot_seq;
        return s;
    }
    s = &fp_slots[0];
    for (i = 0; i < FP_SLOTS; i++) {
        if (fp_slots[i].pid == 0) {
            s = &fp_slots[i];
            break;
        }
        if (fp_slots[i].seq < s->seq) {
            s = &fp_slots[i];
        }
    }
    s->pid = pid;
    s->seq = ++fp_slot_seq;
    s->fp_len = 0;
    s->xs_len = 0;
    s->oversize = 0;
    s->oversize_ntype = 0;
    return s;
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
    /* Save the target's FP/vector state once per attach session, before any
     * remote call hijacks the thread. Subsequent calls (which read back the
     * result registers of a remote call) must not overwrite it. */
    if (fp_slot_find(injector->pid) == NULL) {
        fp_slot_t *s = fp_slot_acquire(injector->pid);
        int fr = fp_state_save(injector->pid, s);
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
                injector__set_errmsg("pid %d has a %zu-byte regset (NT_%s) that does not fit "
                                     "injector's %zu-byte save buffer; refusing to hijack its "
                                     "registers (rebuild with a larger XSTATE_SIZE/FP_STATE_SIZE)",
                                     (int)injector->pid, s->oversize,
                                     s->oversize_ntype == NT_X86_XSTATE ? "X86_XSTATE" : "FPREGSET",
                                     s->oversize_ntype == NT_X86_XSTATE ? (size_t)XSTATE_SIZE
                                                                        : (size_t)FP_STATE_SIZE);
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

#ifdef USE_REGSET
    struct iovec iovec = { (void*)regs, sizeof(*regs) };
    PTRACE_OR_RETURN(PTRACE_SETREGSET, injector, NT_PRSTATUS, (long)&iovec);
#else
    PTRACE_OR_RETURN(PTRACE_SETREGS, injector, 0, (long)regs);
#endif
    if (s != NULL) {
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
    /* fall back to word-at-a-time PTRACE_PEEKTEXT */
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
    /* fall back to word-at-a-time PTRACE_POKETEXT */
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
    PTRACE_OR_RETURN(PTRACE_CONT, injector, 0, 0);
    return 0;
}