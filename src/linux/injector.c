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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <alloca.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <dlfcn.h>
#include <dirent.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <elf.h>
#include "proc.h"
#include "injector_internal.h"

/* MAJOR 7: every public entry point dereferences its injector_t* argument.
 * The Python and Go bindings pass NULL after close(), which used to SIGSEGV
 * the host process. Return INJERR_OTHER with a readable message instead.
 * The message lands in the thread-local buffer, i.e. it is readable through
 * injector_last_error(NULL) / injector_error(). */
#define INJECTOR_CHECK_HANDLE(inj) do {                                     \
    if ((inj) == NULL) {                                                    \
        injector__set_current(NULL);                                        \
        injector__reset_tl_errmsg();                                        \
        injector__set_errmsg("%s: injector handle is NULL", __func__);      \
        return INJERR_OTHER;                                                \
    }                                                                       \
} while (0)

/* MINOR 14: readlink("/proc/PID/exe") keeps the kernel's " (deleted)" marker
 * while the maps-derived path has it stripped, so the two never compared
 * equal for a deleted executable. */
static void strip_deleted_suffix(char *path)
{
    static const char suffix[] = " (deleted)";
    const size_t slen = sizeof(suffix) - 1;
    size_t len = strlen(path);
    if (len >= slen && strcmp(path + len - slen, suffix) == 0) {
        path[len - slen] = '\0';
    }
}

/* MINOR 15: `strstr(path, ".so")` also matched non-libraries such as
 * "/run/foo.socket". Require ".so" at the end of the name or followed by a
 * dot (libc.so.6, ld-linux-x86-64.so.2). */
static int path_is_shared_object(const char *path)
{
    const char *p = path;
    while ((p = strstr(p, ".so")) != NULL) {
        if (p[3] == '\0' || p[3] == '.') {
            return 1;
        }
        p += 3;
    }
    return 0;
}


static inline size_t remote_mem_size(injector_t *injector) {
    return 2 * injector->data_size + injector->stack_size;
}

/* remote_call.c: do these bytes read out of the target match one of the
 * trampolines injector itself writes at injector->code_addr? Declared at the
 * call site rather than in injector_internal.h, the way ptrace.c declares
 * injector__remote_call_reset(). */

int injector__attach_internal(injector_t **injector_out, pid_t pid, const injector_opts_t *o)
{
    injector_t *injector;
    int status;
    intptr_t retval;
    int prot;
    int rv = 0;

    injector__set_current(NULL);
    injector__reset_tl_errmsg();
    /* MAJOR 4: never leave the caller's out-param untouched on failure; a
     * caller that ignores the error code would otherwise hand an
     * uninitialized injector_t* to injector_detach(). Done before every
     * early return below. */
    if (injector_out != NULL) {
        *injector_out = NULL;
    }
    /* SAFETY: refuse pid <= 1. Attaching hijacks the target's libc entry with
     * an `int3` trampoline to run remote syscalls; doing that to init makes
     * pid 1 die on the trap and the kernel panics ("Attempted to kill init!"),
     * taking the whole host down. Confirmed on a real box. Non-intrusive
     * helpers (injector_target_info / injector_can_attach) only read /proc and
     * are deliberately left usable for pid 1. */
    if (pid <= 1) {
        injector__set_errmsg("refusing to attach to pid %d: attaching to init patches an int3 trampoline into its libc and will panic the host", (int)pid);
        return INJERR_NO_PROCESS;
    }
    injector = calloc(1, sizeof(injector_t));
    if (injector == NULL) {
        injector__set_errmsg("malloc error: %s", strerror(errno));
        return INJERR_NO_MEMORY;
    }
    /* current_inj stays NULL through the attach body so all attach-phase
     * errors land in the thread-local fallback and survive even though the
     * handle is freed by error_exit. Set to this handle only on success. */
    injector->pid = pid;
    injector->call_timeout_ms = o->call_timeout_ms;
    injector->mode = o->delivery;
    injector->timeout_action = o->timeout_action;
    injector->enable_write_mem = o->enable_write_mem;
    rv = injector__attach_process(injector);
    if (rv != 0) {
        goto error_exit;
    }
    injector->attached = 1;

    do {
        rv = waitpid(pid, &status, 0);
    } while (rv == -1 && errno == EINTR);
    if (rv == -1) {
        injector__set_errmsg("waitpid error while attaching: %s", strerror(errno));
        rv = INJERR_WAIT_TRACEE;
        goto error_exit;
    }

    rv = injector__collect_libc_information(injector);
    if (rv != 0) {
        goto error_exit;
    }
    rv = injector__get_regs(injector, &injector->regs);
    if (rv != 0) {
        goto error_exit;
    }
    rv = injector__read(injector, injector->code_addr, &injector->backup_code, sizeof(injector->backup_code));
    if (rv != 0) {
        goto error_exit;
    }

    /* MAJOR 1: refuse to adopt our own trampoline as the target's original
     * code.
     *
     * A handle that desynchronised (see remote_call.c's handle_timeout) can be
     * left with the `syscall; int3` or `call *rax; int3` trampoline still
     * patched into libc's e_entry, and the message it reports tells the user to
     * "Detach and attach again". Following that advice used to read those very
     * bytes into backup_code above, so from then on every "restore" - including
     * the verified one cleanup_restore_full() performs - wrote the int3 back and
     * reported success. The target's text is then permanently wrong and the
     * original bytes are unrecoverable, because they are exactly what is
     * missing; a live process that ever executes that address takes a SIGTRAP
     * with no tracer attached and dies (the same failure remote_call.c's
     * cleanup_restore_full() comment describes). On glibc the address is the
     * libc.so banner stub, which an ordinary process does not call, so the trap
     * is usually latent rather than immediate - but the corruption is real, it
     * is silent, it survives every later attach because each one re-adopts it,
     * and it is not ours to leave behind in a process that did nothing wrong.
     * That is worse than the leak the desync table was built to contain.
     *
     * Detect and refuse. Nothing here may repair or overwrite the target, and
     * the check is additive: injector__code_is_trampoline() matches the writers'
     * full pattern including their nop padding, which no compiler emits after
     * an int3 in a function prologue, so a clean target takes the same path it
     * always did. error_exit detaches, leaving the target exactly as found. */
    if (injector__code_is_trampoline(injector, &injector->backup_code)) {
        injector__set_errmsg("refusing to attach to pid %d: it is still carrying an injector trampoline at %p (its libc entry point), left behind by an earlier session that could not restore the original bytes. Attaching would adopt the trampoline as the target's original code, so every later restore would re-install it and the original bytes would be lost for good; the target dies if it ever executes %p again. It cannot be repaired automatically - do not re-attach to it.",
                             (int)pid, (void *)injector->code_addr, (void *)injector->code_addr);
        rv = INJERR_OTHER;
        goto error_exit;
    }

    injector->data_size = sysconf(_SC_PAGESIZE);
    injector->stack_size = 2 * 1024 * 1024;

    rv = injector__call_syscall(injector, &retval, injector->sys_mmap, 0,
                                remote_mem_size(injector), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    if (rv != 0) {
        goto error_exit;
    }
    if (retval == -1) {
        /* MINOR 13: injector__call_syscall() translates the remote -errno into
         * the local errno, so strerror(errno) here really is the TARGET's mmap
         * error -- say so explicitly instead of implying a local failure. */
        injector__set_errmsg("mmap error in the target process: %s", strerror(errno));
        rv = INJERR_ERROR_IN_TARGET;
        goto error_exit;
    }
    injector->mmapped = 1;
    injector->data = (size_t)retval;
    injector->stack = (size_t)retval + 2 * injector->data_size;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    injector->shellcode = (size_t)retval + 1 * injector->data_size;
    prot = PROT_READ | PROT_EXEC;
#else
    prot = PROT_NONE;
#endif
    /* Every injector__call_syscall()/injector__call_function() call site below
     * passes exactly six arguments: remote_call.c always reads six with
     * va_arg(), and supplying fewer makes it read past the caller's varargs
     * area -- ASan reports that as a dynamic-stack-buffer-overflow when the
     * over-read lands in an alloca()d buffer. The padding values are harmless:
     * the remote callee ignores registers beyond its own parameter list. */
    rv = injector__call_syscall(injector, &retval, injector->sys_mprotect,
                                injector->data + injector->data_size, injector->data_size,
                                prot, (long)0, (long)0, (long)0);
    if (rv != 0) {
        goto error_exit;
    }
    if (retval != 0) {
        /* MINOR 13: as above, errno is the TARGET's mprotect error. */
        injector__set_errmsg("mprotect error in the target process: %s", strerror(errno));
        rv = INJERR_ERROR_IN_TARGET;
        goto error_exit;
    }
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    rv = injector__write(injector, injector->shellcode, &injector_shellcode, injector_shellcode_size);
    if (rv != 0) {
        goto error_exit;
    }
    {
        size_t invoke_off = ((size_t)injector_shellcode_size + 15) & ~(size_t)15;
        injector->shellcode_invoke = injector->shellcode + invoke_off;
        rv = injector__write(injector, injector->shellcode_invoke,
                             &injector_shellcode_invoke, injector_shellcode_invoke_size);
        if (rv != 0) {
            goto error_exit;
        }
    }
#endif

    *injector_out = injector;
    injector__set_current(injector);
    return 0;
error_exit:
    injector_detach(injector);
    return rv;
}

int injector_inject(injector_t *injector, const char *path, void **handle)
{
    char abspath[PATH_MAX];
    int dlflags = RTLD_LAZY;
    size_t len;
    int rv;
    intptr_t retval;

    INJECTOR_CHECK_HANDLE(injector);
    injector__set_current(injector);
    injector->errmsg_set = 0;

    if (path == NULL) {
        injector__set_errmsg("path is NULL");
        return INJERR_FILE_NOT_FOUND;
    }
    if (path[0] == '/') {
        len = strlen(path) + 1;
    } else if (realpath(path, abspath) != NULL) {
        path = abspath;
        len = strlen(abspath) + 1;
    } else {
        injector__set_errmsg("failed to get the full path of '%s': %s",
                           path, strerror(errno));
        return INJERR_FILE_NOT_FOUND;
    }

    if (len > injector->data_size) {
        injector__set_errmsg("too long file path: %s", path);
        return INJERR_FILE_NOT_FOUND;
    }

    rv = injector__write(injector, injector->data, path, len);
    if (rv != 0) {
        return rv;
    }
    if (injector->dlfunc_type == DLFUNC_INTERNAL) {
#define __RTLD_DLOPEN	0x80000000 // glibc internal flag
        dlflags |= __RTLD_DLOPEN;
    }
    rv = injector__call_function(injector, &retval, injector->dlopen_addr, injector->data, dlflags,
                                 (long)0, (long)0, (long)0, (long)0);
    if (rv != 0) {
        return rv;
    }
    if (retval == 0) {
        char buf[256 + 1] = {0,};
        if (injector->dlerror_addr != 0) {
            rv = injector__call_function(injector, &retval, injector->dlerror_addr,
                                         (long)0, (long)0, (long)0, (long)0, (long)0, (long)0);
            if (rv == 0 && retval != 0) {
                injector__read(injector, retval, buf, sizeof(buf) - 1);
            }
        }
        if (buf[0] != '\0') {
            injector__set_errmsg("dlopen failed: %s", buf);
        } else {
            injector__set_errmsg("dlopen failed");
        }
        return INJERR_ERROR_IN_TARGET;
    }
    if (handle != NULL) {
        *handle = (void*)retval;
        /* Track for injector_uninject_all. Only track when the caller kept the
         * handle -- if the handle out-param was NULL there is nothing to
         * dlclose later. A failed inject (retval==0 dlopen) returns above. */
        if (injector->injected_count < sizeof(injector->injected_handles) / sizeof(injector->injected_handles[0])) {
            injector->injected_handles[injector->injected_count++] = *handle;
        } else {
            /* MINOR 11: the inject itself succeeded, so do NOT set an error
             * message here: include/injector.h documents that the message is
             * only updated when a function returns non-zero, and a non-empty
             * injector_last_error() after success contradicts that. The
             * library stays loaded; it just cannot be auto-uninjected. */
        }
    }
    return 0;
}

/* waitpid(2): without __WALL only "non-clone" children are waited for, where a
 * "clone" child is one that does not deliver SIGCHLD on termination. The
 * injector_inject_in_cloned_thread() helper clones with exit_signal 0, so its
 * child IS a clone child and a plain wait4() on it fails with ECHILD even
 * though the child is a visible zombie. __WALL waits for all children
 * regardless of type, which is correct for both clone sites. */
#ifndef __WALL
#define __WALL 0x40000000
#endif

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
/* Everything the local-signal fallback in nonstop_cleanup_child() needs to
 * identify the helper, captured right after clone() - the only moment when the
 * helper is certainly ours AND the target is certainly alive:
 *
 *   child_starttime   the helper's kernel start stamp, read as /proc/<child>
 *                     resolves in OUR namespace - so it is the HELPER's stamp
 *                     only when the namespaces match. Cross-namespace the same
 *                     number can name a stranger here, whose stamp would be
 *                     recorded and matched just as happily. A non-zero stamp is
 *                     therefore NOT evidence of a shared namespace (and 0 is not
 *                     proof of a different one): `pidns_shared` below is the only
 *                     thing that makes the number mean the helper, and the
 *                     fallback must keep requiring both. 0 - unreadable, so no
 *                     identity to check - disables it outright.
 *   target_starttime  the target's stamp, so "the target is gone" can be told
 *                     apart from "the target's pid was recycled by a stranger"
 *                     after the target died.
 *   pidns_shared      whether the helper's pid number means the same process in
 *                     our namespace as in the target's - the gate that makes
 *                     child_starttime mean anything, and so never dropped even
 *                     when a stamp looks convincing. This MUST be evaluated
 *                     while the target lives: nonstop_pidns_shared() compares
 *                     /proc/<target>/ns/pid, which disappears with the target,
 *                     and a dead target therefore used to look like "different
 *                     namespace" - exactly when the fallback is needed most
 *                     (MAJOR 1). A process's pid namespace cannot change during
 *                     its lifetime, so the answer stays valid until it dies. */
struct nonstop_child_ctx {
    pid_t target;
    /* MINOR 2: the target's thread-group leader - the pid that owns the mm the
     * helper shares, that the helper's PPid actually names, and whose lifetime
     * decides whether the helper can still be a child of a LIVE target. Equal
     * to `target` for an ordinary (leader) attach, and also used as the
     * fallback when /proc could not be read at clone time, in which case it is
     * simply the pre-fix anchor. */
    pid_t target_tgid;
    unsigned long long child_starttime;
    /* The stamp of `target_tgid`, NOT of `target`: for a non-leader-thread
     * attach /proc/<tid>/stat reports that one thread's start time and
     * /proc/<tid> disappears when the thread exits, neither of which says
     * anything about the process that has to be gone before the fallback may
     * signal. Read from the same pid nonstop_target_is_gone() later probes, so
     * the comparison stays self-consistent. */
    unsigned long long target_starttime;
    int pidns_shared;
};

/* Both functions are defined below with the NONSTOP delivery code. Both clone()
 * helpers need them: a CLONE_VM child that is never terminated and reaped stays
 * a zombie in the target's process table for as long as the target lives, and
 * outlives a dead target while pinning its mm. */
static void nonstop_cleanup_child(injector_t *inj, pid_t child, int graceful,
                                  const struct nonstop_child_ctx *ctx);
static void nonstop_child_ctx_init(pid_t target, pid_t child,
                                   struct nonstop_child_ctx *ctx);

int injector_inject_in_cloned_thread(injector_t *injector, const char *path, void **handle_out)
{
    void *data;
    injector_shellcode_arg_t *arg;
    const size_t file_path_offset = offsetof(injector_shellcode_arg_t, file_path);
    void * const invalid_handle = (void*)-3;
    char abspath[PATH_MAX];
    size_t pathlen;
    int rv;
    intptr_t retval;

    INJECTOR_CHECK_HANDLE(injector);
    injector__set_current(injector);
    injector->errmsg_set = 0;

    if (path == NULL) {
        injector__set_errmsg("path is NULL");
        return INJERR_FILE_NOT_FOUND;
    }
    if (injector->arch != ARCH_X86_64) {
        injector__set_errmsg("injector_inject_in_cloned_thread doesn't support %s.",
                             injector__arch2name(injector->arch));
        return INJERR_UNSUPPORTED_TARGET;
    }

    if (realpath(path, abspath) == NULL) {
        injector__set_errmsg("failed to get the full path of '%s': %s",
                           path, strerror(errno));
        return INJERR_FILE_NOT_FOUND;
    }
    pathlen = strlen(abspath) + 1;

    if (file_path_offset + pathlen > injector->data_size) {
        injector__set_errmsg("too long path name: %s", path);
        return INJERR_FILE_NOT_FOUND;
    }

    data = alloca(injector->data_size);
    memset(data, 0, injector->data_size);
    arg = (injector_shellcode_arg_t *)data;

    arg->handle = invalid_handle;
    arg->dlopen_addr = injector->dlopen_addr;
    arg->dlerror_addr = injector->dlerror_addr;
    arg->dlflags = RTLD_LAZY;
    if (injector->dlfunc_type == DLFUNC_INTERNAL) {
        arg->dlflags |= __RTLD_DLOPEN;
    }
    memcpy(arg->file_path, abspath, pathlen);

    rv = injector__write(injector, injector->data, data, injector->data_size);
    if (rv != 0) {
        return rv;
    }
    rv = injector__call_function(injector, &retval, injector->clone_addr,
                                 injector->shellcode, injector->stack + injector->stack_size - 4096,
                                 //CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID,
                                 CLONE_VM,
                                 injector->data, (long)0, (long)0);
    if (rv != 0) {
        /* Same DEFERRED LEAK as the identical path in injector_invoke_nonstop():
         * a target that dies during this remote clone can leave a CLONE_VM
         * helper whose pid never reached us, so nothing below can terminate or
         * reap it. See the note there for why a safely-gated /proc scan would
         * fix it and why it is deferred. */
        return rv;
    }
    if (retval == -1) {
        /* MINOR 13: clone() is a remote FUNCTION call, so unlike a remote
         * syscall its failure does NOT translate the target's errno into ours;
         * strerror(errno) here described an unrelated local error. */
        injector__set_errmsg("clone failed in the target process (remote return value: %ld)", (long)retval);
        return INJERR_ERROR_IN_TARGET;
    }
    /* clone() returned the child's pid in the target's namespace. This clone
     * uses exit_signal 0, so the target gets no SIGCHLD and will never reap the
     * child itself: without an explicit wait4 every call leaves one zombie in
     * the target for the rest of its life. Reap it on every exit path below. */
    const pid_t child = (pid_t)retval;
    /* Identity context for nonstop_cleanup_child()'s local-signal fallback; see
     * the same call in injector_invoke_nonstop(). */
    struct nonstop_child_ctx child_ctx;
    nonstop_child_ctx_init(injector->pid, child, &child_ctx);
    const struct timespec ts = {0, 100000000}; /* 0.1 second */
    void *handle;
    int cnt = 0;

retry:
    nanosleep(&ts, NULL);
    rv = injector__read(injector, injector->data, &handle, sizeof(handle));
    if (rv != 0) {
        nonstop_cleanup_child(injector, child, 0, &child_ctx);
        return rv;
    }
    if (handle == invalid_handle) {
        int max_retry_cnt = 50;
        if (++cnt <= max_retry_cnt) {
            goto retry;
        }
        injector__set_errmsg("dlopen doesn't return in %d seconds.", max_retry_cnt / 10);
        /* dlopen never returned: the child is stuck, so kill it as well. */
        nonstop_cleanup_child(injector, child, 0, &child_ctx);
        return INJERR_ERROR_IN_TARGET;
    }
    if (handle_out != NULL) {
        *handle_out = handle;
    }
    if (handle == NULL) {
        arg->file_path[0] = '\0';
        injector__read(injector, injector->data, data, injector->data_size);
        /* SUSPECTED 16: the page came from the target. A hostile target with
         * no NUL byte in it would make the "%s" below read past the end of
         * the alloca()d buffer, so force termination inside our own copy. */
        ((char *)data)[injector->data_size - 1] = '\0';
        if (arg->file_path[0] != '\0') {
            injector__set_errmsg("%s", arg->file_path);
        } else {
            injector__set_errmsg("dlopen error");
        }
        /* Reap only AFTER the dlerror text has been copied out of the shared
         * page: killing the child first could truncate that message. */
        nonstop_cleanup_child(injector, child, 0, &child_ctx);
        return INJERR_ERROR_IN_TARGET;
    }
    nonstop_cleanup_child(injector, child, 0, &child_ctx);
    return 0;
}
#endif

int injector_remote_func_addr(injector_t *injector, void *handle, const char* name, size_t *func_addr_out)
{
    int rv;
    intptr_t retval;
    size_t len;

    INJECTOR_CHECK_HANDLE(injector);
    if (name == NULL) {
        injector__set_current(injector);
        injector->errmsg_set = 0;
        injector__set_errmsg("name is NULL");
        return INJERR_FUNCTION_MISSING;
    }
    len = strlen(name) + 1;
    injector__set_current(injector);
    injector->errmsg_set = 0;

    if (len > injector->data_size) {
        injector__set_errmsg("too long function name: %s", name);
        return INJERR_FUNCTION_MISSING;
    }
    rv = injector__write(injector, injector->data, name, len);
    if (rv != 0) {
        return rv;
    }
    rv = injector__call_function(injector, &retval, injector->dlsym_addr, handle, injector->data,
                                 (long)0, (long)0, (long)0, (long)0);
    if (rv != 0) {
        return rv;
    }
    if (retval == 0) {
        injector__set_errmsg("function not found: %s", name);
        return INJERR_FUNCTION_MISSING;
    }
    *func_addr_out = (size_t)retval;
    return 0;
}

int injector_remote_call(injector_t *injector, intptr_t *retval, size_t func_addr, ...)
{
    va_list ap;
    int rv;
    INJECTOR_CHECK_HANDLE(injector);
    injector__set_current(injector);
    injector->errmsg_set = 0;
    va_start(ap, func_addr);
    rv = injector__call_function_va_list(injector, retval, func_addr, ap);
    va_end(ap);
    return rv;
}

int injector_remote_vcall(injector_t *injector, intptr_t *retval, size_t func_addr, va_list ap)
{
    INJECTOR_CHECK_HANDLE(injector);
    injector__set_current(injector);
    injector->errmsg_set = 0;
    return injector__call_function_va_list(injector, retval, func_addr, ap);
}

int injector_call(injector_t *injector, void *handle, const char* name)
{
    size_t func_addr;
    INJECTOR_CHECK_HANDLE(injector);
    int rv = injector_remote_func_addr(injector, handle, name, &func_addr);
    if (rv != 0) {
        return rv;
    }
    return injector__call_function(injector, NULL, func_addr,
                                   (long)0, (long)0, (long)0, (long)0, (long)0, (long)0);
}

int injector_uninject(injector_t *injector, void *handle)
{
    int rv;
    intptr_t retval;

    INJECTOR_CHECK_HANDLE(injector);
    injector__set_current(injector);
    injector->errmsg_set = 0;
    if (injector->libc_type == LIBC_TYPE_MUSL) {
        /* Assume that libc is musl. */
        injector__set_errmsg("Cannot uninject libraries under musl libc. See: https://wiki.musl-libc.org/functional-differences-from-glibc.html#Unloading_libraries");
        return INJERR_UNSUPPORTED_TARGET;
    }

    rv = injector__call_function(injector, &retval, injector->dlclose_addr, handle,
                                 (long)0, (long)0, (long)0, (long)0, (long)0);
    if (rv != 0) {
        return rv;
    }
    if (retval != 0) {
        injector__set_errmsg("dlclose failed");
        return INJERR_ERROR_IN_TARGET;
    }
    return 0;
}

int injector_detach(injector_t *injector)
{
    int rv = 0;
    /* MAJOR 7: NULL (e.g. after a failed attach, which now always sets
     * *out = NULL, or from a binding whose handle was already closed) used to
     * dereference NULL. There is nothing to detach and nothing to free, so
     * report an error instead of crashing. Detaching the same non-NULL
     * pointer twice remains a caller bug: the handle is freed here. */
    INJECTOR_CHECK_HANDLE(injector);
    /* current_inj = NULL so detach cleanup errors go to thread-local and
     * do not dangle after free(injector) below. Leave errmsg_set intact so
     * a caller reading injector_last_error() before detach sees the error. */
    injector__set_current(NULL);

    /* NIT 7: on a desynchronised handle this munmap is refused by
     * kick_then_wait_sigtrap() before it touches the target, so the mapping -
     * remote_mem_size() = 2 pages of data/shellcode plus the 2 MB stack, i.e.
     * 2 MB + 8 KB on a 4 KB-page host - stays in the target until the target
     * exits. The refusal is right for new work and wrong-looking for teardown,
     * but teardown has no safe route either, so the leak is unavoidable rather
     * than merely tolerated:
     *   - there is no non-executing primitive that can unmap another process's
     *     memory (process_vm_writev writes it, process_madvise only advises),
     *     so a remote munmap syscall is the ONLY way to give the region back;
     *   - a remote syscall has to patch the `0f 05 cc` trampoline into libc's
     *     e_entry and re-stop the target to remove it again, and this handle is
     *     marked desynchronised precisely because it can no longer guarantee
     *     that re-stop. Attempting it would trade a bounded 2 MB + 8 KB leak
     *     for a chance of leaving an int3 in a live process's entry point -
     *     the corruption injector__code_is_trampoline() now refuses to adopt.
     * It is not silent: injector_detach() returns the desync error below, so a
     * caller is never told the target was cleaned up when it was not. */
    if (injector->mmapped) {
        int r = injector__call_syscall(injector, NULL, injector->sys_munmap, injector->data,
                                       remote_mem_size(injector), (long)0, (long)0, (long)0, (long)0);
        if (r != 0 && rv == 0) rv = r;
    }
    if (injector->attached) {
        int r = injector__detach_process(injector);
        if (r != 0 && rv == 0) rv = r;
    }
    free(injector);
    return rv;
}

unsigned injector_abi_version(void) { return INJECTOR_ABI_VERSION; }

const char *injector_version_string(void) { return INJECTOR_VERSION; }

void injector__opts_normalize(injector_opts_t *o) {
    if (o->call_timeout_ms == 0) o->call_timeout_ms = 5000;
    /* delivery/timeout_action/enable_write_mem: 0 is the default enum/value, no change needed */
}

int injector__opts_copy(injector_opts_t *dst, const void *src, size_t src_size) {
    *dst = INJECTOR_OPTS_INIT;                 /* start from all-default */
    size_t n = src_size < sizeof(*dst) ? src_size : sizeof(*dst);
    if (n < offsetof(injector_opts_t, delivery) + sizeof(injector_delivery_t))
        return INJERR_OTHER;                   /* opts_size too small to even carry delivery */
    memcpy(dst, src, n);
    dst->opts_size = sizeof(*dst);
    injector__opts_normalize(dst);
    return 0;
}

int injector_attach_with_opts(injector_t **out, pid_t pid, const injector_opts_t *opts) {
    injector_opts_t o;
    injector__set_current(NULL);
    injector__reset_tl_errmsg();
    if (opts == NULL) {
        o = INJECTOR_OPTS_INIT;
        injector__opts_normalize(&o);
    } else {
        int rv = injector__opts_copy(&o, opts, opts->opts_size);
        if (rv) {
            injector__set_errmsg("invalid opts (opts_size too small)");
            return rv;
        }
    }
    return injector__attach_internal(out, pid, &o);
}

int injector_attach(injector_t **out, pid_t pid) {
    return injector_attach_with_opts(out, pid, NULL);
}

/* ---- Non-intrusive target introspection ---- */

static const char *machine_to_arch_str(int machine)
{
    switch (machine) {
    case EM_X86_64: return "x86_64";
    case EM_AARCH64: return "aarch64";
    case EM_386: return "i386";
    case EM_ARM: return "arm";
    case EM_MIPS: return "mips";
    case EM_PPC64: return "ppc64";
    case EM_PPC: return "ppc";
#ifdef EM_RISCV
    case EM_RISCV: return "riscv";
#endif
    default: return "unknown";
    }
}

/* Does `path` look like the C library? Returns 1 and sets *libc_str for a
 * glibc/musl mapping, 0 otherwise. */
static int libc_kind(const char *path, const char **libc_str)
{
    if (strstr(path, "/ld-musl-") != NULL) {
        *libc_str = "musl";
        return 1;
    }
    if (strstr(path, "/libc.so.6") != NULL || strstr(path, "/libc-2.") != NULL) {
        *libc_str = "glibc";
        return 1;
    }
    return 0;
}

int injector_target_info(pid_t pid, injector_target_info_t *out)
{
    char proc_path[64];
    FILE *fp;
    char line[1024];
    char libc_path[512];
    const char *libc_str = "unknown";
    int found_libc = 0;

    if (out == NULL) {
        injector__set_current(NULL);
        injector__reset_tl_errmsg();
        injector__set_errmsg("out is NULL");
        return INJERR_OTHER;
    }
    /* MINOR 8: kill(0, 0) and kill(-1, 0) succeed, so pid <= 0 used to be
     * reported as alive=1/can_attach=1 even though it means "my process
     * group"/"every process we may signal". Reject it up front. */
    if (pid <= 0) {
        injector__set_current(NULL);
        injector__reset_tl_errmsg();
        injector__set_errmsg("invalid pid %d", (int)pid);
        return INJERR_NO_PROCESS;
    }
    memset(out, 0, sizeof(*out));
    out->pid = pid;
    out->arch = "unknown";
    out->libc = "unknown";
    /* heuristic, same as injector_can_attach */

    /* alive: kill(pid, 0) == 0 (exists & permitted) or EPERM (exists, no perm). */
    if (kill(pid, 0) == 0) {
        out->alive = 1;
    } else if (errno == EPERM) {
        out->alive = 1;
    } else {
        out->alive = 0;  /* ESRCH: no such process */
        injector__set_current(NULL);
        injector__reset_tl_errmsg();
        injector__set_errmsg("no such process %d", (int)pid);
        return INJERR_NO_PROCESS;
    }

    out->ptrace_allowed = injector_can_attach(pid);

    /* exe / cwd / root / comm: empty string on failure (non-fatal). */
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", (int)pid);
    proc__read_link(proc_path, out->exe, sizeof(out->exe));
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cwd", (int)pid);
    proc__read_link(proc_path, out->cwd, sizeof(out->cwd));
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/root", (int)pid);
    proc__read_link(proc_path, out->root, sizeof(out->root));
    proc__read_comm(pid, out->comm, sizeof(out->comm));

    /* Scan /proc/PID/maps for the libc mapping to derive arch + libc flavor.
     * This reads only the on-disk libc file's ELF header; no ptrace attach. */
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/maps", (int)pid);
    fp = fopen(proc_path, "r");
    if (fp == NULL) {
        /* MINOR 12: include/injector.h documents INJERR_OTHER on read error;
         * returning 0 here reported success with arch/libc left "unknown". */
        int e = errno;
        injector__set_current(NULL);
        injector__reset_tl_errmsg();
        injector__set_errmsg("failed to open %s: %s", proc_path, strerror(e));
        return INJERR_OTHER;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        proc_map_t m;
        const char *kind;
        if (proc__parse_maps_line(line, &m) != 0) {
            continue;
        }
        if (m.deleted) {
            continue;
        }
        if (libc_kind(m.path, &kind)) {
            libc_str = kind;
            strncpy(libc_path, m.path, sizeof(libc_path) - 1);
            libc_path[sizeof(libc_path) - 1] = '\0';
            found_libc = 1;
            break;
        }
    }
    fclose(fp);

    if (found_libc) {
        int machine = 0;
        out->libc = libc_str;
        if (injector__read_elf_machine(libc_path, &machine) == 0) {
            out->arch = machine_to_arch_str(machine);
        }
    }

    return 0;
}

int injector_can_attach(pid_t pid)
{
    /* Heuristic only. See injector.h doc comment: not a guarantee. */
    /* MINOR 8: pid <= 0 is not a process (0 = own process group, -1 = all). */
    if (pid <= 0) {
        return 0;
    }
    if (kill(pid, 0) != 0 && errno != EPERM) {
        return 0;  /* not alive */
    }
    if (geteuid() == 0) {
        return 1;  /* root can usually attach */
    }
    /* /proc/sys/kernel/yama/ptrace_scope:
     *   0 = ptrace allowed for any process (cap_sys_ptrace not required)
     *   1 = only parent may trace children (we are generally not the parent)
     *   2 = admin-only; 3 = no ptrace at all
     * Absent file (old kernel) => treat as 0 (permissive). */
    FILE *fp = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    if (fp == NULL) {
        return 1;  /* old/unconfigured kernel: permissive default */
    }
    int scope = 0;
    if (fscanf(fp, "%d", &scope) != 1) {
        scope = 0;
    }
    fclose(fp);
    return scope == 0 ? 1 : 0;
}

int injector_read_mem(injector_t *inj, uintptr_t addr, void *buf, size_t len)
{
    INJECTOR_CHECK_HANDLE(inj);
    if (buf == NULL) {
        injector__set_current(inj);
        injector__set_errmsg("buf is NULL");
        return INJERR_OTHER;
    }
    injector__set_current(inj);
    inj->errmsg_set = 0;
    return injector__read(inj, (size_t)addr, buf, len);
}

int injector_write_mem(injector_t *inj, uintptr_t addr, const void *buf, size_t len)
{
    INJECTOR_CHECK_HANDLE(inj);
    if (buf == NULL) {
        injector__set_current(inj);
        injector__set_errmsg("buf is NULL");
        return INJERR_OTHER;
    }
    injector__set_current(inj);
    inj->errmsg_set = 0;
    if (!inj->enable_write_mem) {
        injector__set_errmsg("write_mem disabled (opts.enable_write_mem=1 required)");
        return INJERR_PERMISSION;
    }
    return injector__write(inj, (size_t)addr, buf, len);
}

int injector_resolve_symbol(injector_t *inj, const char *libname, const char *symbol, uintptr_t *addr)
{
    char proc[64];
    char exe_path[PATH_MAX];
    char exe_file[64];
    int exe_truncated = 0;
    char line[PATH_MAX * 2];
    proc_map_t m;
    FILE *fp;
    size_t map_start = 0;
    int found = 0;
    size_t bias = 0;
    size_t a = 0;
    int rv;

    INJECTOR_CHECK_HANDLE(inj);
    injector__set_current(inj);
    inj->errmsg_set = 0;

    /* M1: resolve a symbol in the TARGET EXECUTABLE by non-intrusive ELF
     * parsing (read /proc/PID/maps + the exe's .dynsym). No target code is
     * executed.
     *
     * The original plan was remote dlsym(RTLD_DEFAULT); it does NOT work with
     * this injector's remote-call mechanism: glibc's dlsym(RTLD_DEFAULT) (and
     * dlopen(NULL)) resolve the caller's link_map to pick the search
     * namespace, but the injector calls from anonymous mmap memory that has
     * no link_map, so the target SIGSEGVs. (Remote dlsym with a *real* handle
     * works fine, as injector_remote_func_addr already does for injected
     * libraries.) Parsing the exe's dynamic symbol table avoids the issue
     * entirely and needs no injection.
     *
     * M1 scope: only the target executable is searched. libname is accepted
     * but NOT used to scope the search (documented); searching all loaded
     * libraries is future work. */
    (void)libname;

    if (symbol == NULL) {
        injector__set_errmsg("symbol is NULL");
        return INJERR_OTHER;
    }

    snprintf(proc, sizeof(proc), "/proc/%d/exe", inj->pid);
    if (proc__read_link(proc, exe_path, sizeof(exe_path)) != 0) {
        injector__set_errmsg("failed to read %s: %s", proc, strerror(errno));
        return INJERR_NO_PROCESS;
    }
    /* MINOR 14: a readlink result that exactly fills the buffer is truncated,
     * and the kernel appends " (deleted)" for an unlinked executable. The
     * maps-derived path has neither, so strip the marker and remember the
     * truncation to fall back to a prefix match. The ELF itself is parsed
     * through /proc/PID/exe below, which stays valid in both cases. */
    exe_truncated = (strlen(exe_path) == sizeof(exe_path) - 1);
    strip_deleted_suffix(exe_path);

    snprintf(proc, sizeof(proc), "/proc/%d/maps", inj->pid);
    fp = fopen(proc, "r");
    if (fp == NULL) {
        injector__set_errmsg("failed to open %s: %s", proc, strerror(errno));
        return INJERR_NO_PROCESS;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (proc__parse_maps_line(line, &m) != 0) {
            continue;
        }
        if (strcmp(m.path, exe_path) == 0 ||
            (exe_truncated && strncmp(m.path, exe_path, strlen(exe_path)) == 0)) {
            if (!found || m.start < map_start) {
                map_start = m.start;
                found = 1;
            }
        }
    }
    fclose(fp);
    if (!found) {
        injector__set_errmsg("target executable %s not found in /proc/%d/maps",
                             exe_path, inj->pid);
        return INJERR_NO_LIBRARY;
    }

    /* Compute the runtime load bias. For ET_EXEC the symbol values are
     * absolute virtual addresses and the mapping already sits at the ELF
     * link base, so bias = 0. For ET_DYN (PIE exe / shared object) symbol
     * values are relative to the first PT_LOAD (p_vaddr 0 in practice), so
     * bias = the mapping start. injector__elf_load_bias reads e_type. */
    snprintf(exe_file, sizeof(exe_file), "/proc/%d/exe", inj->pid);
    rv = injector__elf_load_bias(exe_file, map_start, &bias);
    if (rv != 0) {
        return rv;
    }

    {
        const char *const names[1] = { symbol };
        size_t addrs[1] = { 0 };
        rv = injector__elf_find_symbols(exe_file, bias, names, addrs, 1);
        if (rv != 0) {
            return rv;
        }
        a = addrs[0];
    }
    if (a == 0) {
        injector__set_errmsg("symbol not found in target executable: %s", symbol);
        return INJERR_FUNCTION_MISSING;
    }
    if (addr != NULL) {
        *addr = (uintptr_t)a;
    }
    return 0;
}

/* ---- Module listing & bulk uninject ---- */

long injector_list_modules(injector_t *inj, injector_module_t *out, size_t cap)
{
    char path[64];
    FILE *fp;
    char line[1024];
    long count = 0;
    /* Adjacent-dedupe: a .so appears as several contiguous mappings
     * (r-xp, r--p, rw-p) in /proc/PID/maps. Comparing to the previous
     * basename collapses the common case without a large seen[] table.
     * A non-contiguously mapped .so (rare) may be listed twice, which is
     * acceptable for a listing API. */
    char prev[256];
    prev[0] = '\0';

    INJECTOR_CHECK_HANDLE(inj);
    injector__set_current(inj);
    inj->errmsg_set = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", (int)inj->pid);
    fp = fopen(path, "r");
    if (fp == NULL) {
        injector__set_errmsg("failed to open %s: %s", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        proc_map_t m;
        const char *base;
        if (proc__parse_maps_line(line, &m) != 0) {
            continue;
        }
        /* only shared libraries (MINOR 15: ".so" must end the name or be
         * followed by '.', so "/run/x.socket" is no longer listed) */
        if (!path_is_shared_object(m.path)) {
            continue;
        }
        base = strrchr(m.path, '/');
        base = base ? base + 1 : m.path;
        /* dedupe against the previous basename */
        if (prev[0] != '\0' && strcmp(base, prev) == 0) {
            continue;
        }
        strncpy(prev, base, sizeof(prev) - 1);
        prev[sizeof(prev) - 1] = '\0';

        if (out != NULL && (size_t)count < cap) {
            strncpy(out[count].name, m.path, sizeof(out[count].name) - 1);
            out[count].name[sizeof(out[count].name) - 1] = '\0';
            out[count].base = (uintptr_t)m.start;
        }
        count++;
    }
    fclose(fp);
    return count;
}

int injector_uninject_all(injector_t *inj)
{
    int rv = 0;
    size_t i;
    INJECTOR_CHECK_HANDLE(inj);
    injector__set_current(inj);
    inj->errmsg_set = 0;
    /* Delegate per-handle uninject to injector_uninject, which refuses musl
     * targets (INJERR_UNSUPPORTED_TARGET). The first non-zero error wins;
     * we keep trying the rest so a single bad handle doesn't strand others.
     * MAJOR 6: handles whose dlclose FAILED are retained, so the library can
     * still be released by a later call instead of becoming permanently
     * unreleasable, and the reported error and injector_last_error() are made
     * to agree (both describe the FIRST failure). */
    char first_errmsg[sizeof(inj->errmsg)];
    size_t kept = 0;
    first_errmsg[0] = '\0';
    for (i = 0; i < inj->injected_count; i++) {
        int r = injector_uninject(inj, inj->injected_handles[i]);
        if (r == 0) {
            continue;
        }
        if (rv == 0) {
            const char *e = injector_last_error(inj);
            rv = r;
            snprintf(first_errmsg, sizeof(first_errmsg), "%s", e ? e : "");
        }
        inj->injected_handles[kept++] = inj->injected_handles[i];
    }
    inj->injected_count = kept;
    if (rv != 0) {
        /* injector_uninject() reset errmsg_set on every attempt, so the buffer
         * now holds the LAST failure while rv is the FIRST one. */
        inj->errmsg_set = 0;
        injector__set_errmsg("%s", first_errmsg[0] ? first_errmsg : "uninject_all failed");
    }
    return rv;
}


/* ------------------------------------------------------------------ */
/* Library lifecycle + process lookup (public API)                    */
/* ------------------------------------------------------------------ */

static int lib_initialized;

int injector_library_init(void) {
    if (lib_initialized++ == 0) {
        /* reserved for future init (e.g. log handler setup in M4) */
    }
    return 0;
}

int injector_library_deinit(void) {
    if (lib_initialized > 0) {
        lib_initialized--;
    }
    return 0;
}

pid_t injector_find_process(const char *name) {
    DIR *dir = opendir("/proc");
    struct dirent *dent;
    pid_t pid = -1;

    if (dir == NULL) {
        /* best-effort: find_process has no handle to set an errmsg on. */
        return -1;
    }
    while ((dent = readdir(dir)) != NULL) {
        char path[sizeof(dent->d_name) + 11];
        char exepath[PATH_MAX];
        ssize_t len;
        char *exe;

        if (dent->d_name[0] < '1' || '9' < dent->d_name[0]) {
            continue;
        }
        sprintf(path, "/proc/%s/exe", dent->d_name);
        len = readlink(path, exepath, sizeof(exepath) - 1);
        if (len == -1) {
            continue;
        }
        exepath[len] = '\0';
        exe = strrchr(exepath, '/');
        if (exe != NULL && strcmp(exe + 1, name) == 0) {
            pid = atoi(dent->d_name);
            break;
        }
    }
    closedir(dir);
    return pid;
}


/* ---- One-shot invoke / run ---- */

static int injector_invoke_ptrace(injector_t *inj, const char *path, const char *symbol,
                                  const intptr_t *args, int argc,
                                  injector_result_t *out) {
    void *handle = NULL;
    int rv = injector_inject(inj, path, &handle);
    if (rv != 0) {
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }
    size_t func_addr = 0;
    rv = injector_remote_func_addr(inj, handle, symbol, &func_addr);
    if (rv != 0) {
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }
    intptr_t ret = 0;
    rv = injector__call_function(inj, &ret, (long)func_addr,
                                (long)(argc > 0 ? args[0] : 0),
                                (long)(argc > 1 ? args[1] : 0),
                                (long)(argc > 2 ? args[2] : 0),
                                (long)(argc > 3 ? args[3] : 0),
                                (long)(argc > 4 ? args[4] : 0),
                                (long)(argc > 5 ? args[5] : 0));
    if (rv != 0) {
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }
    if (out) out->retval = ret;
    return 0;
}

/* Read `pid`'s thread-group leader ("Tgid:" in /proc/<pid>/status). Returns 0
 * and sets *tgid_out on success, -1 otherwise, and leaves *tgid_out untouched on
 * failure so a caller's fallback value survives. errno is not meaningful on
 * return; callers that are mid-report save and restore it themselves.
 *
 * /proc resolves a non-leader THREAD's directory by direct lookup even though
 * the /proc root only enumerates group leaders - measured on Linux 6.8:
 * /proc/<tid>/{stat,status,ns/pid} all open, and kill(tid, 0) answers for a live
 * thread - so this works for a tid as well as for a pid. That is the whole
 * point: PPid, and the lifetime of the address space a CLONE_VM helper pins or a
 * trampoline is patched into, are properties of the GROUP, not of the one thread
 * a caller happened to attach to.
 *
 * Shared with remote_call.c's desync table, which needs the same answer and
 * cannot get it any other way: once a thread has exited there is no /proc entry
 * left to read its Tgid from, so it has to be captured while the task lives.
 * Declared locally at its call site there, the way ptrace.c declares
 * injector__remote_call_reset(). */
int injector__read_tgid(pid_t pid, pid_t *tgid_out)
{
    char path[64], line[256];
    FILE *f;

    if (pid <= 0 || tgid_out == NULL) {
        return -1;
    }
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char *end;
        long v;

        if (strncmp(line, "Tgid:", 5) != 0) {
            continue;
        }
        v = strtol(line + 5, &end, 10);
        fclose(f);
        if (end == line + 5 || v <= 0) {
            return -1;
        }
        *tgid_out = (pid_t)v;
        return 0;
    }
    fclose(f);
    return -1;
}

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
/* x86_64 syscall numbers, used to clean up the NONSTOP helper child from
 * inside the target. The nonstop delivery path is x86_64-only (see the
 * inj->arch check below), and injector->sys_* only carries mmap/mprotect/
 * munmap, so these are spelled out here. */
#define NONSTOP_SYS_kill  62
#define NONSTOP_SYS_wait4 61
/* 20ms x 5: how long INJECTOR_TIMEOUT_LEAVE lets the helper terminate on its
 * own before SIGKILL follows. Bounded so a hung helper cannot extend the
 * caller-visible latency of an invoke that has already timed out. */
#define NONSTOP_TERM_GRACE_POLLS 5

/* BLOCKER 2: is `pid_number` meaningful in OUR pid namespace?
 *
 * The helper's pid is the return value of clone() executed INSIDE the target,
 * so it is a pid in the TARGET's namespace. With a containerised target the
 * same number names a completely unrelated host process, and signalling it
 * from here would SIGKILL an innocent victim. If the namespaces cannot be
 * compared at all (no /proc, no nsfs), assume they differ: refusing to signal
 * locally is always safe, signalling the wrong process is not. */
static int nonstop_pidns_shared(pid_t target)
{
    struct stat self_ns, target_ns;
    char path[64];

    if (target <= 0) {
        return 0;
    }
    if (stat("/proc/self/ns/pid", &self_ns) != 0) {
        return 0;
    }
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", (int)target);
    if (stat(path, &target_ns) != 0) {
        return 0;
    }
    return self_ns.st_dev == target_ns.st_dev && self_ns.st_ino == target_ns.st_ino;
}

/* Is `child` still OUR helper, and not somebody else who inherited the number?
 *
 * Only meaningful when both processes share a pid namespace. A pid-namespace
 * check says nothing about RECYCLING: if the remote kill could not be performed
 * (typically because the target died), the helper is usually gone too and the
 * kernel is free to hand its pid to an unrelated process. Signalling that would
 * kill an innocent victim, so the local fallback has to prove identity first.
 * The helper is a clone() child of the thread we are driving, so its PPid is
 * that thread's TGID - the target process - and stays that until the whole
 * thread group dies; a recycled pid has a different parent. MINOR 2: PPid is
 * never a non-leader thread's TID (the kernel reports task_tgid_nr_ns of the
 * real parent), so identity has to be checked against the group, not against
 * the pid the caller happened to attach to. */
struct nonstop_proc_id {
    char state;                     /* field 3 of /proc/pid/stat */
    long ppid;                      /* field 4 */
    unsigned long long starttime;   /* field 22: the kernel's per-process stamp */
};

/* Read the identity fields of a process.
 *   0   success
 *  -1   the process is PROVABLY GONE: /proc/<pid>/stat does not exist. Only
 *       ENOENT counts - a hidepid /proc (EACCES) or an exhausted fd table
 *       (EMFILE) also fails to open, and answering "gone" for a process that is
 *       merely invisible is the unsafe direction, the same reason
 *       remote_call.c's desync_pid_gone() uses kill(pid, 0) rather than
 *       access("/proc/<pid>").
 *  -2   /proc answered but the content could not be parsed (short read, a comm
 *       field without a closing ')', a non-numeric field). The process may well
 *       be alive; callers must treat this as UNKNOWN, never as gone, and a
 *       caller proving identity must treat it as "not ours". */
static int nonstop_read_id(pid_t pid, struct nonstop_proc_id *out)
{
    char path[64], buf[1024];
    const char *after_comm, *p;
    FILE *f;
    size_t n;
    int field;

    if (pid <= 0 || out == NULL) {
        return -2;                              /* caller bug: nothing is known */
    }
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    f = fopen(path, "r");
    if (f == NULL) {
        return (errno == ENOENT) ? -1 : -2;     /* gone, vs. merely unreadable */
    }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    /* Field 2 (comm) is parenthesised and may itself contain spaces and
     * parentheses, so parse from the LAST ')' - everything after it is numeric
     * except the single-character state. strtoull rather than sscanf("%c %ld"):
     * starttime (field 22) has to be reached by counting, and a %*d skip list
     * long enough to do that is unreadable and brittle. */
    after_comm = strrchr(buf, ')');
    if (after_comm == NULL) {
        return -2;
    }
    p = after_comm + 1;
    while (*p == ' ') { p++; }
    if (*p == '\0') {
        return -2;
    }
    out->state = *p++;
    out->ppid = 0;
    out->starttime = 0;
    for (field = 4; field <= 22; field++) {
        char *end = NULL;
        unsigned long long v;

        while (*p == ' ') { p++; }
        if (*p == '\0') {
            return -2;
        }
        v = strtoull(p, &end, 10);
        if (end == p) {
            return -2;
        }
        p = end;
        if (field == 4) {
            out->ppid = (long)v;
        } else if (field == 22) {
            out->starttime = v;
            return 0;
        }
    }
    return -2;
}

/* The kernel start time (field 22 of /proc/<pid>/stat) of a process we own or
 * are about to signal. 0 when it cannot be read. */
static unsigned long long nonstop_proc_stamp(pid_t pid)
{
    struct nonstop_proc_id id;

    if (nonstop_read_id(pid, &id) != 0) {
        return 0;
    }
    return id.starttime;
}

static void nonstop_child_ctx_init(pid_t target, pid_t child, struct nonstop_child_ctx *ctx)
{
    pid_t tgid = 0;

    ctx->target = target;
    /* MINOR 2: resolve the thread group HERE, while the target is certainly
     * alive and its /proc entry certainly readable. Later - which is when the
     * answer is needed - the target is typically dead and nothing can say which
     * group a vanished pid belonged to. Falling back to `target` keeps the
     * pre-fix anchor when /proc will not answer, rather than disabling the
     * fallback altogether.
     *
     * The cost of that fallback, stated rather than left implicit: if `target`
     * is a NON-LEADER thread's tid and read_tgid failed (a hidepid /proc, or a
     * race with the thread exiting), then target_tgid is a tid, and that one
     * thread exiting makes nonstop_target_is_gone() report the whole target
     * gone while its process still lives. nonstop_child_is_ours() then rests on
     * the start stamp plus the namespace gate alone, without ppid confirmation
     * - the same residual documented at the stamp comparison below, reached by a
     * narrower route. Killing is still correct in that case (the helper is ours
     * and cleanup means to terminate it); what widens is only the window in
     * which a recycled pid wearing a matching stamp could be mistaken for it.
     * Rejected alternative: refusing the fallback when the tgid is unknown
     * trades that for a guaranteed helper leak, which is the bug being fixed.
     * injector__read_tgid() reads the same /proc/<pid>/stat field the stamp
     * reader does, so if it failed the stamp very likely failed too and
     * child_starttime == 0 already disables the whole fallback. */
    if (injector__read_tgid(target, &tgid) != 0 || tgid <= 0) {
        tgid = target;
    }
    ctx->target_tgid = tgid;
    ctx->child_starttime = nonstop_proc_stamp(child);
    ctx->target_starttime = nonstop_proc_stamp(tgid);
    ctx->pidns_shared = nonstop_pidns_shared(target);
}

/* Is the target gone? Only answerable when its stamp was captured while it was
 * alive; otherwise stay strict and say no. A zombie counts as gone: exit_notify()
 * has already reparented its children (so the helper's PPid is no longer the
 * target) and exit_mm() has already dropped the target's own mm reference, so it
 * can neither reap nor vouch for the helper any more.
 *
 * MINOR 2: "gone" is asked of the THREAD GROUP (ctx->target_tgid), not of the
 * pid the caller attached to. A non-leader thread can exit while its process
 * lives, and that is the wrong answer here in both directions: /proc/<tid>
 * disappearing with it used to read as "no /proc entry at all" -> gone, i.e. the
 * fallback concluded the helper had been reparented when in fact its parent was
 * alive and could still reap it. What actually has to be gone before the helper
 * may be signalled locally is the process - the thing that owns the mm the
 * helper pins and the thing its PPid names - and a thread's death says nothing
 * about that. Probing the group leader is also what makes the answer stable:
 * exit_notify() reparents a dying thread's children to another live thread of
 * the SAME group, and PPid is the reaper's TGID, so the helper's PPid does not
 * change at all when one thread exits. */
static int nonstop_target_is_gone(const struct nonstop_child_ctx *ctx)
{
    struct nonstop_proc_id tid;
    int rr;

    if (ctx->target_tgid <= 0 || ctx->target_starttime == 0) {
        return 0;
    }
    rr = nonstop_read_id(ctx->target_tgid, &tid);
    if (rr == -1) {
        return 1;                               /* /proc/<tgid> is absent: gone */
    }
    if (rr != 0) {
        /* /proc answered but could not be parsed, or could not be opened for a
         * reason other than ENOENT. Once PPid fails to match this is the only
         * gate left before the fallback signals a pid locally, and treating
         * "cannot tell" as "gone" is the unsafe direction: stay strict. */
        return 0;
    }
    if (tid.starttime != ctx->target_starttime) {
        return 1;                               /* recycled: OUR target is gone */
    }
    return tid.state == 'Z';
}

/* Is `child` still the helper we cloned, rather than somebody else wearing a
 * recycled pid? Called only when the remote kill could not be performed, i.e.
 * typically because the target just died, so `child`'s pid may already have
 * been handed to an unrelated process.
 *
 * The anchor is starttime, recorded while the helper was certainly ours: for a
 * stranger to be signalled, the kernel would have to recycle the very same pid
 * number AND start the new process in the very same clock tick, which is what
 * makes it safe to kill on that alone. PPid is a second, weaker anchor and is
 * NOT sufficient by itself - the helper is a child of the target, and so is any
 * process the target forks afterwards, so a target that forks steadily can hand
 * the recycled pid to a new child of its own and PPid would match again.
 *
 * NIT 8, stated explicitly because MAJOR 1 below turned the two anchors into an
 * alternative rather than a conjunction: starttime is field 22 of
 * /proc/<pid>/stat, in USER_HZ ticks, so on a 100 Hz host it only separates
 * processes that started more than 10 ms apart and two processes CAN share it.
 * The residual risk is nonetheless negligible, for three reasons that hold
 * together:
 *   - the number is not reusable at all until the helper has exited AND been
 *     reaped - by the target, or by init/a subreaper once the target died. A
 *     running or zombie helper still owns its pid, and the target is
 *     ptrace-stopped and cannot reap on its own (which is why
 *     nonstop_remote_reap() exists), so for most of this cleanup there is
 *     nothing to recycle into;
 *   - once it IS free, Linux hands pids out cyclically over the whole idr, so
 *     the same number is not offered again until pid_max other allocations have
 *     gone by: 32768 at the legacy minimum, 4194304 on this class of host
 *     (measured: /proc/sys/kernel/pid_max = 4194304, CLK_TCK = 100). Coming
 *     back round to it inside one 10 ms tick would need a sustained 3.3M
 *     forks/s at the minimum and 419M forks/s at the measured value;
 *   - every other gate still applies: the pid namespace must have been proven
 *     shared at clone time, and either PPid must name our target's thread group
 *     or that group must be provably gone.
 * The alternative to killing on that evidence is not "be safer": it is a
 * CLONE_VM helper that outlives its target and pins its mm_struct forever. A
 * startcode/endcode or /proc/<cand>/mem cookie anchor would be strictly
 * stronger but is not needed to make this decision, and both can fail to be
 * readable for a process we do not trace - failing closed on them would
 * re-open exactly the leak MAJOR 1 closed.
 *
 * MAJOR 1: PPid must not be *required*, either. When the target dies - the
 * normal outcome of a timeout or a crash during injector_invoke_nonstop() - the
 * helper is reparented before the target's /proc entry disappears, so
 * `ppid == target` is false BY CONSTRUCTION, and requiring it disabled the
 * fallback in precisely the case it exists for: the helper survived, and since
 * it shares the target's mm via CLONE_VM it pinned that mm (and the stack
 * injector_detach() munmaps) for good. So accept a reparented helper, but only
 * once the target is provably gone - a LIVE target whose child wears a different
 * parent is a stranger and is still refused. */
static int nonstop_child_is_ours(pid_t child, const struct nonstop_child_ctx *ctx)
{
    struct nonstop_proc_id id;

    if (child <= 0 || ctx->child_starttime == 0) {
        return 0;
    }
    if (nonstop_read_id(child, &id) != 0) {
        return 0;                               /* gone, or not provably ours */
    }
    if (id.starttime != ctx->child_starttime) {
        return 0;                               /* recycled pid: a stranger */
    }
    if (id.state == 'Z') {
        return 0;                               /* dead; SIGKILL would be a no-op */
    }
    /* MINOR 2: PPid is the parent's TGID, so comparing it with `target` alone
     * could never match a non-leader-thread attach, and with that thread still
     * alive nonstop_target_is_gone() answers no as well - the helper was left
     * running for every tid attach, which is precisely the leak MAJOR 1 was
     * written to close. `target_tgid` is the anchor; the `== target` disjunct
     * only carries weight when the TGID could not be read at clone time and
     * target_tgid fell back to target. */
    if (ctx->target > 0 &&
        (id.ppid == (long)ctx->target_tgid || id.ppid == (long)ctx->target)) {
        return 1;                               /* the ordinary live-target case */
    }
    return nonstop_target_is_gone(ctx);
}

/* kill(2) executed BY THE TARGET, the one process for which `child` is
 * unambiguous. Returns 0 when the outcome is known (*alive tells whether the
 * child still existed), -1 when it could not be determined (remote call
 * failure, or an unexpected errno). */
static int nonstop_remote_kill(injector_t *inj, pid_t child, int sig, int *alive)
{
    intptr_t r = 0;

    errno = 0;
    if (injector__call_syscall(inj, &r, NONSTOP_SYS_kill, (long)child, (long)sig,
                               (long)0, (long)0, (long)0, (long)0) != 0) {
        return -1;
    }
    if (r == 0) {
        if (alive != NULL) { *alive = 1; }
        return 0;
    }
    /* injector__call_syscall() turns a remote -errno into retval -1 + errno. */
    if (errno == ESRCH) {
        if (alive != NULL) { *alive = 0; }
        return 0;
    }
    return -1;
}

/* wait4(WNOHANG|__WALL) executed BY THE TARGET, the only process that can reap
 * the helper (waitpid() here would fail with ECHILD). Returns 0 when the outcome
 * is known - *reaped says whether the child is out of the target's process
 * table - and -1 when the remote call itself failed.
 *
 * This, not kill(child, 0), is how "has it terminated?" must be asked: an exited
 * helper is a ZOMBIE until the target reaps it, and the target is ptrace-stopped
 * and cannot reap on its own, so a zombie keeps answering kill(pid, 0)
 * indefinitely. __WALL is required because the clone child's exit_signal is
 * SIGCHLD but it is not a thread of the target either. */
static int nonstop_remote_reap(injector_t *inj, pid_t child, int *reaped)
{
    intptr_t w = 0;

    *reaped = 0;
    errno = 0;
    if (injector__call_syscall(inj, &w, NONSTOP_SYS_wait4, (long)child, (long)0,
                               (long)(WNOHANG | __WALL), (long)0, (long)0,
                               (long)0) != 0) {
        return -1;
    }
    if ((pid_t)w == child) {
        *reaped = 1;                          /* reaped just now */
        return 0;
    }
    if (w == -1 && errno == ECHILD) {
        *reaped = 1;                          /* already gone from its table */
        return 0;
    }
    return 0;                                 /* still running, or a zombie */
}

/* BLOCKER 1: terminate and reap the CLONE_VM helper child started by
 * injector_invoke_nonstop().
 *
 * The child shares the target's mm_struct. Left running (invoked function
 * hangs -> INJERR_TIMEOUT) it was never killed nor reaped: it survived the
 * target's death, was reparented to init and kept ~1.7MB of the target's
 * address space pinned forever, and injector_detach() munmapped the region
 * holding its stack. `graceful` (a timeout combined with INJECTOR_TIMEOUT_LEAVE)
 * sends SIGTERM first and waits briefly for the helper to terminate on its own;
 * SIGKILL always follows so the child cannot outlive the call on any path.
 * Best effort: failures here must not mask the caller's error code. */
static void nonstop_cleanup_child(injector_t *inj, pid_t child, int graceful,
                                  const struct nonstop_child_ctx *ctx)
{
    const struct timespec ts = {0, 20 * 1000 * 1000}; /* 20ms */
    char saved_errmsg[sizeof(inj->errmsg)];
    char saved_errmsg_set = inj->errmsg_set;
    int alive = 0;
    int reaped = 0;
    int unreachable = 0;
    int i;   /* reused by the SIGTERM grace loop and the reap loop */

    if (child <= 0) {
        return;
    }
    /* Best effort: this cleanup runs after the outcome of the invoke is known,
     * so its own diagnostics must not replace (or, on success, invent) the
     * caller-visible error message. */
    memcpy(saved_errmsg, inj->errmsg, sizeof(saved_errmsg));

    /* BLOCKER 2: kill from INSIDE the target. The previous code signalled the
     * child locally first and only fell back to a remote kill on EPERM, which
     * was wrong twice over:
     *   - cross-namespace, kill(child, SIGKILL) hits an unrelated host process
     *     that merely happens to own that pid number;
     *   - the fallback never ran when the local kill failed with ESRCH, which
     *     is exactly what a containerised target's pid looks like from here, so
     *     the helper was left alive, pinning the target's mm and running on a
     *     stack that injector_detach() then munmaps.
     * Note the local path is NOT a harmless extra: once the helper dies its pid
     * can be recycled, so a "belt and braces" local SIGKILL can still kill an
     * innocent process. It is therefore only used when the remote kill could
     * not be performed at all AND both processes share a pid namespace. */
    if (graceful) {
        (void)nonstop_remote_kill(inj, child, SIGTERM, NULL);
        /* INJECTOR_TIMEOUT_LEAVE promises the helper gets a chance to terminate,
         * and SIGKILL used to follow the SIGTERM with no gap at all, so the two
         * timeout actions behaved identically. Poll for a bounded moment - with a
         * remote wait4, because an exited helper is a zombie that still answers
         * kill(pid, 0) while the stopped target cannot reap it, so a liveness
         * probe here would never see the exit and would always burn the whole
         * grace period. */
        for (i = 0; i < NONSTOP_TERM_GRACE_POLLS; i++) {
            nanosleep(&ts, NULL);
            if (nonstop_remote_reap(inj, child, &reaped) != 0) {
                break;              /* target unreachable: waiting cannot help */
            }
            if (reaped) {
                goto done;          /* it terminated on its own, and is reaped */
            }
        }
    }
    if (nonstop_remote_kill(inj, child, SIGKILL, &alive) != 0) {
        unreachable++;
        /* Last resort, and a narrow one: the remote kill could not be performed
         * at all (target dead or desynced). Signalling locally is only safe when
         * the pid namespace was known to match - decided at clone time, because
         * by now the target's /proc/<pid>/ns/pid may be gone (MAJOR 1) - AND
         * /proc still shows the pid wearing the helper's own start stamp, still
         * as the target's child or provably reparented because the target died.
         * Otherwise the number may already have been recycled and we would
         * SIGKILL an unrelated process. This is the ONLY path that keeps a
         * CLONE_VM helper from outliving a dead target and pinning its mm. */
        if (ctx->pidns_shared && nonstop_child_is_ours(child, ctx)) {
            kill(child, SIGKILL);
        }
    }

    /* The child belongs to the TARGET's process table, so only the target can
     * reap it (waitpid() here would fail with ECHILD). An unreaped zombie no
     * longer pins the mm (exit_mm() dropped the reference), but reap it
     * anyway so repeated invokes do not litter the target with children. */
    for (i = 0; i < 10; i++) {
        nanosleep(&ts, NULL);
        if (nonstop_remote_reap(inj, child, &reaped) == 0) {
            unreachable = 0;
            if (reaped) {
                goto done;                      /* reaped */
            }
        } else {
            /* The child's death delivers SIGCHLD to the ptraced target, and the
             * first remote call after that stops with "unexpectedly stopped by
             * signal 17". The stop consumes (and discards) the signal, so simply
             * retry -- the next wait4 reaps the zombie. A target that is
             * unreachable for several calls in a row will not become reachable:
             * stop instead of burning one call timeout per iteration. */
            if (++unreachable >= 3) {
                goto done;
            }
            continue;
        }
        /* Still in the target's process table. A local kill(child, 0) would ask
         * about a different process cross-namespace, and about a recycled pid
         * even in the same one, so ask the target. */
        if (nonstop_remote_kill(inj, child, 0, &alive) == 0 && !alive) {
            goto done;
        }
    }
done:
    memcpy(inj->errmsg, saved_errmsg, sizeof(inj->errmsg));
    inj->errmsg_set = saved_errmsg_set;
}

static int injector_invoke_nonstop(injector_t *inj, const char *path, const char *symbol,
                                   const intptr_t *args, int argc,
                                   injector_result_t *out)
{
    char abspath[PATH_MAX];
    size_t pathlen, symlen;
    void *data;
    injector_shellcode_invoke_arg_t *arg;
    int rv;
    intptr_t clone_ret;

    if (inj->arch != ARCH_X86_64) {
        injector__set_errmsg("NONSTOP delivery requires x86_64");
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", "NONSTOP delivery requires x86_64");
        return INJERR_UNSUPPORTED_TARGET;
    }

    if (realpath(path, abspath) == NULL) {
        injector__set_errmsg("failed to get the full path of '%s': %s", path, strerror(errno));
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return INJERR_FILE_NOT_FOUND;
    }
    pathlen = strlen(abspath) + 1;
    symlen = strlen(symbol) + 1;

    const size_t hdr = offsetof(injector_shellcode_invoke_arg_t, file_path);
    size_t func_name_off = hdr + pathlen;
    if (func_name_off + symlen > inj->data_size) {
        injector__set_errmsg("path + symbol too long for data page");
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", "path + symbol too long");
        return INJERR_FILE_NOT_FOUND;
    }

    data = alloca(inj->data_size);
    memset(data, 0, inj->data_size);
    arg = (injector_shellcode_invoke_arg_t *)data;

    arg->status = 0;
    arg->dlopen_addr = inj->dlopen_addr;
    arg->dlsym_addr = inj->dlsym_addr;
    arg->dlerror_addr = inj->dlerror_addr;
    arg->dlflags = RTLD_LAZY;
    if (inj->dlfunc_type == DLFUNC_INTERNAL) {
#define __RTLD_DLOPEN_2 0x80000000
        arg->dlflags |= __RTLD_DLOPEN_2;
    }
    arg->func_name_off = (int32_t)func_name_off;
    for (int i = 0; i < argc && i < 6; i++) {
        arg->func_args[i] = args[i];
    }
    memcpy(arg->file_path, abspath, pathlen);
    memcpy((char*)data + func_name_off, symbol, symlen);

    rv = injector__write(inj, inj->data, data, inj->data_size);
    if (rv != 0) {
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }

    /* BLOCKER 1: SIGCHLD is the clone exit_signal (low byte of the flags).
     * Without it the kernel makes the child unwaitable -- wait4() in the
     * target returns ECHILD even while the child is a zombie -- so a killed
     * or exited helper would stay in the target's process table forever.
     * With it, nonstop_cleanup_child() below can reap the child remotely. */
    rv = injector__call_function(inj, &clone_ret, (long)inj->clone_addr,
                                 (long)inj->shellcode_invoke,
                                 (long)(inj->stack + inj->stack_size - 4096),
                                 (long)(CLONE_VM | SIGCHLD), (long)inj->data,
                                 (long)0, (long)0);
    if (rv != 0) {
        /* DEFERRED LEAK - deferred for scope, NOT because it cannot be fixed
         * safely. If the target died *during* this remote clone, clone() may
         * already have created the helper before its pid could reach us, so
         * `child` below is never known and nothing on any later path can
         * terminate or reap it. The helper shares the target's mm via CLONE_VM,
         * so it pins that whole mm_struct (our 2 MB + 8 KB region included) for
         * as long as it lives, keeps running on a stack that injector_detach()'s
         * munmap unmaps underneath it, and is reparented to init. Reproduced
         * both before and after the BLOCKER 1/2 fixes.
         *
         * A /proc scan CAN identify such a helper, and this note must not claim
         * that it cannot be done safely. The obvious gates are all available at
         * this point: PPid == the target's thread-group id, so only a child of
         * our own target is a candidate; starttime strictly LATER than a stamp
         * taken immediately before this call, so nothing that already existed can
         * match; pidns_shared, so the number names the same process here as it
         * does in the target; and a cookie written into inj->data before the
         * clone and read back from /proc/<cand>/mem. That is already a stronger
         * identity test than nonstop_child_is_ours() applies to a helper whose
         * pid IS known.
         *
         * Those four are necessary but NOT sufficient, and a note claiming
         * otherwise would be wrong: an ordinary fork() child the target happened
         * to create in the same window satisfies every one of them - same PPid,
         * a later starttime, the same namespace, and a COW copy of the data page
         * that reads the cookie back just as happily. What actually singles the
         * helper out is that it SHARES the target's mm rather than inheriting a
         * copy, so a sound scan needs a same-mm discriminator on top: kcmp(2)
         * with KCMP_VM, or an active handshake (a nonce only a process sharing
         * the mm can answer). Both are awkward exactly when they are needed -
         * the target is dead, so there is no surviving process to kcmp against
         * except another helper - which is a design problem to solve, not a
         * reason to signal on the four gates alone.
         *
         * It is not implemented because it is a new mechanism (a /proc walk, a
         * cookie protocol through the shared data page, and that discriminator)
         * and this change set is confined to the reviewed findings - not because
         * a safe version does not exist. Until it is, this path leaks one helper
         * per occurrence. */
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }
    if (clone_ret == -1) {
        /* MINOR 13: clone() is a remote FUNCTION call, so the target's errno is
         * not translated into ours; strerror(errno) described an unrelated
         * local error. Report the remote return value instead. */
        injector__set_errmsg("clone failed in the target process (remote return value: %ld)", (long)clone_ret);
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        return INJERR_ERROR_IN_TARGET;
    }

    /* BLOCKER 1: from here on the helper child exists and MUST be terminated
     * and reaped before this function returns, on every path. */
    const pid_t child = (pid_t)clone_ret;
    int rc;
    /* Record the helper's identity now, while it is certainly ours and the
     * target is certainly alive: if a remote kill later fails and cleanup has
     * to consider signalling the pid locally, nonstop_child_is_ours() needs
     * something a recycled pid cannot fake, and nonstop_pidns_shared() needs a
     * target that still has a /proc entry to compare namespaces against. */
    struct nonstop_child_ctx child_ctx;
    nonstop_child_ctx_init(inj->pid, child, &child_ctx);

    /* Main thread stays ptrace-stopped. The clone child (CLONE_VM, separate
     * process sharing the address space) runs the invoke shellcode. Poll the
     * data page via process_vm_readv — works on the stopped main thread's pid
     * because the address space is shared. */
    int64_t status = 0;
    unsigned timeout_ms = inj->call_timeout_ms ? inj->call_timeout_ms : 5000;
    struct timespec ts_poll, deadline, now;

    ts_poll.tv_sec = 0;
    ts_poll.tv_nsec = 20 * 1000 * 1000; /* 20ms */
    /* MAJOR 3: honour the requested timeout. The old code clamped the poll
     * count to a minimum of 50 x 100ms, so call_timeout_ms=200 actually
     * blocked ~5 s and then reported "timed out after 200 ms". Poll every
     * 20ms against a monotonic deadline; the do/while below guarantees at
     * least one poll iteration even for a 0/1ms timeout. */
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    do {
        nanosleep(&ts_poll, NULL);
        rv = injector__read(inj, inj->data + offsetof(injector_shellcode_invoke_arg_t, status),
                            &status, sizeof(status));
        if (rv != 0) {
            if (out) snprintf(out->errmsg, sizeof(out->errmsg), "failed to read result from target");
            rc = rv;
            goto cleanup;
        }
        if (status != 0) {
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec < deadline.tv_sec ||
             (now.tv_sec == deadline.tv_sec && now.tv_nsec < deadline.tv_nsec));

    if (status == 1) {
        /* MAJOR 2: `result` was uninitialized and the read's return value was
         * ignored, so a target that died mid-invoke returned success (0) with
         * a garbage out->retval. */
        intptr_t result = 0;
        rv = injector__read(inj, inj->data + offsetof(injector_shellcode_invoke_arg_t, retval),
                            &result, sizeof(result));
        if (rv != 0) {
            injector__set_errmsg("failed to read the return value from the target");
            if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
            rc = rv;
            goto cleanup;
        }
        if (out) out->retval = result;
        rc = 0;
    } else if (status == 2) {
        char errbuf[256] = {0,};
        injector__read(inj, inj->data + offsetof(injector_shellcode_invoke_arg_t, file_path),
                       errbuf, sizeof(errbuf) - 1);
        errbuf[sizeof(errbuf) - 1] = '\0';
        injector__set_errmsg("nonstop invoke failed: %s", errbuf[0] ? errbuf : "unknown error");
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        rc = INJERR_ERROR_IN_TARGET;
    } else {
        injector__set_errmsg("nonstop invoke timed out after %u ms", timeout_ms);
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        rc = INJERR_TIMEOUT;
    }

cleanup:
    /* BLOCKER 1 / injector->timeout_action: the child must never outlive this
     * call. A timeout with INJECTOR_TIMEOUT_LEAVE asks it to terminate first;
     * every other outcome - including a SUCCESSFUL invoke, where the helper has
     * already exited and is only waiting to be reaped - goes straight to
     * SIGKILL, because a grace period there would add latency to every invoke
     * without anything left to spare. SIGKILL always follows the SIGTERM too:
     * a surviving CLONE_VM child pins the target's mm_struct forever and
     * injector_detach() munmaps the stack it runs on. */
    nonstop_cleanup_child(inj, child,
                          rc == INJERR_TIMEOUT &&
                          inj->timeout_action == INJECTOR_TIMEOUT_LEAVE,
                          &child_ctx);
    return rc;
}
#endif

int injector_invoke(injector_t *inj, const char *path, const char *symbol,
                    const intptr_t *args, int argc,
                    injector_result_t *out) {
    if (out) { memset(out, 0, sizeof(*out)); }
    INJECTOR_CHECK_HANDLE(inj);
    injector__set_current(inj);
    inj->errmsg_set = 0;

    if (argc < 0 || argc > INJECTOR_MAX_INVOKE_ARGS) {
        injector__set_errmsg("argc must be 0-%d (got %d)", INJECTOR_MAX_INVOKE_ARGS, argc);
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        return INJERR_OTHER;
    }
    if (argc > 0 && args == NULL) {
        injector__set_errmsg("args is NULL but argc is %d", argc);
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        return INJERR_OTHER;
    }

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    if (inj->mode == INJECTOR_DELIVERY_NONSTOP ||
        (inj->mode == INJECTOR_DELIVERY_AUTO && inj->arch == ARCH_X86_64)) {
        return injector_invoke_nonstop(inj, path, symbol, args, argc, out);
    }
#endif
    if (inj->mode == INJECTOR_DELIVERY_NONSTOP) {
        injector__set_errmsg("NONSTOP delivery not available on this architecture");
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        return INJERR_UNSUPPORTED_TARGET;
    }
    return injector_invoke_ptrace(inj, path, symbol, args, argc, out);
}

int injector_run(pid_t pid, const char *lib, const char *symbol,
                 const intptr_t *args, int argc,
                 const injector_opts_t *opts, injector_result_t *out) {
    if (out) { memset(out, 0, sizeof(*out)); }
    injector_t *inj = NULL;
    int rv = injector_attach_with_opts(&inj, pid, opts);
    if (rv != 0) {
        if (out) { const char *e = injector__tl_errmsg(); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }
    rv = injector_invoke(inj, lib, symbol, args, argc, out);
    {
        /* MAJOR 5: the detach result was discarded, so a failed munmap or
         * PTRACE_DETACH after a successful invoke was reported as success.
         * Propagate it, but never mask an earlier invoke error. */
        int drv = injector_detach(inj);
        if (rv == 0) {
            rv = drv;
            if (rv != 0 && out) {
                const char *e = injector__tl_errmsg();
                snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : "");
            }
        }
    }
    return rv;
}