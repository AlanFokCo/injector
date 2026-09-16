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

/*!
 * \file injector.h
 * \brief Library for injecting a shared library into a Linux process
 */
#ifndef INJECTOR_H
#define INJECTOR_H

#include <sys/types.h>
#include <stddef.h>

/*!
 * \brief Process id type (\c pid_t)
 */
typedef pid_t injector_pid_t;

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

/*! \brief Operation succeeded. This is the only non-negative code. */
#define INJERR_SUCCESS 0               /* linux */
/*! \brief Unclassified failure; call \c injector_last_error() for the reason. Also used for the refusals that deliberately leave the target untouched: no FP-state slot free (\c errno is \c EMFILE) and a ptrace request issued from a thread other than the one that attached (\c errno is \c ESRCH). */
#define INJERR_OTHER -1                /* linux */
/*! \brief A local allocation failed. */
#define INJERR_NO_MEMORY -2            /* linux */
/*! \brief The pid is invalid or does not exist, or is one this library refuses to touch at all - notably pid 1 / \c init, attaching to which would patch a trampoline into its libc and panic the host. */
#define INJERR_NO_PROCESS -3           /* linux */
/*! \brief The shared library to inject, or libc in the target, could not be found or opened. */
#define INJERR_NO_LIBRARY -4           /* linux */
/*! \brief The injected code failed inside the target; for example \c dlopen returned NULL. The message carries the target-side reason where one is available. */
#define INJERR_ERROR_IN_TARGET -5      /* linux */
/*! \brief A path could not be opened, or was too long to fit the target's data page. */
#define INJERR_FILE_NOT_FOUND -6       /* linux */
/*! \brief \c ptrace(2) reported \c EFAULT: the address is not valid in the target's address space. */
#define INJERR_INVALID_MEMORY_AREA -7  /* linux */
/*! \brief Not permitted: \c ptrace(2) was denied (\c EPERM/\c EACCES, for example Yama or a missing \c CAP_SYS_PTRACE), or \ref injector_write_mem was called on a handle not attached with \c opts.enable_write_mem set. */
#define INJERR_PERMISSION -8           /* linux */
/*! \brief The target's architecture, ABI or libc is not supported by this build. This includes an x32-ABI target (\c EM_X86_64 with \c ELFCLASS32) - this project ships x86_64 LP64 and i386 runtimes only - and \ref injector_uninject / \ref injector_uninject_all against a musl-libc
 * target, which cannot \c dlclose what was loaded. Nothing else in the API
 * checks the target's libc: the inject and invoke paths gate on architecture
 * only, so a musl target injects normally and simply cannot be uninjected. */
#define INJERR_UNSUPPORTED_TARGET -9   /* linux */
/*! \brief The ELF file is malformed, truncated, or has fields this library refuses to trust. */
#define INJERR_INVALID_ELF_FORMAT -10  /* linux */
/*! \brief The ptrace/waitpid protocol for this handle is out of sync: an earlier remote call timed out and could not leave the target stopped, or this thread's desync table overflowed. Read the message before retrying - it says whether the target can still be repaired. */
#define INJERR_WAIT_TRACEE -11         /* linux */
/*! \brief The named symbol was not found in the target, or the name was NULL or too long. */
#define INJERR_FUNCTION_MISSING -12    /* linux */
/*! \brief A remote call did not complete within \c opts.call_timeout_ms. What happens to the target next is \c opts.timeout_action. */
#define INJERR_TIMEOUT -13            /* linux: remote call timed out */

/*! \brief Deprecated alias for \c INJERR_FUNCTION_MISSING; use that name. */
#define INJERR_NO_FUNCTION INJERR_FUNCTION_MISSING

/*! \brief ABI version these headers describe. Compare against \ref injector_abi_version()
 *         at run time to detect a header/library mismatch. */
#define INJECTOR_ABI_VERSION 1u
/*! \brief Library version as a string; the same value \ref injector_version_string() returns. */
#define INJECTOR_VERSION "1.0.0"
/*! \brief Largest \c argc accepted by \ref injector_invoke. */
#define INJECTOR_MAX_INVOKE_ARGS 6

/*!
 * \brief How a remote call is delivered inside the target.
 */
typedef enum {
    INJECTOR_DELIVERY_AUTO = 0,    /*!< Decide from the target's architecture: NONSTOP on
                                    *   x86_64, PTRACE on every other supported arch. The default. */
    INJECTOR_DELIVERY_NONSTOP = 1, /*!< Run the payload in a helper task created in the target with
                                    *   \c clone(CLONE_VM), so the target's own threads are not
                                    *   hijacked. x86_64 only; another arch fails with
                                    *   \c INJERR_UNSUPPORTED_TARGET. */
    INJECTOR_DELIVERY_PTRACE = 2,  /*!< Save the stopped thread's registers, point them at the
                                    *   payload and restore them afterwards. Any supported arch. */
} injector_delivery_t;

/*!
 * \brief What to do with the target when a remote call exceeds \c call_timeout_ms.
 */
typedef enum {
    INJECTOR_TIMEOUT_LEAVE = 0,       /*!< Stop the tracee again with \c SIGSTOP, restore its
                                       *   original registers and code, and return
                                       *   \c INJERR_TIMEOUT with the handle still attached and
                                       *   stopped. A following \ref injector_detach then unwinds
                                       *   cleanly and the target resumes at its original pc.
                                       *   The default. */
    INJECTOR_TIMEOUT_KILL_THREAD = 1, /*!< \c SIGKILL the task stuck running the hijacked code, and
                                       *   mark the handle desynchronised. Linux has no per-thread
                                       *   \c SIGKILL, so with \c INJECTOR_DELIVERY_PTRACE - where
                                       *   that task is a thread OF THE TARGET - this kills the
                                       *   whole target process. Only \c NONSTOP delivery can kill
                                       *   the stuck task on its own. */
} injector_timeout_action_t;

/*!
 * \brief Options for \ref injector_attach_with_opts.
 *
 * Initialise with \ref INJECTOR_OPTS_INIT and then set only the fields you want;
 * every field's zero value is a working default. \c opts_size is how this library
 * and your headers agree on the struct's layout, so do not set it by hand - a
 * caller built against older headers then gets the fields it knows about honoured
 * and the rest defaulted, instead of the library reading past the end of your
 * struct. An \c opts_size too small to carry a field it needs is rejected with
 * \c INJERR_OTHER rather than guessed at.
 */
typedef struct {
    size_t opts_size;                 /*!< \c sizeof(injector_opts_t) at your compile time. Set by
                                       *   \ref INJECTOR_OPTS_INIT; leave it alone. */
    injector_delivery_t delivery;     /*!< Default \c INJECTOR_DELIVERY_AUTO. */
    unsigned call_timeout_ms;         /*!< Per-remote-call timeout. 0 means 5000 ms. Honoured against
                                       *   a monotonic deadline, so a small value is not rounded up. */
    injector_timeout_action_t timeout_action; /*!< Default \c INJECTOR_TIMEOUT_LEAVE. */
    int enable_write_mem;             /*!< 0 (the default) makes \ref injector_write_mem refuse with
                                       *   \c INJERR_PERMISSION. Writing into a target is destructive
                                       *   and is off unless you ask for it. */
} injector_opts_t;

/*! \brief Default-initialiser for \ref injector_opts_t. It sets \c opts_size and leaves
 *         every other field at its documented default. */
#define INJECTOR_OPTS_INIT ((injector_opts_t){ .opts_size = sizeof(injector_opts_t) })

/*!
 * \brief Return the ABI version the LIBRARY was built with.
 * \return \c INJECTOR_ABI_VERSION as compiled into the library. Compare it with the
 *         \c INJECTOR_ABI_VERSION your headers carry before trusting a handle.
 */
unsigned injector_abi_version(void);

/*!
 * \brief Return the library version as a string (e.g. "1.0.0").
 */
const char *injector_version_string(void);

/*!
 * \brief Library lifecycle hooks (idempotent).
 * \remarks cgo bindings may call \c injector_library_init() at startup for
 *          predictable initialization. Currently near-no-op; reserved for
 *          future use (e.g. logging). Calling more than once is supported.
 * \return zero on success.
 */
int injector_library_init(void);

/*!
 * \brief Counterpart to \ref injector_library_init; also idempotent.
 * \return zero on success.
 * \remarks Reserved for symmetry with \c init and currently a near-no-op. It does
 *          NOT detach live handles: destroy those with \ref injector_detach first.
 */
int injector_library_deinit(void);

/*! \brief Opaque handle to one attached target process. Created by \ref injector_attach
 *         or \ref injector_attach_with_opts and destroyed by \ref injector_detach, which
 *         frees it - so a detached handle must not be used again, not even to read its
 *         error message. Thread-affine: see \ref injector_thread_affinity. */
typedef struct injector injector_t;

/*!
 * \brief Attach to the specified process.
 * \param[out]  injector the address where the newly created injector handle will be stored
 * \param[in]   pid      the process id to be attached
 * \return               zero on success. Otherwise, error code
 */
int injector_attach(injector_t **injector, injector_pid_t pid);

/*!
 * \brief Attach to the specified process with explicit options.
 * \param[out] out  the address where the newly created injector handle will be
 *                   stored; set to NULL if the attach fails
 * \param[in]  pid  the process id to be attached
 * \param[in]  opts options, or NULL for the defaults. Only the fields your
 *                   \c opts_size covers are read; see \ref injector_opts_t
 * \return          zero on success. Otherwise, error code - \c INJERR_OTHER when
 *                   \c opts_size is too small to carry a field this library needs
 * \remarks \ref injector_attach is this call with \c opts == NULL. The handle is
 *          thread-affine: every later operation on it, \ref injector_detach
 *          included, must come from the thread that attached it. See
 *          \ref injector_thread_affinity.
 */
int injector_attach_with_opts(injector_t **out, pid_t pid, const injector_opts_t *opts);

/*!
 * \page injector_thread_affinity Thread safety and thread affinity (Linux)
 *
 * An \c injector_t handle is not safe for concurrent use from multiple threads.
 * Use a handle from a single thread or serialize access. The per-handle error
 * buffer is read via \ref injector_last_error; the thread-local fallback (read
 * via \c injector_error() is intended only for the no-handle attach-failure case.
 *
 * \par Affinity is stronger than "serialize access"
 * On Linux a handle must be driven by the SAME thread that attached it, not
 * merely by one thread at a time. \c ptrace(2) tracer ownership is per-THREAD,
 * not per-process: \c PTRACE_ATTACH makes the calling task the tracer, and from
 * any other thread of this process the kernel answers
 * \c PTRACE_GETREGS/SETREGS/POKETEXT/DETACH for that target with \c ESRCH, as
 * if it were not traced at all. Measured on Linux 6.8/x86_64: attach in thread A,
 * then from thread B both \c PTRACE_GETREGS and \c PTRACE_DETACH fail \c ESRCH
 * while the target keeps reporting \c State: \c t and \c TracerPid: (A's tid).
 *
 * Every operation that would issue a ptrace request from another thread is
 * therefore refused BEFORE anything is sent to the target, with \c INJERR_OTHER
 * and a message naming both tids. Nothing is corrupted and the target is
 * untouched - but it also cannot be detached from there, because no ptrace
 * request moves a tracee to a different tracer. The kernel does release the
 * target when the tracer THREAD exits (measured: it returned to \c State: \c S
 * with \c TracerPid: \c 0), which is the recovery if the owning thread can no
 * longer be used. Note that \ref injector_detach destroys the handle whether or
 * not the detach succeeded, so a cross-thread detach leaves the target stopped
 * and traced with no handle left to detach it with.
 *
 * \par Applies to
 * \ref injector_detach, \ref injector_inject, \ref injector_uninject,
 * \ref injector_uninject_all, \ref injector_call,
 * \ref injector_remote_func_addr, \ref injector_remote_call,
 * \ref injector_remote_vcall, \ref injector_invoke, \ref injector_run (which
 * attaches, invokes and detaches, so all of it must run on one thread),
 * \ref injector_inject_in_cloned_thread, and the \c PEEKTEXT/POKETEXT fallback
 * of \ref injector_read_mem / \ref injector_write_mem. The \c process_vm_readv
 * and \c process_vm_writev fast path of those two is not ptrace-scoped and does
 * work from another thread, which is why the refusal is reported at the fallback
 * rather than at their entry point.
 */

/*!
 * \brief Detach from the attached process and destroy the specified handle.
 * \param[in]   injector the injector handle to destroy
 * \return               zero on success. Otherwise, error code
 * \remarks Thread affinity: must be called from the thread that attached. From
 *          any other thread \c PTRACE_DETACH fails \c ESRCH, so this returns
 *          \c INJERR_OTHER having done nothing to the target - and the handle is
 *          destroyed anyway, leaving the target stopped and traced until the
 *          thread that attached detaches it or exits. See the affinity note at
 *          \ref injector_thread_affinity.
 */
int injector_detach(injector_t *injector);

#if defined(INJECTOR_DOC) || defined(__linux__)
/*!
 * \brief What \ref injector_target_info reports about a process (Linux only).
 *
 * Every field comes from /proc/PID; the process is never ptrace-attached, so
 * reading these is safe before you decide whether to inject.
 */
typedef struct {
    pid_t pid;            /**< The process id this describes. */
    int alive;            /**< 1 if the process exists. */
    int ptrace_allowed;   /**< Heuristic: 1 if an attach would likely succeed. */
    const char *arch;     /**< "x86_64"/"aarch64"/"i386"/"arm"/"mips"/"ppc64"/"ppc"/"riscv"/"unknown". */
    const char *libc;     /**< "glibc"/"musl"/"unknown". */
    char exe[4096];       /**< /proc/PID/exe. */
    char cwd[4096];       /**< /proc/PID/cwd. */
    char root[4096];      /**< /proc/PID/root. */
    char comm[16];        /**< /proc/PID/comm. */
} injector_target_info_t;

/*!
 * \brief Non-intrusive target introspection (Linux only).
 *
 * Reads /proc/PID to fill \c out. Does NOT ptrace-attach to the target, so it is
 * safe to call before deciding whether to inject.
 *
 * \param[in]  pid  the process id to inspect
 * \param[out] out  destination struct (zeroed by the call)
 * \return          zero on success, \c INJERR_NO_PROCESS if \c pid is absent,
 *                  \c INJERR_OTHER on a read error. Unreadable fields are empty;
 *                  \c arch and \c libc are "unknown" when no libc mapping is found.
 */
int injector_target_info(pid_t pid, injector_target_info_t *out);

/*!
 * \brief Heuristic pre-check whether injector_attach() would likely succeed (Linux only).
 *
 * BEST-EFFORT heuristic, NOT a guarantee. Inspects
 * /proc/sys/kernel/yama/ptrace_scope and the caller euid; does not attach.
 * 1 = probably attachable, 0 = probably not. The authoritative check is
 * injector_attach() itself.
 */
int injector_can_attach(pid_t pid);

/*!
 * \brief Find a running process by executable basename (Linux only).
 * \param[in] name  executable basename to match (e.g. "mysvc")
 * \return          the pid on success, -1 if not found.
 * \remarks Scans /proc, reading each /proc/PID/exe symlink and comparing the
 *          basename. "Not found" (-1) is a normal result, not an error.
 */
pid_t injector_find_process(const char *name);
#endif


/*!
 * \brief Inject the specified shared library into the target process.
 * \param[in]   injector the injector handle specifying the target process
 * \param[in]   path     the path name of the shared library
 * \param[out]  handle   the address where the newly created module handle will be stored
 * \return               zero on success. Otherwise, error code
 *
 * Note on Linux:
 * This calls functions inside of the target process interrupted by \c ptrace().
 * If the target process is interrupted while holding a non-reentrant lock and
 * injector calls a function requiring the same lock, the process stops forever.
 * If the lock type is reentrant, the status guarded by the lock may become inconsistent.
 * As far as I checked, \c dlopen() internally calls \c malloc() requiring non-reentrant
 * locks. \c dlopen() also uses a reentrant lock to guard information about loaded files.
 * \remarks Thread affinity: drive this handle from the thread that attached it.
 *          A remote call from another thread is refused before anything is
 *          written to the target (\c INJERR_OTHER, both tids named).
 */
int injector_inject(injector_t *injector, const char *path, void **handle);

/*!
 * \brief Uninject the shared library specified by \c handle.
 * \param[in]   injector the injector handle specifying the target process
 * \param[in]   handle   the module handle created by \c injector_inject
 * \return               zero on success. Otherwise, error code
 * \remarks This fearute isn't supported for musl-libc processes.
 *     See [Functional differences from glibc](https://wiki.musl-libc.org/functional-differences-from-glibc.html#Unloading_libraries).
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_uninject(injector_t *injector, void *handle);

#if defined(INJECTOR_DOC) || defined(__linux__)
/*!
 * \brief Call the specified function taking no arguments in the target process (Linux only)
 * \param[in]   injector the injector handle specifying the target process
 * \param[in]   handle   the module handle created by \c injector_inject or special-handles such as \c RTLD_DEFAULT
 * \param[in]   name     the function name
 *
 * The \c handle and \c name arguments are passed to \c dlsym ([Linux](https://man7.org/linux/man-pages/man3/dlvsym.3.html)) and then the return value of \c dlsym is called without arguments in the target process.
 *
 * This is same with the combination of injector_remote_func_addr() and injector_remote_call() without extra arguments.
 *
 * \note
 *   If the function in the target process internally calls non-[async-signal-safe]((https://man7.org/linux/man-pages/man7/signal-safety.7.html))
 *   functions, it may stop the target process or cause unexpected behaviour.
 * \sa injector_remote_func_addr(), injector_remote_call(), injector_remote_vcall()
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_call(injector_t *injector, void *handle, const char* name);
#endif

/*!
 * \brief Get the message of the last error. (deprecated)
 * \remarks Deprecated: use \ref injector_last_error. Returns the thread-local
 *          fallback only; after handle operations (inject/remote_call/uninject/...)
 *          it may be empty or stale -- use \c injector_last_error(inj) to read a
 *          handle's last error.
 */
__attribute__((deprecated("use injector_last_error")))
const char *injector_error(void);

/*!
 * \brief Get the message of the last error for the specified handle (per-handle).
 * \param[in]   injector the injector handle, or NULL to read the thread-local fallback
 * \remarks The message is updated only when \c injector functions return non-zero.
 *          Use this instead of the deprecated injector_error() when a handle is available
 *          so that concurrent operations on different targets do not clobber each other.
 */
const char *injector_last_error(injector_t *injector);

#if defined(INJECTOR_DOC) || defined(__linux__)
/*! \brief Feature-test macro: defined when the remote-call API below is available. */
#define INJECTOR_HAS_REMOTE_CALL_FUNCS 1
#include <stdarg.h>
#include <stdint.h>

/*!
 * \brief Get the function address in the target process (Linux only)
 * \param[in]   injector      the injector handle specifying the target process
 * \param[in]   handle        the module handle created by \c injector_inject or special-handles such as \c RTLD_DEFAULT
 * \param[in]   name          the function name
 * \param[out]  func_addr_out the address where the function address in the target process will be stored
 * \return                    zero on success. Otherwise, error code
 *
 * \b Example
 *
 * Inject libfoo.so and then call foo_func(1, 2, 3) in it.
 * \code
 * void *handle;
 * // inject libfoo.so and get the handle
 * if (injector_inject(injector, "libfoo.so", &handle) != 0) {
 *    return;
 * }
 * size_t func_addr;
 * // get the address of foo_func in the handle
 * if (injector_remote_func_addr(injector, handle, "foo_func", &func_addr) != 0) {
 *    return;
 * }
 * intptr_t retval;
 * // call foo_func
 * if (injector_remote_call(injector, &retval, func_addr, 1, 2, 3) != 0) {
 *    return;
 * }
 * printf("The return value of foo_func(1, 2, 3) is %ld.\n", retval);
 * \endcode
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_remote_func_addr(injector_t *injector, void *handle, const char* name, size_t *func_addr_out);

/*!
 * \brief Call the function in the target process (Linux only)
 * \param[in]   injector  the injector handle specifying the target process
 * \param[out]  retval    \c NULL or the address where the return value of the function call will be stored
 * \param[in]   func_addr the function address in the target process
 * \param[in]   ...       arguments passed to the function
 * \return                zero on success. Otherwise, error code
 * \remarks
 *   The types of the arguments must be integer or pointer.
 *   If it is a pointer, it must point to a valid address in the target process.
 *   The number of arguments must be less than or equal to six.
 * \note
 *   If the function in the target process internally calls non-[async-signal-safe]((https://man7.org/linux/man-pages/man7/signal-safety.7.html))
 *   functions, it may stop the target process or cause unexpected behaviour.
 * \sa injector_remote_func_addr(), injector_remote_vcall()
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_remote_call(injector_t *injector, intptr_t *retval, size_t func_addr, ...);

/*!
 * \brief Call the function in the target process (Linux only)
 * \param[in]   injector  the injector handle specifying the target process
 * \param[out]  retval    \c NULL or the address where the return value of the function call will be stored
 * \param[in]   func_addr the function address in the target process
 * \param[in]   ap        arguments passed to the function
 * \return                zero on success. Otherwise, error code
 * \remarks
 *   The types of the arguments must be integer or pointer.
 *   If it is a pointer, it must point to a valid address in the target process.
 *   The number of arguments must be less than or equal to six.
 * \note
 *   If the function in the target process internally calls non-[async-signal-safe]((https://man7.org/linux/man-pages/man7/signal-safety.7.html))
 *   functions, it may stop the target process or cause unexpected behaviour.
 * \sa injector_remote_func_addr(), injector_remote_call()
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_remote_vcall(injector_t *injector, intptr_t *retval, size_t func_addr, va_list ap);

/*!
 * \brief Read a chunk of the target process memory (Linux only)
 * \param[in]   inj      the injector handle specifying the target process
 * \param[in]   addr     the remote address to read from
 * \param[out]  buf      buffer in the caller process receiving the bytes
 * \param[in]   len      number of bytes to read
 * \return               zero on success. Otherwise, error code
 * \remarks Uses process_vm_readv with a ptrace single-step fallback.
 * \sa injector_write_mem(), injector_resolve_symbol()
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_read_mem(injector_t *inj, uintptr_t addr, void *buf, size_t len);

/*!
 * \brief Write a chunk of memory into the target process (Linux only)
 * \param[in]   inj      the injector handle specifying the target process
 * \param[in]   addr     the remote address to write to
 * \param[in]   buf      bytes to write
 * \param[in]   len      number of bytes to write
 * \return               zero on success. \c INJERR_PERMISSION when the handle
 *                       was not attached with \c opts.enable_write_mem set.
 * \remarks Gate: the handle must be attached via \c injector_attach_with_opts
 *          with \c opts.enable_write_mem = 1. Uses process_vm_writev with a
 *          ptrace single-step fallback.
 * \sa injector_read_mem(), injector_resolve_symbol()
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_write_mem(injector_t *inj, uintptr_t addr, const void *buf, size_t len);

/*!
 * \brief Resolve a symbol address in the target process (Linux only)
 * \param[in]   inj      the injector handle specifying the target process
 * \param[in]   libname  reserved for future use (M1 does not scope by library).
 *                       Pass \c NULL.
 * \param[in]   symbol   the symbol name
 * \param[out]  addr     the address where the resolved remote address will be
 *                       stored, or \c NULL to ignore
 * \return               zero on success. \c INJERR_FUNCTION_MISSING when the
 *                       symbol is not found.
 * \remarks M1 searches ONLY the target executable's dynamic symbol table
 *          (non-intrusive ELF parse of \c /proc/PID/exe). It does NOT perform
 *          a remote \c dlsym and does NOT search other loaded shared libraries.
 *          To resolve a symbol in an injected shared library, use
 *          \ref injector_remote_func_addr with the handle from \ref injector_inject.
 * \sa injector_read_mem(), injector_write_mem(), injector_remote_func_addr()
 */
int injector_resolve_symbol(injector_t *inj, const char *libname, const char *symbol, uintptr_t *addr);

/*!
 * \brief A loaded shared-library mapping in the target process (Linux only)
 */
typedef struct {
    /** .so path as it appears in /proc/PID/maps, NUL-terminated.
     *
     * NOTE: /proc/PID/maps paths can be up to PATH_MAX long, but this field is
     * 256 bytes and is part of the stable ABI (the Go/Python/Rust bindings
     * hardcode the layout), so a longer path is TRUNCATED at 255 characters and
     * the result is still NUL-terminated. Compare by suffix, or resolve the
     * real path yourself, if you need to distinguish very long paths such as
     * those under /nix/store or a snap/flatpak mount. */
    char name[256];
    uintptr_t base;        /**< Load base address: the first mapping's start. */
} injector_module_t;

/*!
 * \brief List loaded shared libraries in the target process (Linux only)
 * \param[in]   inj      the injector handle specifying the target process
 * \param[out]  out      array of \p cap entries to fill, or \c NULL to only count
 * \param[in]   cap      number of entries in \p out (0 to only count)
 * \return              the number of loaded libraries (always the total count,
 *                      even if greater than \p cap); -1 on error (and sets
 *                      \ref injector_last_error).
 * \remarks Non-intrusive: reads \c /proc/PID/maps and does NOT ptrace-attach
 *          or execute code in the target. Safe to call on an attached handle.
 *          A .so is listed once (adjacent mappings r-xp/r--p/rw-p collapsed);
 *          a non-contiguously mapped library may appear more than once.
 *          The library filter matches the WHOLE path as it appears in
 *          \c /proc/PID/maps, not just the basename: a file-backed mapping is
 *          listed when its path contains \c .so either at the very end or
 *          immediately followed by a dot (\c libfoo.so, \c libc.so.6,
 *          \c ld-linux-x86-64.so.2). Two consequences worth knowing: a
 *          directory component ending in \c .so or \c .so.N also qualifies, so
 *          an ordinary file such as \c /opt/libfoo.so.1/helper IS listed,
 *          whereas \c /opt/foo.so/bar is NOT, because there \c .so is followed
 *          by a slash. The main executable is therefore usually not listed, but
 *          that follows from its path rather than from a guarantee, so do not
 *          rely on it. Anonymous mappings are never listed, and bracketed
 *          pseudo-paths such as \c [vdso] or \c [heap] do not match. Deleted
 *          libraries are listed under their real name (the kernel's
 *          " (deleted)" suffix is stripped before matching). Use
 *          \ref injector_resolve_symbol or read \c /proc/PID/maps yourself if
 *          you need a mapping this filter excludes.
 */
long injector_list_modules(injector_t *inj, injector_module_t *out, size_t cap);

/*!
 * \brief Unload (dlclose) all libraries this handle injected via \c injector_inject (Linux only)
 * \param[in]   inj      the injector handle specifying the target process
 * \return              zero if all succeeded, otherwise the first non-zero
 *                      error code (remaining handles are still attempted).
 * \remarks Refuses musl-libc targets (\c INJERR_UNSUPPORTED_TARGET), as
 *          \ref injector_uninject does. Only handles whose out-param the
 *          caller kept (non-NULL \c handle) at inject time are tracked.
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_uninject_all(injector_t *inj);

/*!
 * \brief Result of a one-shot invoke/run call (Linux only)
 * \remarks Caller-owned; no lifetime issues. \c errmsg is filled on failure
 *          (empty on success).
 */
typedef struct {
    intptr_t retval;        /**< What the entry method returned. */
    int _reserved;          /**< Reserved for future use; always 0. */
    char errmsg[256];       /**< Failure message, empty on success. Caller-owned
                             *   storage, so it stays valid after the handle is
                             *   destroyed. 256 bytes is the whole budget: a long
                             *   primary message can leave no room for an
                             *   appended orphaned-helper verdict. */
} injector_result_t;

/*!
 * \brief Inject a library, resolve a symbol, call it with up to 6 arguments,
 *        and capture the return value (Linux only).
 * \param[in]  inj     an attached injector handle
 * \param[in]  path    the shared library path to inject
 * \param[in]  symbol  function name to call (must return intptr_t)
 * \param[in]  args    array of up to \c INJECTOR_MAX_INVOKE_ARGS intptr_t
 *                     arguments, or \c NULL for a no-argument call
 * \param[in]  argc    number of elements in \p args (0–6)
 * \param[out] out     destination result, or \c NULL to skip capturing it
 * \return             zero on success. On failure, \c out->errmsg is filled
 *                     (if \c out).
 * \remarks Uses the nonstop (clone-based) path on x86_64 when delivery mode
 *          is \c NONSTOP or \c AUTO; falls back to ptrace otherwise.
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_invoke(injector_t *inj, const char *path, const char *symbol,
                    const intptr_t *args, int argc,
                    injector_result_t *out);

/*!
 * \brief One-shot: attach with opts, invoke with arguments, and detach (Linux only).
 * \param[in]  pid     the target process id
 * \param[in]  lib     the shared library path to inject
 * \param[in]  symbol  function name to call (must return intptr_t)
 * \param[in]  args    array of up to \c INJECTOR_MAX_INVOKE_ARGS intptr_t
 *                     arguments, or \c NULL for a no-argument call
 * \param[in]  argc    number of elements in \p args (0–6)
 * \param[in]  opts    attach options, or \c NULL for defaults
 * \param[out] out     destination result, or \c NULL to skip capturing it
 * \return             zero on success.
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_run(pid_t pid, const char *lib, const char *symbol,
                 const intptr_t *args, int argc,
                 const injector_opts_t *opts, injector_result_t *out);
#endif

#if defined(INJECTOR_DOC) || (defined(__linux__) && defined(__x86_64__))
/*! \brief Feature-test macro: defined when \ref injector_inject_in_cloned_thread is available. */
#define INJECTOR_HAS_INJECT_IN_CLONED_THREAD 1 // feature test macro
/*!
 * \brief Inject the specified shared library into the target process by the \c clone system call. (Linux x86_64 only)
 * \param[in]   injector the injector handle specifying the target process
 * \param[in]   path     the path name of the shared library
 * \param[out]  handle   the address where the newly created module handle will be stored
 * \return               zero on success. Otherwise, error code
 *
 * This calls `dlopen()` in a thread created by \c [clone()](https://man7.org/linux/man-pages/man2/clone.2.html). Note that no wonder there are unexpected
 * pitfalls because some resources allocated in \c [pthread_create()](https://man7.org/linux/man-pages/man3/pthread_create.3.html) lack in the \c clone()-ed thread.
 * Use it at your own risk.
 * \remarks Thread affinity: drive this handle from the thread that attached
 *          it; see the affinity note at \ref injector_thread_affinity.
 */
int injector_inject_in_cloned_thread(injector_t *injector, const char *path, void **handle);
#endif

#if 0
{
#endif
#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif