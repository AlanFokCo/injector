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

#define INJERR_SUCCESS 0               /* linux */
#define INJERR_OTHER -1                /* linux */
#define INJERR_NO_MEMORY -2            /* linux */
#define INJERR_NO_PROCESS -3           /* linux */
#define INJERR_NO_LIBRARY -4           /* linux */
#define INJERR_ERROR_IN_TARGET -5      /* linux */
#define INJERR_FILE_NOT_FOUND -6       /* linux */
#define INJERR_INVALID_MEMORY_AREA -7  /* linux */
#define INJERR_PERMISSION -8           /* linux */
#define INJERR_UNSUPPORTED_TARGET -9   /* linux */
#define INJERR_INVALID_ELF_FORMAT -10  /* linux */
#define INJERR_WAIT_TRACEE -11         /* linux */
#define INJERR_FUNCTION_MISSING -12    /* linux */
#define INJERR_TIMEOUT -13            /* linux: remote call timed out */

/* Deprecated alias — use INJERR_FUNCTION_MISSING. */
#define INJERR_NO_FUNCTION INJERR_FUNCTION_MISSING

#define INJECTOR_ABI_VERSION 1u
#define INJECTOR_VERSION "1.0.0"
#define INJECTOR_MAX_INVOKE_ARGS 6

typedef enum {
    INJECTOR_DELIVERY_AUTO = 0,
    INJECTOR_DELIVERY_NONSTOP = 1,
    INJECTOR_DELIVERY_PTRACE = 2,
} injector_delivery_t;

typedef enum {
    INJECTOR_TIMEOUT_LEAVE = 0,
    INJECTOR_TIMEOUT_KILL_THREAD = 1,
} injector_timeout_action_t;

typedef struct {
    size_t opts_size;
    injector_delivery_t delivery;
    unsigned call_timeout_ms;
    injector_timeout_action_t timeout_action;
    int enable_write_mem;
} injector_opts_t;

#define INJECTOR_OPTS_INIT ((injector_opts_t){ .opts_size = sizeof(injector_opts_t) })

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
int injector_library_deinit(void);

typedef struct injector injector_t;

/*!
 * \brief Attach to the specified process.
 * \param[out]  injector the address where the newly created injector handle will be stored
 * \param[in]   pid      the process id to be attached
 * \return               zero on success. Otherwise, error code
 */
int injector_attach(injector_t **injector, injector_pid_t pid);
int injector_attach_with_opts(injector_t **out, pid_t pid, const injector_opts_t *opts);

/*!
 * \brief Thread safety
 * An \c injector_t handle is not safe for concurrent use from multiple threads.
 * Use a handle from a single thread or serialize access. The per-handle error
 * buffer is read via \ref injector_last_error; the thread-local fallback (read
 * via \ref injector_error) is intended only for the no-handle attach-failure case.
 */

/*!
 * \brief Detach from the attached process and destroy the specified handle.
 * \param[in]   injector the injector handle to destroy
 * \return               zero on success. Otherwise, error code
 */
int injector_detach(injector_t *injector);

#if defined(INJECTOR_DOC) || defined(__linux__)
/*!
 * \brief Non-intrusive target introspection (Linux only).
 *
 * Reads /proc/PID to fill `out`. Does NOT ptrace-attach to the target.
 * Safe to call before deciding whether to inject.
 *
 * \param[in]  pid  the process id to inspect
 * \param[out] out  destination struct (zeroed by the call)
 * \return          zero on success, INJERR_NO_PROCESS if pid absent,
 *                  INJERR_OTHER on read error. Unreadable fields are empty;
 *                  arch/libc are "unknown" when no libc mapping is found.
 */
typedef struct {
    pid_t pid;
    int alive;            /* 1 if process exists */
    int ptrace_allowed;   /* heuristic: 1 if attach would likely succeed */
    const char *arch;     /* "x86_64"/"aarch64"/"i386"/"arm"/"mips"/"ppc64"/"ppc"/"riscv"/"unknown" */
    const char *libc;     /* "glibc"/"musl"/"unknown" */
    char exe[4096];       /* /proc/PID/exe */
    char cwd[4096];       /* /proc/PID/cwd */
    char root[4096];      /* /proc/PID/root */
    char comm[16];        /* /proc/PID/comm */
} injector_target_info_t;

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
 */
int injector_inject(injector_t *injector, const char *path, void **handle);

/*!
 * \brief Uninject the shared library specified by \c handle.
 * \param[in]   injector the injector handle specifying the target process
 * \param[in]   handle   the module handle created by \c injector_inject
 * \return               zero on success. Otherwise, error code
 * \remarks This fearute isn't supported for musl-libc processes.
 *     See [Functional differences from glibc](https://wiki.musl-libc.org/functional-differences-from-glibc.html#Unloading_libraries).
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
 */
int injector_remote_vcall(injector_t *injector, intptr_t *retval, size_t func_addr, va_list ap);

/*!
 * \brief Read a chunk of the target process memory (Linux only)
 * \param[in]   injector the injector handle specifying the target process
 * \param[in]   addr     the remote address to read from
 * \param[out]  buf      buffer in the caller process receiving the bytes
 * \param[in]   len      number of bytes to read
 * 
eturn               zero on success. Otherwise, error code
 * 
emarks Uses process_vm_readv with a ptrace single-step fallback.
 * \sa injector_write_mem(), injector_resolve_symbol()
 */
int injector_read_mem(injector_t *inj, uintptr_t addr, void *buf, size_t len);

/*!
 * \brief Write a chunk of memory into the target process (Linux only)
 * \param[in]   injector the injector handle specifying the target process
 * \param[in]   addr     the remote address to write to
 * \param[in]   buf      bytes to write
 * \param[in]   len      number of bytes to write
 * 
eturn               zero on success. \c INJERR_PERMISSION when the handle
 *                       was not attached with \c opts.enable_write_mem set.
 * 
emarks Gate: the handle must be attached via \c injector_attach_with_opts
 *          with \c opts.enable_write_mem = 1. Uses process_vm_writev with a
 *          ptrace single-step fallback.
 * \sa injector_read_mem(), injector_resolve_symbol()
 */
int injector_write_mem(injector_t *inj, uintptr_t addr, const void *buf, size_t len);

/*!
 * \brief Resolve a symbol address in the target process (Linux only)
 * \param[in]   injector the injector handle specifying the target process
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
    char name[256];        /* .so path (full path as it appears in /proc/PID/maps) */
    uintptr_t base;        /* load base address (first mapping's start) */
} injector_module_t;

/*!
 * \brief List loaded shared libraries in the target process (Linux only)
 * \param[in]   injector the injector handle specifying the target process
 * \param[out]  out      array of \p cap entries to fill, or \c NULL to only count
 * \param[in]   cap      number of entries in \p out (0 to only count)
 * \return              the number of loaded libraries (always the total count,
 *                      even if greater than \p cap); -1 on error (and sets
 *                      \ref injector_last_error).
 * \remarks Non-intrusive: reads \c /proc/PID/maps and does NOT ptrace-attach
 *          or execute code in the target. Safe to call on an attached handle.
 *          A .so is listed once (adjacent mappings r-xp/r--p/rw-p collapsed);
 *          a non-contiguously mapped library may appear more than once.
 */
long injector_list_modules(injector_t *inj, injector_module_t *out, size_t cap);

/*!
 * \brief Unload (dlclose) all libraries this handle injected via \c injector_inject (Linux only)
 * \param[in]   injector the injector handle specifying the target process
 * \return              zero if all succeeded, otherwise the first non-zero
 *                      error code (remaining handles are still attempted).
 * \remarks Refuses musl-libc targets (\c INJERR_UNSUPPORTED_TARGET), as
 *          \ref injector_uninject does. Only handles whose out-param the
 *          caller kept (non-NULL \c handle) at inject time are tracked.
 */
int injector_uninject_all(injector_t *inj);

/*!
 * \brief Result of a one-shot invoke/run call (Linux only)
 * \remarks Caller-owned; no lifetime issues. \c errmsg is filled on failure
 *          (empty on success).
 */
typedef struct {
    intptr_t retval;        /* entry method return value */
    int _reserved;          /* reserved for future use (always 0) */
    char errmsg[256];       /* failure message; caller-owned, no lifetime issue */
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
 */
int injector_run(pid_t pid, const char *lib, const char *symbol,
                 const intptr_t *args, int argc,
                 const injector_opts_t *opts, injector_result_t *out);
#endif

#if defined(INJECTOR_DOC) || (defined(__linux__) && defined(__x86_64__))
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