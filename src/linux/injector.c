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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <elf.h>
#include "proc.h"
#include "injector_internal.h"


static inline size_t remote_mem_size(injector_t *injector) {
    return 2 * injector->data_size + injector->stack_size;
}

int injector__attach_internal(injector_t **injector_out, pid_t pid, const injector_opts_t *o)
{
    injector_t *injector;
    int status;
    intptr_t retval;
    int prot;
    int rv = 0;

    injector__set_current(NULL);
    injector__reset_tl_errmsg();

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

    injector->data_size = sysconf(_SC_PAGESIZE);
    injector->stack_size = 2 * 1024 * 1024;

    rv = injector__call_syscall(injector, &retval, injector->sys_mmap, 0,
                                remote_mem_size(injector), PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    if (rv != 0) {
        goto error_exit;
    }
    if (retval == -1) {
        injector__set_errmsg("mmap error: %s", strerror(errno));
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
    rv = injector__call_syscall(injector, &retval, injector->sys_mprotect,
                                injector->data + injector->data_size, injector->data_size,
                                prot);
    if (rv != 0) {
        goto error_exit;
    }
    if (retval != 0) {
        injector__set_errmsg("mprotect error: %s", strerror(errno));
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

    injector__set_current(injector);
    injector->errmsg_set = 0;

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
    rv = injector__call_function(injector, &retval, injector->dlopen_addr, injector->data, dlflags);
    if (rv != 0) {
        return rv;
    }
    if (retval == 0) {
        char buf[256 + 1] = {0,};
        if (injector->dlerror_addr != 0) {
            rv = injector__call_function(injector, &retval, injector->dlerror_addr);
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
            injector__set_errmsg("too many injected libraries to track (max 32)");
            /* still succeed: the library is loaded, we just can't auto-uninject it */
        }
    }
    return 0;
}

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
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

    injector__set_current(injector);
    injector->errmsg_set = 0;

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
                                 injector->data);
    if (rv != 0) {
        return rv;
    }
    if (retval == -1) {
        injector__set_errmsg("clone error: %s", strerror(errno));
        return INJERR_ERROR_IN_TARGET;
    }
    const struct timespec ts = {0, 100000000}; /* 0.1 second */
    void *handle;
    int cnt = 0;

retry:
    nanosleep(&ts, NULL);
    rv = injector__read(injector, injector->data, &handle, sizeof(handle));
    if (rv != 0) {
        return rv;
    }
    if (handle == invalid_handle) {
        int max_retry_cnt = 50;
        if (++cnt <= max_retry_cnt) {
            goto retry;
        }
        injector__set_errmsg("dlopen doesn't return in %d seconds.", max_retry_cnt / 10);
        return INJERR_ERROR_IN_TARGET;
    }
    if (handle_out != NULL) {
        *handle_out = handle;
    }
    if (handle == NULL) {
        arg->file_path[0] = '\0';
        injector__read(injector, injector->data, data, injector->data_size);
        if (arg->file_path[0] != '\0') {
            injector__set_errmsg("%s", arg->file_path);
        } else {
            injector__set_errmsg("dlopen error");
        }
        return INJERR_ERROR_IN_TARGET;
    }
    return 0;
}
#endif

int injector_remote_func_addr(injector_t *injector, void *handle, const char* name, size_t *func_addr_out)
{
    int rv;
    intptr_t retval;
    size_t len = strlen(name) + 1;

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
    rv = injector__call_function(injector, &retval, injector->dlsym_addr, handle, injector->data);
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
    injector__set_current(injector);
    injector->errmsg_set = 0;
    va_start(ap, func_addr);
    rv = injector__call_function_va_list(injector, retval, func_addr, ap);
    va_end(ap);
    return rv;
}

int injector_remote_vcall(injector_t *injector, intptr_t *retval, size_t func_addr, va_list ap)
{
    injector__set_current(injector);
    injector->errmsg_set = 0;
    return injector__call_function_va_list(injector, retval, func_addr, ap);
}

int injector_call(injector_t *injector, void *handle, const char* name)
{
    size_t func_addr;
    int rv = injector_remote_func_addr(injector, handle, name, &func_addr);
    if (rv != 0) {
        return rv;
    }
    return injector__call_function(injector, NULL, func_addr);
}

int injector_uninject(injector_t *injector, void *handle)
{
    int rv;
    intptr_t retval;

    injector__set_current(injector);
    injector->errmsg_set = 0;
    if (injector->libc_type == LIBC_TYPE_MUSL) {
        /* Assume that libc is musl. */
        injector__set_errmsg("Cannot uninject libraries under musl libc. See: https://wiki.musl-libc.org/functional-differences-from-glibc.html#Unloading_libraries");
        return INJERR_UNSUPPORTED_TARGET;
    }

    rv = injector__call_function(injector, &retval, injector->dlclose_addr, handle);
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
    /* current_inj = NULL so detach cleanup errors go to thread-local and
     * do not dangle after free(injector) below. Leave errmsg_set intact so
     * a caller reading injector_last_error() before detach sees the error. */
    injector__set_current(NULL);

    if (injector->mmapped) {
        int r = injector__call_syscall(injector, NULL, injector->sys_munmap, injector->data, remote_mem_size(injector));
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
        /* alive but no maps (e.g. zombie/permission): arch/libc stay unknown */
        return 0;
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
    injector__set_current(inj);
    inj->errmsg_set = 0;
    return injector__read(inj, (size_t)addr, buf, len);
}

int injector_write_mem(injector_t *inj, uintptr_t addr, const void *buf, size_t len)
{
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
    char line[PATH_MAX * 2];
    proc_map_t m;
    FILE *fp;
    size_t map_start = 0;
    int found = 0;
    size_t bias = 0;
    size_t a = 0;
    int rv;

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
        if (strcmp(m.path, exe_path) == 0) {
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
    rv = injector__elf_load_bias(exe_path, map_start, &bias);
    if (rv != 0) {
        return rv;
    }

    {
        const char *const names[1] = { symbol };
        size_t addrs[1] = { 0 };
        rv = injector__elf_find_symbols(exe_path, bias, names, addrs, 1);
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
        /* only shared libraries: cheap ".so" filter on the path */
        if (strstr(m.path, ".so") == NULL) {
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
    injector__set_current(inj);
    inj->errmsg_set = 0;
    /* Delegate per-handle uninject to injector_uninject, which refuses musl
     * targets (INJERR_UNSUPPORTED_TARGET). The first non-zero error wins;
     * we keep trying the rest so a single bad handle doesn't strand others. */
    for (i = 0; i < inj->injected_count; i++) {
        int r = injector_uninject(inj, inj->injected_handles[i]);
        if (r != 0 && rv == 0) {
            rv = r;
        }
    }
    inj->injected_count = 0;
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

static int injector_invoke_ptrace(injector_t *inj, const char *path, const char *symbol, injector_result_t *out) {
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
    rv = injector__call_function(inj, &ret, (long)func_addr);
    if (rv != 0) {
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }
    if (out) out->retval = ret;
    return 0;
}

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
static int injector_invoke_nonstop(injector_t *inj, const char *path, const char *symbol, injector_result_t *out)
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
    memcpy(arg->file_path, abspath, pathlen);
    memcpy((char*)data + func_name_off, symbol, symlen);

    rv = injector__write(inj, inj->data, data, inj->data_size);
    if (rv != 0) {
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }

    rv = injector__call_function(inj, &clone_ret, (long)inj->clone_addr,
                                 (long)inj->shellcode_invoke,
                                 (long)(inj->stack + inj->stack_size - 4096),
                                 (long)CLONE_VM, (long)inj->data);
    if (rv != 0) {
        if (out) { const char *e = injector_last_error(inj); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }
    if (clone_ret == -1) {
        injector__set_errmsg("clone error: %s", strerror(errno));
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        return INJERR_ERROR_IN_TARGET;
    }

    /* Main thread stays ptrace-stopped. The clone child (CLONE_VM, separate
     * process sharing the address space) runs the invoke shellcode. Poll the
     * data page via process_vm_readv — works on the stopped main thread's pid
     * because the address space is shared. */
    const struct timespec ts_poll = {0, 100000000}; /* 100ms */
    int64_t status = 0;
    int cnt = 0;
    int max_cnt = (int)(inj->call_timeout_ms / 100);
    if (max_cnt < 50) max_cnt = 50;

    while (status == 0 && cnt++ < max_cnt) {
        nanosleep(&ts_poll, NULL);
        rv = injector__read(inj, inj->data + offsetof(injector_shellcode_invoke_arg_t, status),
                            &status, sizeof(status));
        if (rv != 0) {
            if (out) snprintf(out->errmsg, sizeof(out->errmsg), "failed to read result from target");
            return rv;
        }
    }

    if (status == 1) {
        intptr_t result;
        injector__read(inj, inj->data + offsetof(injector_shellcode_invoke_arg_t, retval),
                       &result, sizeof(result));
        if (out) out->retval = result;
        return 0;
    } else if (status == 2) {
        char errbuf[256] = {0,};
        injector__read(inj, inj->data + offsetof(injector_shellcode_invoke_arg_t, file_path),
                       errbuf, sizeof(errbuf) - 1);
        injector__set_errmsg("nonstop invoke failed: %s", errbuf[0] ? errbuf : "unknown error");
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        return INJERR_ERROR_IN_TARGET;
    } else {
        injector__set_errmsg("nonstop invoke timed out after %u ms", inj->call_timeout_ms);
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        return INJERR_TIMEOUT;
    }
}
#endif

int injector_invoke(injector_t *inj, const char *path, const char *symbol, injector_result_t *out) {
    if (out) { memset(out, 0, sizeof(*out)); }
    injector__set_current(inj);
    inj->errmsg_set = 0;

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    if (inj->mode == INJECTOR_DELIVERY_NONSTOP ||
        (inj->mode == INJECTOR_DELIVERY_AUTO && inj->arch == ARCH_X86_64)) {
        return injector_invoke_nonstop(inj, path, symbol, out);
    }
#endif
    if (inj->mode == INJECTOR_DELIVERY_NONSTOP) {
        injector__set_errmsg("NONSTOP delivery not available on this architecture");
        if (out) snprintf(out->errmsg, sizeof(out->errmsg), "%s", injector_last_error(inj));
        return INJERR_UNSUPPORTED_TARGET;
    }
    return injector_invoke_ptrace(inj, path, symbol, out);
}

int injector_run(pid_t pid, const char *lib, const char *symbol,
                 const injector_opts_t *opts, injector_result_t *out) {
    if (out) { memset(out, 0, sizeof(*out)); }
    injector_t *inj = NULL;
    int rv = injector_attach_with_opts(&inj, pid, opts);
    if (rv != 0) {
        /* attach failed: no handle; error is in thread-local (injector_error). */
        if (out) { const char *e = injector__tl_errmsg(); snprintf(out->errmsg, sizeof(out->errmsg), "%s", e ? e : ""); }
        return rv;
    }
    rv = injector_invoke(inj, lib, symbol, out);
    injector_detach(inj);
    return rv;
}