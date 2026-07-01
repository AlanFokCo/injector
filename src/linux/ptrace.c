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

#if defined(__aarch64__) || defined(__riscv)
#define USE_REGSET
#include <elf.h> /* for NT_PRSTATUS */
#endif

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

int injector__attach_process(const injector_t *injector)
{
    PTRACE_OR_RETURN(PTRACE_ATTACH, injector, 0, 0);
    return 0;
}

int injector__detach_process(const injector_t *injector)
{
    PTRACE_OR_RETURN(PTRACE_DETACH, injector, 0, 0);
    return 0;
}

int injector__get_regs(const injector_t *injector, struct user_regs_struct *regs)
{
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
#ifdef USE_REGSET
    struct iovec iovec = { (void*)regs, sizeof(*regs) };
    PTRACE_OR_RETURN(PTRACE_SETREGSET, injector, NT_PRSTATUS, (long)&iovec);
#else
    PTRACE_OR_RETURN(PTRACE_SETREGS, injector, 0, (long)regs);
#endif
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
        long word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        char *dest = (char*)&word;
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