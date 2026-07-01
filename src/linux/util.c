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
#include <stdio.h>
#include <stdarg.h>
#include "injector_internal.h"

static __thread injector_t *current_inj;
static __thread char tl_errmsg[512];
static __thread char tl_errmsg_set;

void injector__set_current(injector_t *inj)
{
    current_inj = inj;
}

void injector__reset_tl_errmsg(void)
{
    tl_errmsg_set = 0;
}

const char *injector__tl_errmsg(void)
{
    return tl_errmsg;
}

void injector__set_errmsg(const char *format, ...)
{
    va_list ap;
    int rv;
    char *buf;
    char *set;
    size_t bufsz;

    if (current_inj != NULL) {
        buf = current_inj->errmsg;
        set = &current_inj->errmsg_set;
        bufsz = sizeof(current_inj->errmsg);
    } else {
        buf = tl_errmsg;
        set = &tl_errmsg_set;
        bufsz = sizeof(tl_errmsg);
    }
    /* prevent the error message from being overwritten. */
    if (*set) {
        return;
    }
    *set = 1;

    va_start(ap, format);
    rv = vsnprintf(buf, bufsz, format, ap);
    va_end(ap);
    if (rv == -1 || rv >= (int)bufsz) {
        buf[bufsz - 1] = 0;
    }
}

/* Deprecated: new code should use injector_last_error() which is per-handle.
 * This returns only the thread-local fallback, which is set when no handle is
 * current (e.g. injector_attach failure before a handle exists). */
const char *injector_error(void)
{
    return tl_errmsg;
}

const char *injector_last_error(injector_t *inj)
{
    return inj ? inj->errmsg : tl_errmsg;
}

const char *injector__arch2name(arch_t arch)
{
    switch (arch) {
    case ARCH_X86_64:
        return "x86_64";
    case ARCH_X86_64_X32:
        return "x86_64 x32-ABI";
    case ARCH_I386:
        return "i386";
    case ARCH_ARM64:
        return "ARM64";
    case ARCH_ARM_EABI_THUMB:
        return "ARM EABI thumb";
    case ARCH_ARM_EABI:
        return "ARM EABI";
    case ARCH_MIPS_64:
        return "MIPS 64";
    case ARCH_MIPS_N32:
        return "MIPS N32 ABI";
    case ARCH_MIPS_O32:
        return "MIPS O32 ABI";
    case ARCH_POWERPC_64:
        return "PowerPC 64-bit";
    case ARCH_POWERPC:
        return "PowerPC";
    case ARCH_RISCV_64:
        return "RISC-V 64";
    case ARCH_RISCV_32:
        return "RISC-V 32";
    }
    return "?";
}
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
