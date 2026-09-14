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
#if defined __linux__
/* Detect musl libc. See https://stackoverflow.com/a/70211227/985524  */
#define _GNU_SOURCE
#include <features.h>
#ifndef __USE_GNU
#define MUSL_LIBC
#endif // __USE_GNU
#endif // __linux__

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "injector_internal.h"

// #define INJECTOR_DEBUG_REMOTE_CALL 1

#ifdef INJECTOR_DEBUG_REMOTE_CALL
#undef DEBUG
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#undef DEBUG
#define DEBUG(...) do {} while(0)
#endif

#ifdef __x86_64__
#define eip rip
#define ebp rbp
#define esp rsp
#define eax rax
#define ebx rbx
#define ecx rcx
#define edx rdx
#define esi rsi
#define edi rdi
#define ebp rbp
#endif

#if defined(__arm__)
#define reg32_return reg_return
#define uregs regs.uregs
#endif

#define THUMB_MODE_BIT (1u << 5)
#define BREAKINST_THUMB 0xde01 /* in linux-source-tree/arch/arm/kernel/ptrace.c */
#define BREAKINST_ARM 0xe7f001f0 /* in linux-source-tree/arch/arm/kernel/ptrace.c */
#define BREAKINST_ARM64 0xd4200000 /* asm("brk #0") */

/* The TRAMP_* x86 trampoline byte macros live in injector_internal.h, next to
 * code_t and arch_t, because three parties have to agree on them: the two
 * writers below, injector__code_is_trampoline(), and
 * tests/unit/test_trampoline.c. */

#ifdef __mips__
#define REG_V0 2
#define REG_A0 4
#define REG_A1 5
#define REG_A2 6
#define REG_A3 7
#define REG_A4 8
#define REG_A5 9
#define REG_T4 12
#define REG_T9 25
#define REG_SP 29
#define REG_FP 30
#define REG_RA 31

static void print_regs(const injector_t *injector, const struct pt_regs *regs)
{
    DEBUG("  Registers:\n");
    DEBUG("    -- at v0 v1: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3]);
    DEBUG("    a0 a1 a2 a3: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[4], regs->regs[5], regs->regs[6], regs->regs[7]);
    DEBUG("    %s: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          (injector->arch != ARCH_MIPS_O32) ? "a4 a5 a6 a7" : "t0 t1 t2 t3",
          regs->regs[8], regs->regs[9], regs->regs[10], regs->regs[11]);
    DEBUG("    t4 t5 t6 t7: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[12], regs->regs[13], regs->regs[14], regs->regs[15]);
    DEBUG("    s0 s1 s2 s3: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[16], regs->regs[17], regs->regs[18], regs->regs[19]);
    DEBUG("    s4 s5 s6 s7: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[20], regs->regs[21], regs->regs[22], regs->regs[23]);
    DEBUG("    t8 t9 k0 k1: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[24], regs->regs[25], regs->regs[26], regs->regs[27]);
    DEBUG("    gp sp s8 ra: %016"PRIx64" %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->regs[28], regs->regs[29], regs->regs[30], regs->regs[31]);
    DEBUG("    lo hi epc:                    %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->lo, regs->hi, regs->cp0_epc);
    DEBUG("    badvaddr status cause:        %016"PRIx64" %016"PRIx64" %016"PRIx64"\n",
          regs->cp0_badvaddr, regs->cp0_status, regs->cp0_cause);
}
#define PRINT_REGS(injector, regs) print_regs((injector), (regs))
#endif /* __mips__ */


#ifdef __powerpc__
static void print_regs(const injector_t *injector, const struct pt_regs *regs)
{
#undef WIDTH
#ifdef __LP64__
#define WIDTH "016"
#define softe_or_mq_str "softe"
#define softe_or_mq softe
#else
#define WIDTH "08"
#define softe_or_mq_str "mq   "
#define softe_or_mq mq
#endif
    DEBUG("  Registers:\n");
    DEBUG("    gpr0  gpr1  gpr2   gpr3   : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[0], regs->gpr[1], regs->gpr[2], regs->gpr[3]);
    DEBUG("    gpr4  gpr5  gpr6   gpr7   : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[4], regs->gpr[5], regs->gpr[6], regs->gpr[7]);
    DEBUG("    gpr8  gpr9  gpr10  gpr11  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[8], regs->gpr[9], regs->gpr[10], regs->gpr[11]);
    DEBUG("    gpr12 gpr13 gpr14  gpr15  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[12], regs->gpr[13], regs->gpr[14], regs->gpr[15]);
    DEBUG("    gpr16 gpr17 gpr18  gpr19  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[16], regs->gpr[17], regs->gpr[18], regs->gpr[19]);
    DEBUG("    gpr20 gpr21 gpr22  gpr23  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[20], regs->gpr[21], regs->gpr[22], regs->gpr[23]);
    DEBUG("    gpr24 gpr25 gpr26  gpr27  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[24], regs->gpr[25], regs->gpr[26], regs->gpr[27]);
    DEBUG("    gpr28 gpr29 gpr30  gpr31  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->gpr[28], regs->gpr[29], regs->gpr[30], regs->gpr[31]);
    DEBUG("    nip   msr   orig_gpr3 ctr : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->nip, regs->msr, regs->orig_gpr3, regs->ctr);
    DEBUG("    link  xer   ccr    "softe_or_mq_str"  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->link, regs->xer, regs->ccr, regs->softe_or_mq);
    DEBUG("    trap  dar   dsisr  result : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->trap, regs->dar, regs->dsisr, regs->result);
#undef WIDTH
}
#define PRINT_REGS(injector, regs) print_regs((injector), (regs))
#endif

#ifdef __riscv
#define REG_RA 1
#define REG_T1 6
#ifdef __LP64__
#define WIDTH "016"
#else
#define WIDTH "08"
#endif
static void print_regs(const injector_t *injector, const struct user_regs_struct *regs)
{
    DEBUG("  Registers:\n");
    DEBUG("    pc  ra  sp  gp  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->pc, regs->ra, regs->sp, regs->gp);
    DEBUG("    tp  t0  t1  t2  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->tp, regs->t0, regs->t1, regs->t2);
    DEBUG("    s0  s1  a0  a1  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->s0, regs->s1, regs->a0, regs->a1);
    DEBUG("    a2  a3  a4  a5  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->a2, regs->a3, regs->a4, regs->a5);
    DEBUG("    a6  a7  s2  s3  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->a6, regs->a7, regs->s2, regs->s3);
    DEBUG("    s4  s5  s6  s7  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->s4, regs->s5, regs->s6, regs->s7);
    DEBUG("    s8  s9  s10 s11 : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->s8, regs->s9, regs->s10, regs->s11);
    DEBUG("    t3  t4  t5  t6  : %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx %"WIDTH"lx\n",
          regs->t3, regs->t4, regs->t5, regs->t6);
}
#define PRINT_REGS(injector, regs) print_regs((injector), (regs))
#endif

/* register type used in struct user_regs_struct */
#if defined(__mips__)
typedef uint64_t user_reg_t;
#elif defined(__riscv)
typedef unsigned long user_reg_t;
#elif defined(__LP64__) && !defined(MUSL_LIBC)
typedef unsigned long long user_reg_t;
#elif defined(__i386__)
typedef long user_reg_t;
#elif defined(__x86_64__) && defined(__ILP32__)
/* x32: __x86_64__ is defined but __LP64__ is not (x32 is ILP32), so none of
 * the branches above match even though user_regs_struct is the 64-bit one and
 * the `#define eax rax` block at the top of this file makes regs.eax an
 * unsigned long long. Without this branch user_reg_t would be a 32-bit
 * `unsigned long` and `reg_return = &regs.eax` fails -Werror on `make x32`.
 *
 * The test must be __ILP32__, not bare __x86_64__: musl declares
 * user_regs_struct with `unsigned long` fields, so on musl/x86_64 (LP64,
 * MUSL_LIBC defined) the __LP64__ branch above is skipped on purpose and this
 * one has to be skipped too, letting the #else below pick `unsigned long`.
 * A bare __x86_64__ here silently broke the Alpine/musl build with
 * -Werror=incompatible-pointer-types on every `reg_return = &regs.<reg>`. */
typedef unsigned long long user_reg_t;
#else
typedef unsigned long user_reg_t;
#endif

/* How many arguments the system call takes, for the syscalls this library
 * issues itself (resolved at attach time into injector->sys_*). Reading six
 * va_args when the caller passed two forwards indeterminate values as syscall
 * arguments 3-6 - munmap takes two, mprotect three. Unknown numbers keep the
 * historical six, so no existing caller changes behaviour. */
static int syscall_arg_count(const injector_t *injector, long syscall_number)
{
    if (injector->sys_munmap != 0 && syscall_number == injector->sys_munmap) {
        return 2;
    }
    if (injector->sys_mprotect != 0 && syscall_number == injector->sys_mprotect) {
        return 3;
    }
    return 6; /* mmap and anything this file does not know about */
}

/* Same idea for the libc functions this library calls itself: dlerror(0),
 * dlclose(1), dlopen(2), dlsym(2), clone(4). An arbitrary user function
 * address (injector_remote_call / injector_invoke) cannot communicate its
 * argument count through injector__call_function_va_list()'s signature, so it
 * keeps the historical six; the reads stay in bounds because a SysV varargs
 * caller always provides a six-slot register save area. */
static int function_arg_count(const injector_t *injector, long function_addr)
{
    size_t a = (size_t)function_addr;

    if (a == 0) {
        return 6;
    }
    if (injector->dlerror_addr == a) {
        return 0;
    }
    if (injector->dlclose_addr == a) {
        return 1;
    }
    if (injector->dlopen_addr == a || injector->dlsym_addr == a) {
        return 2;
    }
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    if (injector->clone_addr == a) {
        return 4;
    }
#endif
    return 6;
}

/* Read exactly `nargs` varargs and zero the rest, so nothing indeterminate is
 * ever forwarded to the target. */
static void read_varargs(va_list ap, int nargs, long args[6])
{
    int i;

    for (i = 0; i < 6; i++) {
        if (i < nargs) {
            args[i] = va_arg(ap, long);
        } else {
            args[i] = 0;
        }
    }
}

static int kick_then_wait_sigtrap(const injector_t *injector, struct user_regs_struct *regs, code_t *code, size_t code_size);

#ifndef PRINT_REGS
#define PRINT_REGS(injector, regs) do {} while (0)
#endif

/*
 * Call the specified system call in the target process.
 *
 * The arguments after syscall_number must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_syscall(const injector_t *injector, intptr_t *retval, long syscall_number, ...)
{
    struct user_regs_struct regs = injector->regs;
    code_t code;
    size_t code_size;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    long sc_args[6];
    va_list ap;
    int nargs;
    int rv;
#if !defined(__mips__) && !defined(__powerpc__)
    user_reg_t *reg_return = NULL;
#if defined(__aarch64__)
    uint32_t *reg32_return = NULL;
    uint32_t *uregs = (uint32_t *)&regs;
#endif
#endif

    nargs = syscall_arg_count(injector, syscall_number);
    va_start(ap, syscall_number);
    read_varargs(ap, nargs, sc_args);
    va_end(ap);
    arg1 = sc_args[0];
    arg2 = sc_args[1];
    arg3 = sc_args[2];
    arg4 = sc_args[3];
    arg5 = sc_args[4];
    arg6 = sc_args[5];

    DEBUG("injector__call_syscall:\n");
    DEBUG("  args: %ld, %lx, %lx, %lx, %lx, %lx, %lx\n", syscall_number, arg1, arg2, arg3, arg4, arg5, arg6);

#if !(defined(__x86_64__) && defined(__LP64__))
    if (injector->arch == ARCH_X86_64_X32) {
        injector__set_errmsg("x32-ABI target process is supported only by x86_64.");
        return INJERR_UNSUPPORTED_TARGET;
    }
#endif

    switch (injector->arch) {
#if defined(__x86_64__) && defined(__LP64__)
    case ARCH_X86_64:
    case ARCH_X86_64_X32:
        /* setup instructions */
        code.u8[0] = TRAMP_SYSCALL64_B0;
        code.u8[1] = TRAMP_SYSCALL64_B1; /* 0f 05 : syscall */
        code.u8[2] = TRAMP_INT3;         /* cc    : int3    */
        memset(&code.u8[TRAMP_LEN], TRAMP_NOP, sizeof(long) - TRAMP_LEN); /* fill the rests with `nop` */
        code_size = sizeof(long);
        /* setup registers */
        regs.rip = injector->code_addr;
        regs.rax = syscall_number;
        regs.rdi = arg1;
        regs.rsi = arg2;
        regs.rdx = arg3;
        regs.r10 = arg4;
        regs.r8 = arg5;
        regs.r9 = arg6;
        reg_return = &regs.rax;
        break;
#endif
#if defined(__x86_64__) || defined(__i386__)
    case ARCH_I386:
        /* setup instructions */
        code.u8[0] = TRAMP_SYSCALL32_B0;
        code.u8[1] = TRAMP_SYSCALL32_B1; /* cd 80 : int $80 */
        code.u8[2] = TRAMP_INT3;         /* cc    : int3    */
        memset(&code.u8[TRAMP_LEN], TRAMP_NOP, sizeof(long) - TRAMP_LEN); /* fill the rests with `nop` */
        code_size = sizeof(long);
        /* setup registers */
        regs.eip = injector->code_addr;
        regs.eax = syscall_number;
        regs.ebx = arg1;
        regs.ecx = arg2;
        regs.edx = arg3;
        regs.esi = arg4;
        regs.edi = arg5;
        regs.ebp = arg6;
        reg_return = &regs.eax;
        break;
#endif
#if defined(__aarch64__)
    case ARCH_ARM64:
        /* setup instructions */
        code.u32[0] = 0xd4000001; /* svc #0 */
        code.u32[1] = BREAKINST_ARM64;
        code_size = 2 * 4;
        /* setup registers */
        regs.pc = injector->code_addr;
        regs.regs[8] = syscall_number;
        regs.regs[0] = arg1;
        regs.regs[1] = arg2;
        regs.regs[2] = arg3;
        regs.regs[3] = arg4;
        regs.regs[4] = arg5;
        regs.regs[5] = arg6;
        reg_return = &regs.regs[0];
        break;
#endif
#if defined(__aarch64__) || defined(__arm__)
    case ARCH_ARM_EABI_THUMB:
        /* setup instructions */
        code.u16[0] = 0xdf00; /* svc #0 */
        code.u16[1] = BREAKINST_THUMB;
#ifdef __LP64__
        code.u16[2] = 0x46c0; /* nop (mov r8, r8) */
        code.u16[3] = 0x46c0; /* nop (mov r8, r8) */
#endif
        code_size = sizeof(long);
        /* setup registers */
        uregs[16] |= THUMB_MODE_BIT;
        uregs[15] = injector->code_addr;
        uregs[7] = syscall_number;
        uregs[0] = arg1;
        uregs[1] = arg2;
        uregs[2] = arg3;
        uregs[3] = arg4;
        uregs[4] = arg5;
        uregs[5] = arg6;
        reg32_return = &uregs[0];
        break;
    case ARCH_ARM_EABI:
        /* setup instructions */
        code.u32[0] = 0xef000000; /* svc #0 */
        code.u32[1] = BREAKINST_ARM;
        code_size = 2 * 4;
        /* setup registers */
        uregs[16] &= ~THUMB_MODE_BIT;
        uregs[15] = injector->code_addr;
        uregs[7] = syscall_number;
        uregs[0] = arg1;
        uregs[1] = arg2;
        uregs[2] = arg3;
        uregs[3] = arg4;
        uregs[4] = arg5;
        uregs[5] = arg6;
        reg32_return = &uregs[0];
        break;
#endif
#if defined(__mips__)
    case ARCH_MIPS_64:
    case ARCH_MIPS_N32:
    case ARCH_MIPS_O32:
        /* setup instructions */
        if (syscall_number > 0xffff) {
            injector__set_errmsg("too large system call number: %d", syscall_number);
            return INJERR_OTHER;
        }
        code.u32[0] = 0x00000025 | (REG_A3 << 11) | (REG_T4 << 21); /* or $a3, $t4, $zero; move $a3, $t4 */
        code.u32[1] = 0x24000000 | (REG_V0 << 16) | syscall_number; /* addiu $v0, $zero, syscall_number */
        code.u32[2] = 0x0000000c; /* syscall */
        code.u32[3] = 0x0000000d; /* break */
        code_size = 4 * 4;
        DEBUG("  Code: %08"PRIx32" %08"PRIx32" %08"PRIx32" %08"PRIx32"\n",
              code.u32[0], code.u32[1], code.u32[2], code.u32[3]);
        /* setup registers */
        regs.cp0_epc  = injector->code_addr;
        regs.regs[REG_A0] = arg1;
        regs.regs[REG_A1] = arg2;
        regs.regs[REG_A2] = arg3;
        // Use the combination of "regs.regs[REG_T4] = arg4" and "move $a3, $t4"
        // instead of "regs.regs[REG_A3] = arg4". I don't know why the latter
        // doesn't work.
        regs.regs[REG_T4] = arg4;
        if (injector->arch != ARCH_MIPS_O32) {
            /* ARCH_MIPS_64 or ARCH_MIPS_N32 */
            regs.regs[REG_A4] = arg5;
            regs.regs[REG_A5] = arg6;
        } else {
            /* ARCH_MIPS_O32 */
            regs.regs[REG_SP] -= 32;
            PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.regs[REG_SP] + 16, arg5);
            PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.regs[REG_SP] + 20, arg6);
        }
        break;
#endif
#if defined(__powerpc__)
#ifdef __LP64__
    case ARCH_POWERPC_64:
#endif
    case ARCH_POWERPC:
        /* setup instructions */
        code.u32[0] = 0x44000002; /* sc */
        code.u32[1] = 0x7fe00008; /* trap */
        code_size = 2 * 4;
        /* setup registers */
        regs.nip = injector->code_addr;
        regs.gpr[PT_R0] = syscall_number;
        regs.gpr[PT_R3] = arg1;
        regs.gpr[PT_R4] = arg2;
        regs.gpr[PT_R5] = arg3;
        regs.gpr[PT_R6] = arg4;
        regs.gpr[PT_R7] = arg5;
        regs.gpr[PT_R8] = arg6;
        break;
#endif
#if defined(__riscv)
#ifdef __LP64__
    case ARCH_RISCV_64:
#endif
    case ARCH_RISCV_32:
        /* setup instructions */
        code.u32[0] = 0x00000073; /* ecall */
        code.u32[1] = 0x00100073; /* ebreak */
        code_size = 2 * 4;
        DEBUG("  Code: %08"PRIx32" %08"PRIx32"\n",
              code.u32[0], code.u32[1]);
        /* setup registers */
        regs.pc  = injector->code_addr;
        regs.a0 = arg1;
        regs.a1 = arg2;
        regs.a2 = arg3;
        regs.a3 = arg4;
        regs.a4 = arg5;
        regs.a5 = arg6;
        regs.a7 = syscall_number;
        reg_return = &regs.a0;
        break;
#endif
    default:
        injector__set_errmsg("Unexpected architecture: %s", injector__arch2name(injector->arch));
        return INJERR_UNSUPPORTED_TARGET;
    }

    PRINT_REGS(injector, &regs);
    rv = kick_then_wait_sigtrap(injector, &regs, &code, code_size);
    if (rv != 0) {
        return rv;
    }
    PRINT_REGS(injector, &regs);

    if (retval != NULL) {
#if defined(__mips__)
        if (regs.regs[REG_A3] == 0) {
            *retval = (intptr_t)regs.regs[REG_V0];
        } else {
            errno = (int)regs.regs[REG_V0];
            *retval = -1;
        }
#elif defined(__powerpc__)
        /* https://github.com/strace/strace/blob/v5.19/src/linux/powerpc/get_error.c#L21-L26 */
        if (regs.ccr & 0x10000000) {
            errno = (int)regs.gpr[PT_R3];
            *retval = -1;
        } else {
            *retval = (intptr_t)regs.gpr[PT_R3];
        }
#else
#if defined(__aarch64__)
        if (reg32_return != NULL) {
            if (*reg32_return <= -4096u) {
                *retval = (intptr_t)*reg32_return;
            } else {
                errno = -((int)*reg32_return);
                *retval = -1;
            }
        } else {
#endif
            if ((unsigned long)*reg_return <= -4096ul) {
                *retval = (intptr_t)*reg_return;
            } else {
                errno = -((int)*reg_return);
                *retval = -1;
            }
#if defined(__aarch64__)
        }
#endif
#endif /* defined(__mips__) */
    }
    return 0;
}

/*
 * Call the function at the specified address in the target process.
 *
 * The arguments after function_addr must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_function(const injector_t *injector, intptr_t *retval, long function_addr, ...)
{
    va_list ap;
    int rv;
    va_start(ap, function_addr);
    rv = injector__call_function_va_list(injector, retval, function_addr, ap);
    va_end(ap);
    return rv;
}

/*
 * Call the function at the specified address in the target process.
 *
 * The arguments after function_addr must be integer types and
 * the size must not be greater than the size of long.
 */
int injector__call_function_va_list(const injector_t *injector, intptr_t *retval, long function_addr, va_list ap)
{
    struct user_regs_struct regs = injector->regs;
    code_t code;
    size_t code_size;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    long fc_args[6];
    int nargs;
    int rv;
    user_reg_t *reg_return = NULL;
#if defined(__aarch64__)
    uint32_t *reg32_return = NULL;
    uint32_t *uregs = (uint32_t *)&regs;
#endif

    nargs = function_arg_count(injector, function_addr);
    read_varargs(ap, nargs, fc_args);
    arg1 = fc_args[0];
    arg2 = fc_args[1];
    arg3 = fc_args[2];
    arg4 = fc_args[3];
    arg5 = fc_args[4];
    arg6 = fc_args[5];

    DEBUG("injector__call_function:\n");
    DEBUG("  args: %lx, %lx, %lx, %lx, %lx, %lx, %lx\n", function_addr, arg1, arg2, arg3, arg4, arg5, arg6);

    switch (injector->arch) {
#if defined(__x86_64__) && defined(__LP64__)
    case ARCH_X86_64:
    case ARCH_X86_64_X32:
        /* setup instructions */
        code.u8[0] = TRAMP_CALLFUNC_B0;
        code.u8[1] = TRAMP_CALLFUNC_B1; /* ff d0 : callq *%rax */
        code.u8[2] = TRAMP_INT3;        /* cc    : int3        */
        memset(&code.u8[TRAMP_LEN], TRAMP_NOP, sizeof(long) - TRAMP_LEN); /* fill the rests with `nop` */
        code_size = sizeof(long);
        /* setup registers */
        regs.rip = injector->code_addr;
        regs.rbp = injector->stack + injector->stack_size - 16;
        /* rsp must be aligned to a 16-byte boundary. */
        regs.rsp = injector->stack + injector->stack_size - (2 * 16);
        regs.rax = function_addr;
        regs.rdi = arg1;
        regs.rsi = arg2;
        regs.rdx = arg3;
        regs.rcx = arg4;
        regs.r8 = arg5;
        regs.r9 = arg6;
        reg_return = &regs.rax;
        break;
#endif
#if defined(__x86_64__) || defined(__i386__)
    case ARCH_I386:
        /* setup instructions */
        code.u8[0] = TRAMP_CALLFUNC_B0;
        code.u8[1] = TRAMP_CALLFUNC_B1; /* ff d0 : call *%eax */
        code.u8[2] = TRAMP_INT3;        /* cc    : int3       */
        memset(&code.u8[TRAMP_LEN], TRAMP_NOP, sizeof(long) - TRAMP_LEN); /* fill the rests with `nop` */
        code_size = sizeof(long);
        /* setup registers */
        regs.eip = injector->code_addr;
        regs.ebp = injector->stack + injector->stack_size - 16;
        /* esp should be at 16-byte boundary after call instruction.*/
        regs.esp = injector->stack + injector->stack_size - (3 * 16) + 4;
        regs.eax = function_addr;
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 0, arg1);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 4, arg2);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 8, arg3);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 12, arg4);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 16, arg5);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.esp + 20, arg6);
        reg_return = &regs.eax;
        break;
#endif
#if defined(__aarch64__)
    case ARCH_ARM64:
        /* setup instructions */
        code.u32[0] = 0xd63f00c0; /* blr x6 */
        code.u32[1] = BREAKINST_ARM64;
        code_size = 2 * 4;
        /* setup registers */
        regs.pc = injector->code_addr;
        regs.sp = injector->stack + injector->stack_size - 16;
        regs.regs[6] = function_addr;
        regs.regs[0] = arg1;
        regs.regs[1] = arg2;
        regs.regs[2] = arg3;
        regs.regs[3] = arg4;
        regs.regs[4] = arg5;
        regs.regs[5] = arg6;
        reg_return = &regs.regs[0];
        break;
#endif
#if defined(__aarch64__) || defined(__arm__)
    case ARCH_ARM_EABI_THUMB:
        /* setup instructions */
        code.u16[0] = 0x47a0; /* blx r4 */
        code.u16[1] = BREAKINST_THUMB;
#ifdef __LP64__
        code.u16[2] = 0x46c0; /* nop (mov r8, r8) */
        code.u16[3] = 0x46c0; /* nop (mov r8, r8) */
#endif
        code_size = sizeof(long);
        /* setup registers */
        uregs[16] |= THUMB_MODE_BIT;
        uregs[15] = injector->code_addr;
        uregs[13] = injector->stack + injector->stack_size - 16;
        uregs[4] = function_addr;
        uregs[0] = arg1;
        uregs[1] = arg2;
        uregs[2] = arg3;
        uregs[3] = arg4;
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, uregs[13] + 0, arg5);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, uregs[13] + 4, arg6);
        reg32_return = &uregs[0];
        break;
    case ARCH_ARM_EABI:
        /* setup instructions */
        code.u32[0] = 0xe12fff34; /* blx r4 */
        code.u32[1] = BREAKINST_ARM;
        code_size = 2 * 4;
        /* setup registers */
        uregs[16] &= ~THUMB_MODE_BIT;
        uregs[15] = injector->code_addr;
        uregs[13] = injector->stack + injector->stack_size - 16;
        uregs[4] = function_addr;
        uregs[0] = arg1;
        uregs[1] = arg2;
        uregs[2] = arg3;
        uregs[3] = arg4;
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, uregs[13] + 0, arg5);
        PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, uregs[13] + 4, arg6);
        reg32_return = &uregs[0];
        break;
#endif
#if defined(__mips__)
    case ARCH_MIPS_64:
    case ARCH_MIPS_N32:
    case ARCH_MIPS_O32:
        /* setup instructions */
        code.u32[0] = 0x00000009 | (REG_RA << 11) | (REG_T9 << 21); /* jalr $t9;  */
        code.u32[1] = 0x00000025 | (REG_A3 << 11) | (REG_T4 << 21); /* or $a3, $t4, $zero; in a delay slot */
        code.u32[2] = 0x0000000d; /* break */
        code.u32[3] = 0x00000000; /* nop */
        code_size = 4 * 4;
        DEBUG("  Code: %08"PRIx32" %08"PRIx32" %08"PRIx32" %08"PRIx32"\n",
              code.u32[0], code.u32[1], code.u32[2], code.u32[3]);
        /* setup registers */
        regs.cp0_epc  = injector->code_addr;
        regs.regs[REG_FP] = injector->stack + injector->stack_size - 32;
        regs.regs[REG_SP] = injector->stack + injector->stack_size - 64;
        regs.regs[REG_T9] = function_addr;
        regs.regs[REG_A0] = arg1;
        regs.regs[REG_A1] = arg2;
        regs.regs[REG_A2] = arg3;
        regs.regs[REG_T4] = arg4;
        if (injector->arch != ARCH_MIPS_O32) {
            /* ARCH_MIPS_64 or ARCH_MIPS_N32 */
            regs.regs[REG_A4] = arg5;
            regs.regs[REG_A5] = arg6;
        } else {
            /* ARCH_MIPS_O32 */
            PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.regs[REG_SP] + 16, arg5);
            PTRACE_OR_RETURN(PTRACE_POKETEXT, injector, regs.regs[REG_SP] + 20, arg6);
        }
        reg_return = &regs.regs[REG_V0];
        break;
#endif
#if defined(__powerpc__)
#ifdef __LP64__
    case ARCH_POWERPC_64:
#endif
    case ARCH_POWERPC:
        /* setup instructions */
        code.u32[0] = 0x4e800421; /* bctrl */
        code.u32[1] = 0x7fe00008; /* trap */
        code_size = 2 * 4;
        /* setup registers */
        regs.nip = injector->code_addr;
        regs.gpr[PT_R1] = injector->stack + injector->stack_size - 256;
        regs.ctr = function_addr;
        regs.gpr[PT_R3] = arg1;
        regs.gpr[PT_R4] = arg2;
        regs.gpr[PT_R5] = arg3;
        regs.gpr[PT_R6] = arg4;
        regs.gpr[PT_R7] = arg5;
        regs.gpr[PT_R8] = arg6;
        regs.gpr[PT_R12] = function_addr;
        reg_return = &regs.gpr[PT_R3];
        break;
#endif
#if defined(__riscv)
#ifdef __LP64__
    case ARCH_RISCV_64:
#endif
    case ARCH_RISCV_32:
        /* setup instructions */
        code.u32[0] = 0x00000067 | (REG_RA << 7) | (REG_T1 << 15) ; /* jalr t1 */
        code.u32[1] = 0x00100073; /* ebreak */
        code_size = 2 * 4;
        DEBUG("  Code: %08"PRIx32" %08"PRIx32"\n",
              code.u32[0], code.u32[1]);
        /* setup registers */
        regs.pc = injector->code_addr;
        regs.sp = injector->stack + injector->stack_size - 16;
        regs.t1 = function_addr;
        regs.a0 = arg1;
        regs.a1 = arg2;
        regs.a2 = arg3;
        regs.a3 = arg4;
        regs.a4 = arg5;
        regs.a5 = arg6;
        reg_return = &regs.a0;
        break;
#endif
    default:
        injector__set_errmsg("Unexpected architecture: %s", injector__arch2name(injector->arch));
        return INJERR_UNSUPPORTED_TARGET;
    }

    PRINT_REGS(injector, &regs);
    rv = kick_then_wait_sigtrap(injector, &regs, &code, code_size);
    if (rv != 0) {
        return rv;
    }
    PRINT_REGS(injector, &regs);

    if (retval != NULL) {
#if defined(__aarch64__)
        if (reg32_return != NULL) {
            *retval = (long)*reg32_return;
        } else {
            *retval = (long)*reg_return;
        }
#else
        *retval = (long)*reg_return;
#endif
    }
    return 0;
}

/* ------------------------------------------------------------------------
 * Recognising our own trampoline.
 *
 * injector__attach_internal() reads sizeof(code_t) bytes at injector->code_addr
 * (libc's e_entry) and keeps them as `backup_code`, i.e. as the target's
 * ORIGINAL code that every later restore writes back. A handle that
 * desynchronised can leave the trampoline installed there, so on a fresh attach
 * that read would capture OUR bytes and present them as the target's: every
 * later "restore" would then re-install an `int3` into libc's entry point and
 * the target would die at its next call, silently and unrecoverably, because
 * the original bytes are exactly what is missing. The bytes read at attach time
 * are therefore matched against what the two writers above emit, and the attach
 * is refused on a hit.
 *
 * How wide the match is, per architecture - it is NOT uniform, and a clean
 * target must never be refused by mistake:
 *   - x86 (both writers): exact and full-width over all of code_t, including the
 *     `nop` padding, which no compiler emits after an `int3` in the middle of a
 *     function prologue. Unambiguous.
 *   - arm64, arm, powerpc, riscv: both words the writer emits, i.e. the whole
 *     trampoline. Unambiguous.
 *   - arm EABI thumb on an LP64 host: the two emitted halfwords. The writer also
 *     pads u16[2..3] with `mov r8, r8` there; that padding is not compared, but
 *     the breakinst plus the svc/blx halfword is already decisive without it.
 *   - mips: three of the four words. The syscall writer puts the syscall NUMBER
 *     in u32[1], so that word cannot be matched at all; u32[0] plus `syscall`
 *     plus `break` is what is compared instead.
 * This is detect-and-refuse ONLY: nothing here may repair or overwrite the
 * target, and the `default:` branch answers "not ours" rather than guessing for
 * an architecture this build has no writer for.
 *
 * Each branch reuses the corresponding writer's own preprocessor guard and word
 * layout, and the byte patterns themselves are the TRAMP_* / BREAKINST_* /
 * REG_* macros the writers emit, so the two cannot drift apart silently - on
 * x86 that is now true by construction rather than by diligence, and
 * tests/unit/test_trampoline.c asserts the detector against those macros so a
 * detector-only edit is a red build rather than a false negative in the field.
 * The remaining manual coupling is the per-arch guard and word layout; keep
 * those in step with injector__call_syscall() and
 * injector__call_function_va_list() above.
 * ---------------------------------------------------------------------- */
#if defined(__x86_64__) || defined(__i386__)
/* Both x86 writers pad their 3-byte trampoline with `nop` up to sizeof(long),
 * which on x86 is sizeof(code_t), so the whole word must look like that. */
static int x86_trampoline_is_nop_padded(const code_t *code)
{
    size_t i;
    for (i = TRAMP_LEN; i < sizeof(code_t); i++) {
        if (code->u8[i] != TRAMP_NOP) {
            return 0;
        }
    }
    return 1;
}
#endif

int injector__code_is_trampoline(const injector_t *injector, const code_t *code)
{
    switch (injector->arch) {
#if defined(__x86_64__) && defined(__LP64__)
    case ARCH_X86_64:
    case ARCH_X86_64_X32:
        /* `0f 05 cc` = syscall; int3     (injector__call_syscall)
         * `ff d0 cc` = callq *%rax; int3 (injector__call_function_va_list) */
        if (code->u8[2] == TRAMP_INT3 &&
            ((code->u8[0] == TRAMP_SYSCALL64_B0 &&
              code->u8[1] == TRAMP_SYSCALL64_B1) ||
             (code->u8[0] == TRAMP_CALLFUNC_B0 &&
              code->u8[1] == TRAMP_CALLFUNC_B1))) {
            return x86_trampoline_is_nop_padded(code);
        }
        return 0;
#endif
#if defined(__x86_64__) || defined(__i386__)
    case ARCH_I386:
        /* `cd 80 cc` = int $0x80; int3   (injector__call_syscall)
         * `ff d0 cc` = call *%eax; int3  (injector__call_function_va_list) */
        if (code->u8[2] == TRAMP_INT3 &&
            ((code->u8[0] == TRAMP_SYSCALL32_B0 &&
              code->u8[1] == TRAMP_SYSCALL32_B1) ||
             (code->u8[0] == TRAMP_CALLFUNC_B0 &&
              code->u8[1] == TRAMP_CALLFUNC_B1))) {
            return x86_trampoline_is_nop_padded(code);
        }
        return 0;
#endif
#if defined(__aarch64__)
    case ARCH_ARM64:
        /* `svc #0; brk #0` or `blr x6; brk #0` */
        return code->u32[1] == (uint32_t)BREAKINST_ARM64 &&
               (code->u32[0] == 0xd4000001u || code->u32[0] == 0xd63f00c0u);
#endif
#if defined(__aarch64__) || defined(__arm__)
    case ARCH_ARM_EABI_THUMB:
        /* `svc #0` or `blx r4`, each followed by the thumb breakinst */
        return code->u16[1] == (uint16_t)BREAKINST_THUMB &&
               (code->u16[0] == 0xdf00u || code->u16[0] == 0x47a0u);
    case ARCH_ARM_EABI:
        /* `svc #0; <arm breakinst>` or `blx r4; <arm breakinst>` */
        return code->u32[1] == (uint32_t)BREAKINST_ARM &&
               (code->u32[0] == 0xef000000u || code->u32[0] == 0xe12fff34u);
#endif
#if defined(__mips__)
    case ARCH_MIPS_64:
    case ARCH_MIPS_N32:
    case ARCH_MIPS_O32:
        /* syscall: `or $a3,$t4,$zero; addiu $v0,$zero,N; syscall; break`. Word
         * 1 carries the syscall number and cannot be matched, so words 0, 2 and
         * 3 are the anchor. function: `jalr $t9; or $a3,$t4,$zero; break; nop`,
         * where word 1 is fixed but word 0 already identifies it. */
        if (code->u32[0] == (uint32_t)(0x00000025 | (REG_A3 << 11) | (REG_T4 << 21))) {
            return code->u32[2] == 0x0000000cu && code->u32[3] == 0x0000000du;
        }
        return code->u32[0] == (uint32_t)(0x00000009 | (REG_RA << 11) | (REG_T9 << 21)) &&
               code->u32[2] == 0x0000000du;
#endif
#if defined(__powerpc__)
#ifdef __LP64__
    case ARCH_POWERPC_64:
#endif
    case ARCH_POWERPC:
        /* `sc; trap` or `bctrl; trap` */
        return code->u32[1] == 0x7fe00008u &&
               (code->u32[0] == 0x44000002u || code->u32[0] == 0x4e800421u);
#endif
#if defined(__riscv)
#ifdef __LP64__
    case ARCH_RISCV_64:
#endif
    case ARCH_RISCV_32:
        /* `ecall; ebreak` or `jalr t1; ebreak` */
        return code->u32[1] == 0x00100073u &&
               (code->u32[0] == 0x00000073u ||
                code->u32[0] == (uint32_t)(0x00000067 | (REG_RA << 7) | (REG_T1 << 15)));
#endif
    default:
        /* An architecture this build has no trampoline writer for. */
        return 0;
    }
}

/* injector.c: read the thread-group leader ("Tgid:" in /proc/<pid>/status) of
 * `pid`, which may be a non-leader thread. Declared at its call site rather than
 * in injector_internal.h, the way injector__detach_process()'s translation unit
 * declares injector__remote_call_reset() below. */

/* ------------------------------------------------------------------------
 * Per-handle waitpid protocol state.
 *
 * kick_then_wait_sigtrap() drives the tracee through a strict protocol: every
 * PTRACE_CONT is matched by exactly one waitpid status for injector->pid. If we
 * ever give up while the tracee is still running - because it could not be
 * re-stopped after a timeout, because a foreign fatal signal was handed back to
 * it, or because someone else reaped our status - that protocol is left
 * desynchronised, and every later remote call on the same handle would consume
 * a stale stop or never see its own. Such pids are remembered here so later
 * calls fail fast with a clear message instead of corrupting the target.
 *
 * Thread-local storage: a handle is driven by one thread at a time, which is
 * the same assumption util.c makes with injector__set_current(). A fresh
 * attach clears the mark (see injector__attach_process in ptrace.c).
 * ---------------------------------------------------------------------- */
/* How long to wait for our SIGSTOP to be observed after a timeout, and how
 * much longer to keep waiting when the target is in an uninterruptible /
 * TASK_KILLABLE wait and therefore cannot be stopped yet (see handle_timeout). */
#define STOP_GRACE_MS         2000L
#define STOP_GRACE_EXTEND_MS  8000L

/* 40 rather than the 8 this table started with: markers accumulate for every
 * DISTINCT pid a thread has desynced, including handles it detached long ago,
 * so a thread that works through many targets fills the table without ever
 * holding many handles at once. desync_reclaim_dead() below stops dead ones
 * from counting at all. The cost is 2 * DESYNC_SLOTS pid_t of TLS per thread -
 * 320 bytes, since MINOR 4 added a parallel desync_tgids[] - which is a cheap
 * margin.
 *
 * MINOR 7, and the rule this table now lives by: a marker for a LIVE pid is
 * NEVER evicted. Age-eviction - what 48328e2 introduced - dropped the oldest
 * marker as soon as a ninth distinct pid desynced in a thread, and the evicted
 * handle was then treated as usable: it went on to re-patch a trampoline whose
 * original bytes were already lost, i.e. it silently corrupted a live target.
 * Dropping the NEW marker instead is no better, it just moves the corruption to
 * the handle that desynced last.
 *
 * So when the table genuinely runs out, nothing is evicted: the marker is not
 * stored and `desync_lossy` latches, which makes injector__handle_is_desynced()
 * refuse EVERY handle in the thread. Loud, permanent and recoverable (detach the
 * handles you are done with and drive the rest from fresh threads) - unlike a
 * clobbered text section. It also cannot be undone by a later reset(), because
 * the pid that lost its marker is unknown and no later event can prove it safe.
 *
 * Three releases keep that state out of reach in practice, so latching takes 40
 * DISTINCT PIDS marked and still not provably dead, in one thread, at the moment
 * a 41st is marked. Note what that is NOT: it is not 40 handles attached at the
 * same instant. injector__detach_process() releases the FP slot
 * unconditionally but drops this marker only once PTRACE_DETACH has SUCCEEDED,
 * and a desynced target usually answers DETACH with ESRCH - so the handle is
 * gone while its marker stays. Attaching to 40 live targets one after another
 * in a single thread, each desyncing, fills the table just as dead. That is
 * still far past the one-handle-per-thread model util.c's
 * injector__set_current() already assumes, and the markers are reclaimed as
 * their pids die, but the bound is on live marked pids, not on concurrency:
 *   - injector__detach_process() drops the marker once PTRACE_DETACH succeeds,
 *     so a slot is held only while a handle is actually attached (a detached
 *     handle can make no remote call, and a re-attach clears the mark anyway) -
 *     or, when DETACH failed, until that pid dies: NIT 6, because a pid that is
 *     still traced may still carry a trampoline, so its marker has to outlive
 *     the handle injector_detach() is about to free;
 *   - desync_reclaim_dead() drops markers whose pid is provably gone;
 *   - injector__remote_call_reset() drops it on a fresh attach to that pid. */
#define DESYNC_SLOTS 40
static __thread pid_t desync_pids[DESYNC_SLOTS];
/* Thread-group leader of each marked pid, captured when the marker was
 * stored; 0 when /proc could not answer. See desync_pid_gone(). */
static __thread pid_t desync_tgids[DESYNC_SLOTS];
/* Latched when a marker did not fit. Never cleared - see above. */
static __thread int desync_lossy;

static int desync_find(pid_t pid)
{
    int i;
    for (i = 0; i < DESYNC_SLOTS; i++) {
        if (desync_pids[i] == pid) {
            return i;
        }
    }
    return -1;
}

static int desync_free_slot(void)
{
    int i;
    for (i = 0; i < DESYNC_SLOTS; i++) {
        if (desync_pids[i] == 0) {
            return i;
        }
    }
    return -1;
}

/* Is the process wearing `pid` - meaning its whole THREAD GROUP - definitely
 * GONE? Only a definite answer may release a slot, so this asks with
 * kill(pid, 0) and reads ESRCH. Signal 0 delivers nothing - it only runs the
 * existence and permission checks - and EPERM therefore still means "alive, we
 * may just not touch it". That is why it is sound where access("/proc/<pid>")
 * is not: a hidepid /proc, or any other reason a live process is invisible
 * there, would have read as death and dropped a live handle's marker.
 *
 * MINOR 4: `pid` is whatever the caller attached to, which may be a non-leader
 * THREAD. A thread can exit while its thread group - and the mm that holds the
 * patched text section - lives on, and kill(tid, 0) answers ESRCH for it as
 * soon as it does. Reading that as "gone" released a marker for a process that
 * may still be carrying our trampoline, i.e. it handed back a handle that
 * would go on to re-patch bytes whose original was already lost: the same
 * corruption class the attach-time guard above exists to stop. So the group
 * leader recorded at mark time is probed too and BOTH must be gone. `tgid <= 1`
 * means the leader was not recorded, because /proc/<pid>/status was unreadable
 * when the marker was stored - in practice the task was already gone or dying.
 * Note how narrow what that costs is: the group probe is only skipped once
 * kill(pid, 0) has ALREADY answered ESRCH, so a task that is alive but hides its
 * /proc entry (hidepid, a permission error) never reaches this branch - it is
 * answered "not gone" by kill(pid, 0) first. The residual case is a thread whose
 * /proc entry was unreadable at mark time and whose whole group is somehow still
 * alive; there is no anchor left for it, so the pre-fix pid-only answer is kept
 * rather than pinning the slot forever.
 *
 * NIT 5: pid <= 1 is never probed at all, not even with signal 0 - nothing in
 * this library may touch pid 1 in any form - but answering "gone" here is NOT
 * "the safe direction" and must not be read as one. It RELEASES a marker, so
 * for a live pid it would hand back a handle whose waitpid protocol is out of
 * sync, which is precisely the failure this table exists to prevent. What makes
 * the branch tolerable is that it is unreachable: every entry is an
 * injector->pid, injector__handle_mark_desynced() below ignores pid == 0, and
 * injector__attach_internal() refuses pid <= 1 before a handle can exist at
 * all. It stays only so that a bug which somehow stored pid 1 can never cause
 * a signal to be sent to it. */
static int desync_pid_gone(pid_t pid, pid_t tgid)
{
    int saved_errno = errno;   /* callers rely on errno surviving a mark */
    int gone;

    if (pid <= 1) {
        return 1;
    }
    gone = (kill(pid, 0) != 0 && errno == ESRCH);
    if (gone && tgid > 1 && tgid != pid) {
        errno = 0;
        gone = (kill(tgid, 0) != 0 && errno == ESRCH);
    }
    errno = saved_errno;
    return gone;
}

/* Release slots held by pids that are definitely gone; return a free slot, or -1
 * when every slot holds a live pid. A dead pid's marker is worthless: no handle
 * can consult it again, and a recycled pid always arrives through a fresh
 * attach, which calls injector__remote_call_reset() and clears it. This is what
 * keeps the table self-cleaning for the common case - one thread working through
 * many short-lived targets - so that it never has to choose a victim among
 * handles that are still attached. */
static int desync_reclaim_dead(void)
{
    int i, slot = -1;

    for (i = 0; i < DESYNC_SLOTS; i++) {
        if (desync_pids[i] == 0) {
            if (slot < 0) { slot = i; }
        } else if (desync_pid_gone(desync_pids[i], desync_tgids[i])) {
            desync_pids[i] = 0;
            desync_tgids[i] = 0;
            if (slot < 0) { slot = i; }
        }
    }
    return slot;
}

int injector__handle_is_desynced(pid_t pid)
{
    if (desync_find(pid) >= 0) {
        return 1;
    }
    /* Fail closed: desync_lossy means some earlier marker did not fit, so this
     * thread cannot say WHICH of its handles are out of sync. Answering "not
     * desynced" is what age-eviction amounted to, and it let the unmarked
     * handle re-patch a trampoline whose original bytes were already gone. */
    return desync_lossy;
}

void injector__handle_mark_desynced(pid_t pid)
{
    pid_t tgid = 0;
    int saved_errno = errno;   /* callers rely on errno surviving a mark */
    int slot;

    /* desync_find(), not injector__handle_is_desynced(): once desync_lossy is
     * latched the latter answers yes for everything, and this function would
     * then never record anything again. */
    if (pid == 0 || desync_find(pid) >= 0) {
        return;
    }
    slot = desync_free_slot();
    if (slot < 0) {
        slot = desync_reclaim_dead();
    }
    if (slot < 0) {
        desync_lossy = 1;   /* every slot holds a LIVE pid: refuse, never evict */
        return;
    }
    /* MINOR 4: record the thread-group leader now, while the task still has a
     * /proc entry. By the time desync_reclaim_dead() asks whether this marker
     * can be released, `pid` may already be a dead thread and nothing else can
     * say which group it belonged to. Best effort: errno is restored because
     * the callers of this function are in the middle of reporting one. */
    (void)injector__read_tgid(pid, &tgid);
    errno = saved_errno;
    desync_pids[slot] = pid;
    desync_tgids[slot] = (tgid > 1) ? tgid : 0;
}

/* Called by injector__attach_process(): a new attach re-establishes the
 * waitpid protocol from scratch, so forget any previous desync of this pid. */
void injector__remote_call_reset(pid_t pid)
{
    int i;
    for (i = 0; i < DESYNC_SLOTS; i++) {
        if (desync_pids[i] == pid) {
            desync_pids[i] = 0;
            desync_tgids[i] = 0;
        }
    }
    /* desync_lossy is deliberately NOT cleared here: a fresh protocol for THIS
     * pid says nothing about the handle whose marker was lost, and clearing it
     * would make that handle - still desynced, still live - look usable again. */
}

/* ------------------------------------------------------------------------
 * Poll granularity. The previous 1ms -> 50ms exponential backoff could add up
 * to 50ms of stop latency to a single remote call, more than a small user
 * timeout allows. 200us -> 5ms keeps the added latency far below any sensible
 * timeout (cost: at most ~200 wakeups/second while waiting) and no sleep ever
 * crosses the deadline.
 * ---------------------------------------------------------------------- */
#define POLL_MIN_NS 200000L   /* 200us */
#define POLL_MAX_NS 5000000L  /* 5ms   */

static void deadline_from_now(struct timespec *out, long ms)
{
    clock_gettime(CLOCK_MONOTONIC, out);
    out->tv_sec += ms / 1000;
    out->tv_nsec += (ms % 1000) * 1000000L;
    if (out->tv_nsec >= 1000000000L) {
        out->tv_sec++;
        out->tv_nsec -= 1000000000L;
    }
}

/* Nanoseconds left before `deadline`, 0 when it has passed. Clamped to 60s:
 * callers only ever care about the near future. */
static long remaining_ns(const struct timespec *deadline)
{
    struct timespec now;
    long sec;
    long ns;

    clock_gettime(CLOCK_MONOTONIC, &now);
    sec = deadline->tv_sec - now.tv_sec;
    ns = deadline->tv_nsec - now.tv_nsec;
    if (sec < 0 || (sec == 0 && ns <= 0)) {
        return 0;
    }
    if (sec > 60) {
        sec = 60;
    }
    return sec * 1000000000L + ns;
}

static void poll_sleep(long *backoff_ns, const struct timespec *deadline)
{
    long rem = remaining_ns(deadline);
    long nap = *backoff_ns;
    struct timespec ts;

    if (*backoff_ns < POLL_MAX_NS) {
        *backoff_ns *= 2;
        if (*backoff_ns > POLL_MAX_NS) {
            *backoff_ns = POLL_MAX_NS;
        }
    }
    if (rem <= 0) {
        return; /* let the caller observe the timeout immediately */
    }
    if (nap > rem) {
        nap = rem;
    }
    ts.tv_sec = nap / 1000000000L;
    ts.tv_nsec = nap % 1000000000L;
    nanosleep(&ts, NULL);
}

/* Wait up to grace_ms for the tracee to stop.
 *   > 0 : WSTOPSIG() of the observed stop
 *     0 : still running when the grace period expired
 *    -1 : the tracee exited or was killed (*exit_sig gets WTERMSIG, 0 if it exited)
 *    -2 : the waitpid protocol is broken (ECHILD - e.g. the host process
 *         installed a SIGCHLD handler reaping with wait(-1) and stole our
 *         status, or another tracer took the tracee over) */
static int wait_for_stop(pid_t pid, long grace_ms, int *exit_sig)
{
    struct timespec dl;
    long backoff = POLL_MIN_NS;
    int status;

    if (exit_sig != NULL) {
        *exit_sig = 0;
    }
    deadline_from_now(&dl, grace_ms);
    for (;;) {
        pid_t p = waitpid(pid, &status, WNOHANG);
        if (p == pid) {
            if (WIFSTOPPED(status)) {
                return WSTOPSIG(status);
            }
            if (WIFSIGNALED(status) && exit_sig != NULL) {
                *exit_sig = WTERMSIG(status);
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                return -1;
            }
            return -2;
        }
        if (p == -1) {
            if (errno == EINTR) {
                if (remaining_ns(&dl) <= 0) {
                    return 0;
                }
                poll_sleep(&backoff, &dl);   /* no busy spin under a signal storm */
                continue;
            }
            return -2;
        }
        if (remaining_ns(&dl) <= 0) {
            return 0;
        }
        poll_sleep(&backoff, &dl);
    }
}

/* Consume the death status of a tracee we just killed so that no stale waitpid
 * status is left behind for a later call on this handle. Bounded to 1s. */
static void reap_dead_tracee(pid_t pid)
{
    struct timespec dl;
    long backoff = POLL_MIN_NS;
    int status;

    deadline_from_now(&dl, 1000);
    while (remaining_ns(&dl) > 0) {
        pid_t p = waitpid(pid, &status, WNOHANG);
        if (p == pid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                return;
            }
            /* still in a stop with SIGKILL pending: keep polling */
        } else if (p == -1 && errno != EINTR) {
            return; /* ECHILD: someone else reaped it */
        }
        poll_sleep(&backoff, &dl);
    }
}

/* Signals a tracee may legitimately receive from the outside world while we
 * are running a remote call in it (an exiting child, a terminal resize, a
 * timer, ...). They are neither ours nor fatal-by-nature, so handing them back
 * to the target and keeping waiting is what a debugger does; failing the call
 * over them would make remote calls unusable in any process that has children.
 * Job-control signals are deliberately absent: re-delivering them would just
 * produce the same group-stop again. Fatal/hardware signals (SIGSEGV, SIGBUS,
 * SIGILL, SIGFPE, SIGABRT, SIGSYS, ...) must still fail the call. */
static int signal_is_benign(int sig)
{
    switch (sig) {
    case SIGCHLD:
    case SIGWINCH:
    case SIGALRM:
    case SIGVTALRM:
    case SIGPROF:
    case SIGURG:
    case SIGIO:
    case SIGUSR1:
    case SIGUSR2:
    case SIGPIPE:
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
    case SIGQUIT:
        return 1;
    default:
        return 0;
    }
}

/* Is the tracee stopped exactly at the breakpoint instruction *we* wrote at
 * injector->code_addr? A SIGTRAP from anywhere else (the target's own int3, a
 * hardware watchpoint, another tracer's breakpoint) must not be mistaken for
 * the completion of our remote call: its rax would otherwise be used as, say,
 * an mmap base address. */
static int stopped_at_our_break(const injector_t *injector, const struct user_regs_struct *regs, size_t *pc_out)
{
    int match;

    *pc_out = 0;
    switch (injector->arch) {
#if defined(__x86_64__) && defined(__LP64__)
    case ARCH_X86_64:
    case ARCH_X86_64_X32:
        /* `ff d0 cc` (call *%rax) or `0f 05 cc` (syscall): the `int3` sits at
         * code_addr + 2. Measured on Linux 6.8/x86-64 the trap reports rip one
         * past the `int3` (code_addr + 3, the convention gdb compensates for
         * with decr_pc_after_break); accept both that and a kernel reporting
         * rip at the `int3` itself, and reject everything else. */
        *pc_out = (size_t)regs->rip;
        match = (*pc_out == injector->code_addr + 3 || *pc_out == injector->code_addr + 2);
        break;
#endif
#if defined(__x86_64__) || defined(__i386__)
    case ARCH_I386:
        *pc_out = (size_t)(regs->eip & 0xffffffffu);
        match = (*pc_out == injector->code_addr + 3 || *pc_out == injector->code_addr + 2);
        break;
#endif
#if defined(__aarch64__)
    case ARCH_ARM64:
        /* `blr x6; brk #0` */
        *pc_out = (size_t)regs->pc;
        match = (*pc_out == injector->code_addr + 4);
        break;
#endif
#if defined(__aarch64__) || defined(__arm__)
    case ARCH_ARM_EABI_THUMB:
        /* `blx r4; <thumb breakinst>` */
        *pc_out = (size_t)(((const uint32_t *)regs)[15] & ~(size_t)THUMB_MODE_BIT);
        match = (*pc_out == injector->code_addr + 2);
        break;
    case ARCH_ARM_EABI:
        /* `blx r4; <arm breakinst>` */
        *pc_out = (size_t)(((const uint32_t *)regs)[15] & ~(size_t)THUMB_MODE_BIT);
        match = (*pc_out == injector->code_addr + 4);
        break;
#endif
#if defined(__mips__)
    case ARCH_MIPS_64:
    case ARCH_MIPS_N32:
    case ARCH_MIPS_O32:
        /* `jalr; or; syscall; break` */
        *pc_out = (size_t)regs->cp0_epc;
        match = (*pc_out == injector->code_addr + 12);
        break;
#endif
#if defined(__powerpc__)
    case ARCH_POWERPC:
#ifdef __LP64__
    case ARCH_POWERPC_64:
#endif
        /* `sc; trap` */
        *pc_out = (size_t)regs->nip;
        match = (*pc_out == injector->code_addr + 4);
        break;
#endif
#if defined(__riscv)
    case ARCH_RISCV_64:
    case ARCH_RISCV_32:
        /* `ecall; ebreak` */
        *pc_out = (size_t)regs->pc;
        match = (*pc_out == injector->code_addr + 4);
        break;
#endif
    default:
        /* An architecture this build cannot validate: accept the trap. */
        return 1;
    }
    return match;
}

/* Restore the target's original registers - integer *and* FP/vector state, see
 * injector__set_regs() - and its backup code, then PROVE the code is back by
 * reading it out of the target again.
 *
 * Returns 0 only when both halves succeeded. *regs_rv / *code_rv / *regs_err /
 * *code_err report the halves separately, because they fail for different
 * reasons and matter differently:
 *   - PTRACE_SETREGS needs a STOPPED tracee;
 *   - the code restore goes through process_vm_writev() first and therefore
 *     also works while the target is RUNNING (injector__write() additionally
 *     falls back to PTRACE_POKETEXT word-by-word).
 * A failed code restore leaves the `ff d0 cc` trampoline patched into the
 * target's libc e_entry. A live process that later executes it takes a SIGTRAP
 * with no tracer attached and dies - which panics the host if that process
 * happens to be pid 1 - so it must never be reported as success.
 *
 * injector__set_errmsg() is sticky (first writer wins), so the restore runs
 * with the handle detached from the message buffer (injector__set_current(NULL),
 * the same mechanism injector.c uses) and the failures are returned instead:
 * a cleanup-time error must not clobber the primary error the caller reports. */
static int cleanup_restore_full(const injector_t *inj, size_t code_size,
                                int *regs_rv, int *code_rv, int *regs_err, int *code_err)
{
    unsigned char readback[sizeof(code_t)];
    int rrv;
    int crv;

    *regs_rv = 0;
    *code_rv = 0;
    *regs_err = 0;
    *code_err = 0;
    injector__set_current(NULL);
    rrv = injector__set_regs(inj, &inj->regs);
    if (rrv != 0) {
        *regs_err = errno;
    }
    crv = injector__write(inj, inj->code_addr, &inj->backup_code, code_size);
    if (crv != 0) {
        /* process_vm_writev failed (EFAULT/EIO) and so did the POKETEXT
         * fallback inside injector__write(): retry once - giving up here is
         * what leaves a trampoline installed in a live process. */
        *code_err = errno;
        crv = injector__write(inj, inj->code_addr, &inj->backup_code, code_size);
    }
    if (crv == 0) {
        memset(readback, 0, sizeof(readback));
        if (injector__read(inj, inj->code_addr, readback, code_size) != 0) {
            *code_err = errno;
            crv = INJERR_OTHER;   /* cannot prove the trampoline is gone */
        } else if (memcmp(readback, &inj->backup_code, code_size) != 0) {
            *code_err = EIO;
            crv = INJERR_OTHER;   /* wrote it, but the target does not show it */
        }
    } else {
        *code_err = errno;
    }
    injector__set_current((injector_t *)inj);
    *regs_rv = rrv;
    *code_rv = crv;
    return (rrv != 0) ? rrv : crv;
}

/* Called on every exit path of kick_then_wait_sigtrap (success, failure,
 * timeout, target death) so the target is never left with hijacked state.
 * Returns `rv` when the target was restored (or when a more important error
 * already happened), otherwise the restore error: a failed restore must never
 * be reported as success, that would leave the `ff d0 cc` trampoline patched
 * into the target's libc e_entry and its registers hijacked.
 *
 * State left behind on return:
 *   - rv == 0 and the restore worked : ATTACHED + STOPPED, original regs/code.
 *   - restore failed                 : pid marked desynchronised; callers must
 *                                      detach (and re-attach) to use it again. */
static int cleanup_remote_call(const injector_t *inj, size_t code_size, int rv)
{
    int regs_rv, code_rv, regs_err, code_err;
    int cleanup_rv = cleanup_restore_full(inj, code_size, &regs_rv, &code_rv, &regs_err, &code_err);

    if (cleanup_rv != 0) {
        injector__handle_mark_desynced(inj->pid);
        if (code_rv != 0 && kill(inj->pid, 0) == 0) {
            /* Live process with a trampoline we could not verifiably remove:
             * that outranks whatever else went wrong. */
            injector__set_errmsg("the remote call's trampoline at %p in pid %d could NOT be restored and verified (%s); the target may still execute it",
                                 (void *)inj->code_addr, inj->pid, strerror(code_err));
            return code_rv;
        }
        if (rv == 0) {
            injector__set_errmsg("remote call finished but the target's state could not be restored (pid %d): regs=%s code=%s",
                                 inj->pid,
                                 regs_rv != 0 ? strerror(regs_err) : "ok",
                                 code_rv != 0 ? strerror(code_err) : "ok");
            return cleanup_rv;
        }
    }
    return rv;
}

/* Timeout handling. Honours injector->timeout_action:
 *
 *  INJECTOR_TIMEOUT_LEAVE (default)
 *      The tracee is RUNNING (we PTRACE_CONT'ed it), so it has to be stopped
 *      again before its registers and code can be restored. PTRACE_INTERRUPT is
 *      unusable here - the library attaches with PTRACE_ATTACH, not
 *      PTRACE_SEIZE, and PTRACE_INTERRUPT returns EIO for an ATTACH tracee - so
 *      send SIGSTOP instead. That is a ptrace control signal delivered to the
 *      TARGET, not a handler installed in our own process, so the library stays
 *      signal-handler-free (Go-runtime friendly).
 *      On success the handle is left ATTACHED + STOPPED with the original
 *      registers and code, INJERR_TIMEOUT is returned, and the caller's
 *      injector_detach() munmaps and PTRACE_DETACHes normally: no mmap leak, no
 *      stale flags, no hijacked code, and the target resumes at its original pc.
 *
 *  INJECTOR_TIMEOUT_KILL_THREAD
 *      Terminate the thread that is stuck executing the hijacked code. Linux
 *      has no per-thread SIGKILL - a SIGKILL sent to a single tid takes down
 *      its whole thread group - so on the ptrace delivery path, where the
 *      hijacked thread *is* a thread of the target, this terminates the target
 *      process. (The clone/nonstop delivery path runs the hijack in a separate
 *      CLONE_VM task that can be killed on its own; that timeout loop lives in
 *      injector.c, not here.) The death status is reaped so no stale waitpid
 *      status is left behind, and the handle is marked desynchronised.
 */
static int handle_timeout(const injector_t *injector, size_t code_size)
{
    int stop_sig;
    int exit_sig = 0;
    int regs_rv = 0, code_rv = 0, regs_err = 0, code_err = 0;
    int restore_rv;

    if (injector->timeout_action == INJECTOR_TIMEOUT_KILL_THREAD) {
        if (kill(injector->pid, SIGKILL) != 0) {
            int e = errno;
            injector__set_errmsg("remote call timed out after %u ms; timeout_action=INJECTOR_TIMEOUT_KILL_THREAD but kill(pid %d, SIGKILL) failed: %s",
                                 injector->call_timeout_ms, injector->pid, strerror(e));
            injector__handle_mark_desynced(injector->pid);
            return INJERR_TIMEOUT;
        }
        reap_dead_tracee(injector->pid);
        injector__set_errmsg("remote call timed out after %u ms; timeout_action=INJECTOR_TIMEOUT_KILL_THREAD: sent SIGKILL to the hijacked thread (pid %d)",
                             injector->call_timeout_ms, injector->pid);
        injector__handle_mark_desynced(injector->pid);
        return INJERR_TIMEOUT;
    }

    /* INJECTOR_TIMEOUT_LEAVE */
    if (kill(injector->pid, SIGSTOP) != 0) {
        int e = errno;
        injector__set_errmsg("remote call timed out after %u ms; kill(pid %d, SIGSTOP) failed (%s), so the target could not be stopped to restore its state: it keeps running the hijacked code and its libc e_entry stays patched",
                             injector->call_timeout_ms, injector->pid, strerror(e));
        injector__handle_mark_desynced(injector->pid);
        return INJERR_TIMEOUT;
    }

    /* Only SIGSTOP is positively ours; anything else did not come from us. */
    stop_sig = wait_for_stop(injector->pid, STOP_GRACE_MS, &exit_sig);
    if (stop_sig == 0) {
        /* Still running. Without a stop the trampoline CANNOT be removed:
         * injector__write() has to fall back to PTRACE_POKETEXT for libc's text
         * page (process_vm_writev returns EFAULT on a file-backed r-x page -
         * measured on Linux 6.8), and POKETEXT needs a stopped tracee. Leaving
         * `ff d0 cc` behind in a live process is fatal for any process that
         * later executes it, so keep waiting for our pending SIGSTOP to be
         * delivered: a TASK_KILLABLE (vfork) or D-state wait ends eventually,
         * and the alternative is to give up with the trampoline installed. */
        stop_sig = wait_for_stop(injector->pid, STOP_GRACE_EXTEND_MS, &exit_sig);
    }

    if (stop_sig == SIGSTOP) {
        /* Positively our own stop: the tracee is stopped, so restoring its
         * registers and code is safe and the handle stays ATTACHED + STOPPED.
         * cleanup_restore_full() also reads the code back out of the target to
         * prove the trampoline is gone. */
        restore_rv = cleanup_restore_full(injector, code_size, &regs_rv, &code_rv, &regs_err, &code_err);
        if (restore_rv == 0) {
            injector__set_errmsg("remote call timed out after %u ms", injector->call_timeout_ms);
            return INJERR_TIMEOUT;
        }
        injector__handle_mark_desynced(injector->pid);
        injector__set_errmsg("remote call timed out after %u ms and the target's state could not be fully restored (registers: %s; trampoline at %p: %s)",
                             injector->call_timeout_ms,
                             regs_rv != 0 ? strerror(regs_err) : "restored",
                             (void *)injector->code_addr,
                             code_rv != 0 ? strerror(code_err) : "restored and verified");
        return INJERR_TIMEOUT;
    }

    if (stop_sig > 0) {
        /* Stopped, but not by our SIGSTOP. The tracee being stopped makes the
         * restore safe, so restore first - then hand the signal back instead of
         * swallowing it: a SIGSEGV/SIGTRAP that is not ours must stay fatal. */
        (void)cleanup_restore_full(injector, code_size, &regs_rv, &code_rv, &regs_err, &code_err);
        injector__set_errmsg("remote call timed out after %u ms; while re-stopping, pid %d was stopped by signal %d (not our SIGSTOP). Registers: %s. Trampoline at %p: %s. Re-delivered signal %d; this handle is left desynchronised",
                             injector->call_timeout_ms, injector->pid, stop_sig,
                             regs_rv != 0 ? strerror(regs_err) : "restored",
                             (void *)injector->code_addr,
                             code_rv != 0 ? strerror(code_err) : "restored and verified",
                             stop_sig);
        (void)injector__ptrace(PTRACE_CONT, injector->pid, 0, stop_sig, "PTRACE_CONT");
        injector__handle_mark_desynced(injector->pid);
        return INJERR_TIMEOUT;
    }

    if (stop_sig == -1) {
        injector__set_errmsg("remote call timed out after %u ms; pid %d terminated while being re-stopped%s%d",
                             injector->call_timeout_ms, injector->pid,
                             exit_sig != 0 ? " by signal " : " with exit code ", exit_sig);
        injector__handle_mark_desynced(injector->pid);
        return INJERR_TIMEOUT;
    }

    /* 0: never stopped even after the extended grace (TASK_KILLABLE /
     * uninterruptible sleep), -2: our waitpid status was stolen. Nothing can be
     * restored without a stop: PTRACE_SETREGS needs one, and so does the code
     * restore, because injector__write() has to fall back to PTRACE_POKETEXT for
     * libc's text page (process_vm_writev returns EFAULT on a file-backed r-x
     * mapping - measured on Linux 6.8). Still attempt it, then report exactly
     * what state the target is in: a leftover `ff d0 cc` in a live process is
     * what kills any process that later executes libc's e_entry, so the caller
     * must be told rather than handed INJERR_TIMEOUT alone. */
    (void)cleanup_restore_full(injector, code_size, &regs_rv, &code_rv, &regs_err, &code_err);
    injector__set_errmsg("remote call timed out after %u ms; could not re-stop pid %d within %ld ms (%s), so its registers could not be restored (%s). Trampoline at %p: %s. This handle is left desynchronised",
                         injector->call_timeout_ms, injector->pid,
                         STOP_GRACE_MS + STOP_GRACE_EXTEND_MS,
                         stop_sig == -2 ? "the waitpid status was lost, e.g. a host SIGCHLD handler reaping with wait(-1) stole it"
                                        : "uninterruptible/TASK_KILLABLE sleep",
                         regs_rv != 0 ? strerror(regs_err) : "unexpectedly succeeded",
                         (void *)injector->code_addr,
                         code_rv != 0 ? strerror(code_err) : "removed and verified");
    injector__handle_mark_desynced(injector->pid);
    return INJERR_TIMEOUT;
}

static int kick_then_wait_sigtrap(const injector_t *injector, struct user_regs_struct *regs, code_t *code, size_t code_size)
{
    struct timespec deadline;
    int status;
    int rv;
    long backoff_ns = POLL_MIN_NS;

    if (injector__handle_is_desynced(injector->pid)) {
        if (desync_find(injector->pid) < 0) {
            /* MINOR 7: refused because desync_lossy latched - this thread
             * desynced more handles than the table holds and no live marker was
             * evicted to make room - not because this handle is itself known to
             * be out of sync. Say which of the two it is, and what to do. */
            injector__set_errmsg("remote call refused: this thread desynced more handles than injector can track (all %d slots were held by live pids when the table overflowed), and no marker was evicted to make room, so it can no longer say which of its handles are out of sync - pid %d is refused along with every other handle in this thread. Detach the handles you are done with and drive the rest from fresh threads.",
                                 DESYNC_SLOTS, injector->pid);
        } else {
            injector__set_errmsg("remote call refused: an earlier call on this handle timed out and could not leave pid %d stopped, so the ptrace/waitpid protocol is out of sync. Detach and attach again - but if that re-attach is itself refused with 'still carrying an injector trampoline', the trampoline could not be removed and is still patched into the target's libc, so its original bytes are gone and the target cannot be repaired automatically; do not keep retrying it.",
                                 injector->pid);
        }
        return INJERR_WAIT_TRACEE;
    }

    rv = injector__set_regs(injector, regs);
    if (rv != 0) {
        return rv;
    }
    rv = injector__write(injector, injector->code_addr, code, code_size);
    if (rv != 0) {
        return cleanup_remote_call(injector, code_size, rv);
    }
    rv = injector__continue(injector);
    if (rv != 0) {
        return cleanup_remote_call(injector, code_size, rv);
    }

    /* deadline = now + call_timeout_ms. CLOCK_MONOTONIC + polling
     * waitpid(WNOHANG): no SIGALRM, the library must stay signal-free so it can
     * be used from a Go runtime. */
    deadline_from_now(&deadline, (long)injector->call_timeout_ms);

    for (;;) {
        pid_t pid = waitpid(injector->pid, &status, WNOHANG);
        if (pid == -1) {
            if (errno == EINTR) {
                /* A signal interrupted waitpid. Honour the deadline and keep
                 * the bounded sleep, otherwise a host/target delivering signals
                 * at a high rate turns this into a busy spin that burns a core
                 * and never observes the timeout. */
                if (remaining_ns(&deadline) <= 0) {
                    return handle_timeout(injector, code_size);
                }
                poll_sleep(&backoff_ns, &deadline);
                continue;
            }
            /* ECHILD means our tracee status is gone: a host SIGCHLD handler
             * reaping with wait(-1) stole it, or another tracer took over. */
            injector__set_errmsg("waitpid error: %s%s", strerror(errno),
                                 errno == ECHILD ? " (the tracee status was reaped by someone else, e.g. a host SIGCHLD handler using wait(-1))" : "");
            injector__handle_mark_desynced(injector->pid);
            return cleanup_remote_call(injector, code_size, INJERR_WAIT_TRACEE);
        }
        if (pid == injector->pid) {
            if (WIFSTOPPED(status)) {
                switch (WSTOPSIG(status)) {
                case SIGTRAP: {
                    size_t trap_pc = 0;
                    int ours;
                    rv = injector__get_regs(injector, regs);
                    if (rv != 0) {
                        return cleanup_remote_call(injector, code_size, rv);
                    }
                    ours = stopped_at_our_break(injector, regs, &trap_pc);
                    if (ours) {
                        return cleanup_remote_call(injector, code_size, 0);
                    }
                    /* Not our breakpoint: the target's own int3, a hardware
                     * watchpoint or another tracer. Its rax must not be used as
                     * the result of our call - hand SIGTRAP back to the target
                     * and keep waiting, bounded by the timeout. */
                    DEBUG("ignoring a SIGTRAP that is not ours (pc=%"SIZE_T_FMT"lx, expected %"SIZE_T_FMT"lx)\n",
                          trap_pc, injector->code_addr + 2);
                    rv = injector__ptrace(PTRACE_CONT, injector->pid, 0, SIGTRAP, "PTRACE_CONT");
                    if (rv != 0) {
                        return cleanup_remote_call(injector, code_size, rv);
                    }
                    break; /* keep waiting */
                }
                case SIGSTOP:
                    rv = injector__continue(injector);
                    if (rv != 0) {
                        return cleanup_remote_call(injector, code_size, rv);
                    }
                    break;  /* keep waiting */
                default:
#if defined(PT_GETSIGINFO)
                    {
                        siginfo_t si = {0,};
                        if (WSTOPSIG(status) == SIGSYS) {
                            int grv = injector__ptrace(PT_GETSIGINFO, injector->pid, 0, (long)&si, "PT_GETSIGINFO");
                            if (grv != 0) {
                                return cleanup_remote_call(injector, code_size, grv);
                            }
                            if (si.si_signo == SIGSYS && si.si_code == 1) {
                                injector__set_errmsg("Got SIGSYS. System call %d at address %p might be blocked by seccomp.",
                                                     si.si_syscall, (void*)si.si_call_addr);
                                return cleanup_remote_call(injector, code_size, INJERR_OTHER);
                            }
                        }
                    }
#endif
                    if (signal_is_benign(WSTOPSIG(status))) {
                        /* Not ours, not fatal: give it back to the target and
                         * keep waiting for our own stop, bounded by the timeout. */
                        rv = injector__ptrace(PTRACE_CONT, injector->pid, 0, WSTOPSIG(status), "PTRACE_CONT");
                        if (rv != 0) {
                            return cleanup_remote_call(injector, code_size, rv);
                        }
                        break; /* keep waiting */
                    }
                    injector__set_errmsg("The target process unexpectedly stopped by signal %d.", WSTOPSIG(status));
                    return cleanup_remote_call(injector, code_size, INJERR_OTHER);
                }
            } else if (WIFEXITED(status)) {
                injector__set_errmsg("The target process unexpectedly terminated with exit code %d.", WEXITSTATUS(status));
                return cleanup_remote_call(injector, code_size, INJERR_OTHER);
            } else if (WIFSIGNALED(status)) {
                injector__set_errmsg("The target process unexpectedly terminated by signal %d.", WTERMSIG(status));
                return cleanup_remote_call(injector, code_size, INJERR_OTHER);
            } else {
                injector__set_errmsg("Unexpected waitpid status: 0x%x", status);
                return cleanup_remote_call(injector, code_size, INJERR_OTHER);
            }
        }
        /* pid == 0: the tracee has not changed state yet. */
        if (remaining_ns(&deadline) <= 0) {
            return handle_timeout(injector, code_size);
        }
        poll_sleep(&backoff_ns, &deadline);
    }
}
