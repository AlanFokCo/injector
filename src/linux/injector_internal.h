#ifndef INJECTOR_INTERNAL_H
#define INJECTOR_INTERNAL_H 1
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <errno.h>
#include "injector.h"

#ifdef __LP64__
#define SIZE_T_FMT "l"
#else
#define SIZE_T_FMT ""
#endif

#ifdef __arm__
#define user_regs_struct user_regs
#endif

#ifdef __mips__
#include <asm/ptrace.h>
#define user_regs_struct pt_regs
#endif

#ifdef __powerpc__
#include <asm/ptrace.h>
#define user_regs_struct pt_regs
#endif

#ifdef __riscv
#include <asm/ptrace.h>
#endif

#define PTRACE_OR_RETURN(request, injector, addr, data) do { \
    int rv = injector__ptrace(request, injector->pid, addr, data, #request); \
    if (rv != 0) { \
        return rv; \
    } \
} while (0)

typedef enum {
    /* use dlopen/dlsym/dlclose (glibc 2.34 or later) */
    DLFUNC_POSIX,
    /* use __libc_dlopen_mode/__libc_dlsym/__libc_dlclose" (glibc 2.33 or earlier) */
    DLFUNC_INTERNAL,
} dlfunc_type_t;

typedef enum {
    LIBC_TYPE_UNKNOWN = 0,
    LIBC_TYPE_GNU,
    LIBC_TYPE_MUSL,
} libc_type_t;

typedef enum {
    ARCH_X86_64,
    ARCH_X86_64_X32,
    ARCH_I386,
    ARCH_ARM64,
    ARCH_ARM_EABI_THUMB,
    ARCH_ARM_EABI,
    ARCH_MIPS_64,
    ARCH_MIPS_N32,
    ARCH_MIPS_O32,
    ARCH_POWERPC_64,
    ARCH_POWERPC,
    ARCH_RISCV_64,
    ARCH_RISCV_32,
} arch_t;

typedef union {
#if defined(__x86_64__) || defined(__i386__)
    uint8_t u8[sizeof(long)];
#elif defined(__aarch64__) || defined(__arm__)
    uint16_t u16[4];
    uint32_t u32[2];
#elif defined(__mips__)
    uint32_t u32[4];
#elif defined(__powerpc__)
    uint32_t u32[2];
#elif defined(__riscv)
    uint32_t u32[2];
#endif
    long dummy;
} code_t;

struct injector {
    pid_t pid;
    uint8_t attached;
    uint8_t mmapped;
    arch_t arch;
    libc_type_t libc_type;
    struct user_regs_struct regs;
    dlfunc_type_t dlfunc_type;
    size_t dlopen_addr;
    size_t dlclose_addr;
    size_t dlsym_addr;
    size_t dlerror_addr;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    size_t clone_addr;
#endif
    size_t code_addr; /* address where instructions are written */
    code_t backup_code;
    long sys_mmap;
    long sys_mprotect;
    long sys_munmap;

    /* memory layout allocated in the target process
     *
     *  high +----------------------+
     *       |     stack area       |
     *       |      size: 2MB       |
     *       |----------------------|
     *       |  inaccessible area   |
     *       |      size: 4096      |
     *       |----------------------|
     *       |      data area       |
     *       |      size: 4096      |
     *  low  +----------------------+
     */
    size_t data; /* read-write region */
    size_t data_size; /* page size */
    size_t stack; /* stack area */
    size_t stack_size; /* 2MB */
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    size_t shellcode;
    size_t shellcode_invoke;
#endif
    char errmsg[512];
    char errmsg_set;
    unsigned call_timeout_ms;
    injector_delivery_t mode;
    injector_timeout_action_t timeout_action;
    int enable_write_mem;
    void *injected_handles[32];   /* handles created by injector_inject, for uninject_all */
    size_t injected_count;
};

/* elf.c */
int injector__collect_libc_information(injector_t *injector);
int injector__elf_find_symbols(const char *path, size_t libc_addr,
                               const char *const names[], size_t addrs[], size_t n);

/* elf.c: open `path` and return its ELF e_machine (non-intrusive arch probe). */
int injector__read_elf_machine(const char *path, int *machine_out);

/* elf.c: compute the runtime load bias for an ELF object given its lowest
 * /proc/PID/maps mapping start. ET_EXEC -> 0 (symbol values are absolute);
 * ET_DYN (PIE exe / shared object) -> map_start. */
int injector__elf_load_bias(const char *path, size_t map_start, size_t *bias_out);

/* ptrace.c */
int injector__ptrace(int request, pid_t pid, long addr, long data, const char *request_name);
int injector__attach_process(const injector_t *injector);
int injector__detach_process(const injector_t *injector);
int injector__get_regs(const injector_t *injector, struct user_regs_struct *regs);
int injector__set_regs(const injector_t *injector, const struct user_regs_struct *regs);
int injector__read(const injector_t *injector, size_t addr, void *buf, size_t len);
int injector__write(const injector_t *injector, size_t addr, const void *buf, size_t len);
int injector__continue(const injector_t *injector);

/* remote_call.c - call functions and syscalls in the target process */
int injector__call_syscall(const injector_t *injector, intptr_t *retval, long syscall_number, ...);
int injector__call_function(const injector_t *injector, intptr_t *retval, long function_addr, ...);
int injector__call_function_va_list(const injector_t *injector, intptr_t *retval, long function_addr, va_list ap);

/* util.c */
void injector__set_errmsg(const char *format, ...) __attribute__((format (printf, 1, 2)));
const char *injector__arch2name(arch_t arch);
void injector__set_current(injector_t *inj);
void injector__reset_tl_errmsg(void);
const char *injector__tl_errmsg(void);
void injector__opts_normalize(injector_opts_t *o);
int injector__opts_copy(injector_opts_t *dst, const void *src, size_t src_size);
int injector__attach_internal(injector_t **out, pid_t pid, const injector_opts_t *o);

/* shellcode.S */
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
typedef struct {
    void *handle;
    size_t dlopen_addr;
    size_t dlerror_addr;
    int dlflags;
    char file_path[0]; // dummy size.
} injector_shellcode_arg_t;

typedef struct {
    intptr_t retval;       /* 0:  function return value */
    int64_t status;        /* 8:  0=running, 1=ok, 2=error */
    size_t dlopen_addr;    /* 16 */
    size_t dlsym_addr;     /* 24 */
    size_t dlerror_addr;   /* 32 */
    int32_t dlflags;       /* 40 */
    int32_t func_name_off; /* 44: byte offset from struct base to func_name */
    char file_path[0];     /* 48: library path; func_name at base + func_name_off */
} injector_shellcode_invoke_arg_t;

void *injector_shellcode(injector_shellcode_arg_t *arg);
extern int injector_shellcode_size;
void *injector_shellcode_invoke(injector_shellcode_invoke_arg_t *arg);
extern int injector_shellcode_invoke_size;
#endif

#endif
