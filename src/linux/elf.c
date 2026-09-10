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
#include <stdlib.h>
#include <inttypes.h>
#include <regex.h>
#include <elf.h>
#include <glob.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <limits.h>
#include <unistd.h>
#include "injector_internal.h"

#ifdef __LP64__
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Phdr Elf64_Phdr
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Phdr Elf32_Phdr
#endif

/* Bounds for the attacker-controlled "entry size" fields of an ELF file.
 * A 64-bit injector may legitimately read 32-bit ELF objects and vice versa,
 * but nothing else: read_elf_shdr()/read_elf_sym()/read_elf_phdr() write into
 * fixed-size Elf*_Shdr/Sym/Phdr buffers, so a bigger entry size would smash
 * the stack or the heap. On ILP32 the minimum and the maximum are the same. */
#define ELF_SHDR_SIZE_MIN ((size_t)sizeof(Elf32_Shdr))
#define ELF_SHDR_SIZE_MAX ((size_t)sizeof(Elf_Shdr))
#define ELF_SYM_SIZE_MIN  ((size_t)sizeof(Elf32_Sym))
#define ELF_SYM_SIZE_MAX  ((size_t)sizeof(Elf_Sym))
#define ELF_PHDR_SIZE_MIN ((size_t)sizeof(Elf32_Phdr))
#define ELF_PHDR_SIZE_MAX ((size_t)sizeof(Elf_Phdr))

/* "Does this 64-bit ELF field fit in a size_t?"
 *
 * On a 32-bit size_t that is a real check, because the ELF64 fields are wider
 * than size_t. On a 64-bit size_t it is a tautology - and spelling it as a
 * comparison makes -Wtype-limits (implied by -Wextra) reject the build, which
 * matters because this project builds with -Werror and CI compiles the library
 * for i386 and x32 as well as x86_64. Hiding the tautological case behind the
 * preprocessor keeps the check where it is meaningful and the build clean
 * everywhere. */
static int elf_u64_fits_size_t(uint64_t v)
{
#if SIZE_MAX >= UINT64_MAX
    (void)v;
    return 1;
#else
    return v <= (uint64_t)SIZE_MAX;
#endif
}

// #define INJECTOR_DEBUG_ELF_C 1

#ifdef INJECTOR_DEBUG_ELF_C
#undef DEBUG
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#undef DEBUG
#define DEBUG(...) do {} while(0)
#endif

static int search_and_open_libc(FILE **fp_out, char *path_out, size_t path_out_sz, pid_t pid, size_t *addr, libc_type_t *libc_type);
static int open_libc(FILE **fp_out, char *path_out, size_t path_out_sz, const char *path, pid_t pid, dev_t dev, ino_t ino);
static FILE *fopen_with_ino(const char *path, dev_t dev, ino_t ino);
static int read_elf_ehdr(FILE *fp, Elf_Ehdr *ehdr);
static int read_elf_shdr(FILE *fp, Elf_Shdr *shdr, size_t shdr_size);
static int read_elf_sym(FILE *fp, Elf_Sym *sym, size_t sym_size);
static int read_elf_phdr(FILE *fp, Elf_Phdr *phdr, size_t phdr_size);
static int locate_dynsym(FILE *fp, const Elf_Ehdr *ehdr, uint64_t fsize, size_t *str_off, size_t *str_sz, size_t *sym_off, size_t *sym_num, size_t *sym_entsize);
static int elf_file_size(FILE *fp, uint64_t *size_out);
static int elf_seek(FILE *fp, uint64_t offset);
static int elf_range_in_file(uint64_t off, uint64_t len, uint64_t fsize);
static int validate_elf_layout(FILE *fp, const Elf_Ehdr *ehdr, uint64_t *fsize_out);
static int section_name_is(FILE *fp, uint64_t strtab_off, uint64_t strtab_size, uint64_t name_off, const char *want);

int injector__collect_libc_information(injector_t *injector)
{
    pid_t pid = injector->pid;
    FILE *fp = NULL;
    Elf_Ehdr ehdr;
    char path[PATH_MAX];
    size_t libc_addr;
    int rv;

    path[0] = '\0';
    rv = search_and_open_libc(&fp, path, sizeof(path), pid, &libc_addr, &injector->libc_type);
    if (rv != 0) {
        return rv;
    }
    rv = read_elf_ehdr(fp, &ehdr);
    if (rv != 0) {
        goto cleanup;
    }

    /* Reject a hostile header before it is used to compute any file offset. */
    rv = validate_elf_layout(fp, &ehdr, NULL);
    if (rv != 0) {
        goto cleanup;
    }

    /* The meaning of e_entry depends on e_type: for ET_DYN (PIE executable or
     * shared object) it is relative to the load base, for ET_EXEC it is an
     * absolute virtual address. Anything else cannot be injected into. */
    switch (ehdr.e_type) {
    case ET_DYN:
        if ((uint64_t)ehdr.e_entry > (uint64_t)SIZE_MAX - (uint64_t)libc_addr) {
            injector__set_errmsg("invalid ELF entry point: 0x%" PRIx64, (uint64_t)ehdr.e_entry);
            rv = INJERR_INVALID_ELF_FORMAT;
            goto cleanup;
        }
        injector->code_addr = libc_addr + (size_t)ehdr.e_entry;
        break;
    case ET_EXEC:
        injector->code_addr = (size_t)ehdr.e_entry;
        break;
    default:
        injector__set_errmsg("Invalid ELF type: %u", (unsigned int)ehdr.e_type);
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }

    switch (ehdr.e_machine) {
    case EM_X86_64:
        if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
            /* LP64 */
            injector->arch = ARCH_X86_64;
            injector->sys_mmap = 9;
            injector->sys_mprotect = 10;
            injector->sys_munmap = 11;
        } else {
            /* ILP32 */
            injector->arch = ARCH_X86_64_X32;
            injector->sys_mmap = 0x40000000 + 9;
            injector->sys_mprotect = 0x40000000 + 10;
            injector->sys_munmap = 0x40000000 + 11;
        }
        break;
    case EM_386:
        injector->arch = ARCH_I386;
        injector->sys_mmap = 192;
        injector->sys_mprotect = 125;
        injector->sys_munmap = 91;
        break;
    case EM_AARCH64:
        injector->arch = ARCH_ARM64;
        injector->sys_mmap = 222;
        injector->sys_mprotect = 226;
        injector->sys_munmap = 215;
        break;
    case EM_ARM:
        if (EF_ARM_EABI_VERSION(ehdr.e_flags) == 0) {
            injector__set_errmsg("ARM OABI target process isn't supported.");
            rv = INJERR_UNSUPPORTED_TARGET;
            goto cleanup;
        }
        if (injector->code_addr & 1u) {
            injector->code_addr &= ~1u;
            injector->arch = ARCH_ARM_EABI_THUMB;
        } else {
            injector->arch = ARCH_ARM_EABI;
        }
        injector->sys_mmap = 192;
        injector->sys_mprotect = 125;
        injector->sys_munmap = 91;
        break;
    case EM_MIPS:
        if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
            /* MIPS 64 */
            injector->arch = ARCH_MIPS_64;
            injector->sys_mmap = 5000 + 9;
            injector->sys_mprotect = 5000 + 10;
            injector->sys_munmap = 5000 + 11;
        } else if (ehdr.e_flags & EF_MIPS_ABI2) {
            /* MIPS N32 */
            injector->arch = ARCH_MIPS_N32;
            injector->sys_mmap = 6000 + 9;
            injector->sys_mprotect = 6000 + 10;
            injector->sys_munmap = 6000 + 11;
        } else {
            /* MIPS O32 */
            injector->arch = ARCH_MIPS_O32;
            injector->sys_mmap = 4000 + 90;
            injector->sys_mprotect = 4000 + 125;
            injector->sys_munmap = 4000 + 91;
        }
        break;
    case EM_PPC64:
        injector->arch = ARCH_POWERPC_64;
        injector->sys_mmap = 90;
        injector->sys_mprotect = 125;
        injector->sys_munmap = 91;
        break;
    case EM_PPC:
        injector->arch = ARCH_POWERPC;
        injector->sys_mmap = 90;
        injector->sys_mprotect = 125;
        injector->sys_munmap = 91;
        break;
#ifdef EM_RISCV
    case EM_RISCV:
        if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
            injector->arch = ARCH_RISCV_64;
        } else {
            injector->arch = ARCH_RISCV_32;
        }
        injector->sys_mmap = 222;
        injector->sys_mprotect = 226;
        injector->sys_munmap = 215;
        break;
#endif
    default:
        injector__set_errmsg("Unknown target process architecture: 0x%04x", ehdr.e_machine);
        rv = INJERR_UNSUPPORTED_TARGET;
        goto cleanup;
    }

    /* Close the verified FILE*; injector__elf_find_symbols re-opens the
     * resolved path to read .dynstr/.dynsym in a single pass. */
    fclose(fp);
    fp = NULL;

    {
        /*
         * Resolve every wanted symbol name in a single pass over .dynsym.
         *
         * Layout (paired posix/internal names so that the DLFUNC_POSIX vs
         * DLFUNC_INTERNAL decision can be made after the fact, preserving the
         * original "try posix first, fall back to internal" rule):
         *   [0] dlopen                  [1] __libc_dlopen_mode
         *   [2] dlclose                 [3] __libc_dlclose
         *   [4] dlsym                   [5] __libc_dlsym
         *   [6] dlerror                 (posix only)
         *   [7] clone                   (posix == internal name)
         *   [8] gnu_get_libc_release    (existence -> GNU libc)
         */
        const char *names[] = {
            "dlopen", "__libc_dlopen_mode",
            "dlclose", "__libc_dlclose",
            "dlsym", "__libc_dlsym",
            "dlerror",
            "clone",
            "gnu_get_libc_release",
        };
        size_t addrs[9] = {0};

        rv = injector__elf_find_symbols(path, libc_addr, names, addrs, 9);
        if (rv != 0) {
            goto cleanup;
        }

        /* dlopen decides dlfunc_type: try posix first, then internal. */
        if (addrs[0] != 0) {
            injector->dlfunc_type = DLFUNC_POSIX;
            injector->dlopen_addr = addrs[0];
        } else if (addrs[1] != 0) {
            injector->dlfunc_type = DLFUNC_INTERNAL;
            injector->dlopen_addr = addrs[1];
        } else {
            injector__set_errmsg("failed to find dlopen/__libc_dlopen_mode in the .dynsym section.");
            rv = INJERR_NO_FUNCTION;
            goto cleanup;
        }

        /* dlclose */
        if (injector->dlfunc_type == DLFUNC_POSIX) {
            if (addrs[2] == 0) {
                injector__set_errmsg("failed to find dlclose in the .dynsym section.");
                rv = INJERR_NO_FUNCTION;
                goto cleanup;
            }
            injector->dlclose_addr = addrs[2];
        } else {
            if (addrs[3] == 0) {
                injector__set_errmsg("failed to find __libc_dlclose in the .dynsym section.");
                rv = INJERR_NO_FUNCTION;
                goto cleanup;
            }
            injector->dlclose_addr = addrs[3];
        }

        /* dlsym */
        if (injector->dlfunc_type == DLFUNC_POSIX) {
            if (addrs[4] == 0) {
                injector__set_errmsg("failed to find dlsym in the .dynsym section.");
                rv = INJERR_NO_FUNCTION;
                goto cleanup;
            }
            injector->dlsym_addr = addrs[4];
        } else {
            if (addrs[5] == 0) {
                injector__set_errmsg("failed to find __libc_dlsym in the .dynsym section.");
                rv = INJERR_NO_FUNCTION;
                goto cleanup;
            }
            injector->dlsym_addr = addrs[5];
        }

        /* dlerror: looked up only when not DLFUNC_INTERNAL; 0 when INTERNAL. */
        if (injector->dlfunc_type != DLFUNC_INTERNAL) {
            if (addrs[6] == 0) {
                injector__set_errmsg("failed to find dlerror in the .dynsym section.");
                rv = INJERR_NO_FUNCTION;
                goto cleanup;
            }
            injector->dlerror_addr = addrs[6];
        } else {
            injector->dlerror_addr = 0;
        }

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        if (addrs[7] == 0) {
            injector__set_errmsg("failed to find clone in the .dynsym section.");
            rv = INJERR_NO_FUNCTION;
            goto cleanup;
        }
        injector->clone_addr = addrs[7];
#endif

        /* gnu_get_libc_release presence => GNU libc. Not-found is not an error. */
        if (addrs[8] != 0) {
            injector->libc_type = LIBC_TYPE_GNU;
        }
    }

    rv = 0;
cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    return rv;
}

/* Resolve multiple symbols from an ELF file in a single pass.
 *
 * path:      ELF file path (opened internally).
 * libc_addr: load base added to each st_value (use 0 to get raw st_value).
 * names:     array of wanted symbol names (n entries).
 * addrs:     output array (n entries); each set to libc_addr + st_value, or 0
 *            if the name is not present in .dynsym.
 * Returns 0 when the file was parsed successfully (regardless of whether any
 * name matched), INJERR_* on open/parse error.
 */
int injector__elf_find_symbols(const char *path, size_t libc_addr,
                               const char *const names[], size_t addrs[], size_t n)
{
    FILE *fp;
    Elf_Ehdr ehdr;
    size_t str_offset = 0, str_size = 0, sym_offset = 0, sym_num = 0, sym_entsize = 0;
    uint64_t fsize = 0;
    char *str = NULL;
    Elf_Sym *syms = NULL;
    int rv = 0;
    size_t i, k;

    fp = fopen(path, "r");
    if (fp == NULL) {
        injector__set_errmsg("failed to open %s. (error: %s)", path, strerror(errno));
        return INJERR_NO_LIBRARY;
    }

    rv = read_elf_ehdr(fp, &ehdr);
    if (rv != 0) {
        goto cleanup;
    }

    /* Validate every header field used for offsets/sizes exactly once, before
     * any seek or read below. */
    rv = validate_elf_layout(fp, &ehdr, &fsize);
    if (rv != 0) {
        goto cleanup;
    }

    rv = locate_dynsym(fp, &ehdr, fsize, &str_offset, &str_size, &sym_offset, &sym_num, &sym_entsize);
    if (rv != 0) {
        goto cleanup;
    }

    if (str_offset == 0 || str_size == 0 || sym_offset == 0 || sym_entsize == 0 || sym_num == 0) {
        injector__set_errmsg("failed to find the .dynstr and .dynsym sections.");
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }

    /* Neither the string table nor the symbol table can legitimately be larger
     * than the file itself; locate_dynsym() already enforced that. Re-check it
     * here so that the two allocations below can never be driven by an
     * unbounded, file-controlled size. */
    if ((uint64_t)str_size > fsize ||
        (uint64_t)sym_num > fsize / ELF_SYM_SIZE_MIN ||
        (uint64_t)sym_offset > fsize) {
        injector__set_errmsg("invalid .dynstr/.dynsym size.");
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }

    /* Read .dynstr into a heap buffer once. One extra byte is allocated and
     * forced to NUL, so that every strcmp() below stays inside the buffer even
     * when the file's string table has no trailing NUL byte. */
    if (str_size > (size_t)SIZE_MAX - 1) {
        rv = INJERR_NO_MEMORY;
        goto cleanup;
    }
    str = malloc(str_size + 1);
    if (str == NULL) {
        rv = INJERR_NO_MEMORY;
        goto cleanup;
    }
    if (elf_seek(fp, str_offset) != 0 ||
        fread(str, 1, str_size, fp) != str_size) {
        injector__set_errmsg("failed to read .dynstr.");
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }
    str[str_size] = '\0';

    /* Read .dynsym into a heap buffer of Elf_Sym (read_elf_sym handles 32->64
     * conversion on LP64). */
    if (sym_num > (size_t)SIZE_MAX / sizeof(Elf_Sym)) {
        rv = INJERR_NO_MEMORY;
        goto cleanup;
    }
    syms = malloc(sym_num * sizeof(Elf_Sym));
    if (syms == NULL) {
        rv = INJERR_NO_MEMORY;
        goto cleanup;
    }
    if (elf_seek(fp, sym_offset) != 0) {
        injector__set_errmsg("failed to seek .dynsym.");
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }
    for (k = 0; k < sym_num; k++) {
        rv = read_elf_sym(fp, &syms[k], sym_entsize);
        if (rv != 0) {
            goto cleanup;
        }
    }

    /* Single pass over .dynsym, matching against all wanted names. */
    for (i = 0; i < n; i++) {
        addrs[i] = 0;
    }
    for (k = 0; k < sym_num; k++) {
        size_t nm_off = (size_t)syms[k].st_name;
        /* An undefined symbol (an import) or a symbol without an address is
         * not a usable function: reporting it as found would make the caller
         * jump to libc_addr + 0 inside the target process. */
        if (syms[k].st_shndx == SHN_UNDEF || syms[k].st_value == 0) {
            continue;
        }
        if (nm_off == 0 || nm_off >= str_size) {
            continue;
        }
        for (i = 0; i < n; i++) {
            if (addrs[i] != 0) {
                continue;
            }
            if (strcmp(str + nm_off, names[i]) == 0) {
                addrs[i] = libc_addr + (size_t)syms[k].st_value;
            }
        }
    }

    rv = 0;
cleanup:
    free(str);
    free(syms);
    if (fp != NULL) {
        fclose(fp);
    }
    return rv;
}

static int search_and_open_libc(FILE **fp_out, char *path_out, size_t path_out_sz, pid_t pid, size_t *addr, libc_type_t *libc_type)
{
    char buf[512];
    FILE *fp = NULL;
    regex_t reg;
    regmatch_t match;

    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        injector__set_errmsg("failed to open %s. (error: %s)", buf, strerror(errno));
        return INJERR_OTHER;
    }
    DEBUG("Open %s\n", buf);
    /* /libc.so.6 or /libc-2.{DIGITS}.so or /ld-musl-{arch}.so.1 */
    if (regcomp(&reg, "/libc(\\.so\\.6|-2\\.[0-9]+\\.so)|/ld-musl-.+?\\.so\\.1", REG_EXTENDED) != 0) {
        injector__set_errmsg("regcomp failed!");
        return INJERR_OTHER;
    }
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        unsigned long saddr, eaddr;
        unsigned long long offset, inode;
        unsigned int dev_major, dev_minor;
        DEBUG("   %s", buf);
        if (sscanf(buf, "%lx-%lx %*s %llx %x:%x %llu", &saddr, &eaddr, &offset, &dev_major, &dev_minor, &inode) != 6) {
            continue;
        }
        if (offset != 0) {
            continue;
        }
        if (regexec(&reg, buf, 1, &match, 0) != 0) {
            continue;
        }
        char *p = buf + match.rm_eo;
        if (strcmp(p, " (deleted)\n") == 0) {
            injector__set_errmsg("The C library when the process started was removed");
            fclose(fp);
            regfree(&reg);
            return INJERR_NO_LIBRARY;
        }
        if (strcmp(p, "\n") != 0) {
            continue;
        }
        fclose(fp);
        *addr = saddr;
        if (strstr(buf, "/ld-musl-") != NULL) {
            *libc_type = LIBC_TYPE_MUSL;
        } else {
            *libc_type = LIBC_TYPE_GNU;
        }
        regfree(&reg);
        *p = '\0';
        p = strchr(buf, '/');
        DEBUG(" libc in /proc/PID/maps: '%s'\n", p);
        return open_libc(fp_out, path_out, path_out_sz, p, pid, makedev(dev_major, dev_minor), inode);
    }
    fclose(fp);
    injector__set_errmsg("Could not find libc");
    regfree(&reg);
    return INJERR_NO_LIBRARY;
}

static int open_libc(FILE **fp_out, char *path_out, size_t path_out_sz, const char *path, pid_t pid, dev_t dev, ino_t ino)
{
    FILE *fp;

#define RECORD_WINNER(candidate) do { \
        if (path_out != NULL && path_out_sz > 0) { \
            strncpy(path_out, (candidate), path_out_sz - 1); \
            path_out[path_out_sz - 1] = '\0'; \
        } \
    } while (0)

    fp = fopen_with_ino(path, dev, ino);
    if (fp != NULL) {
        RECORD_WINNER(path);
        *fp_out = fp;
        return 0;
    }

    /* workaround for LXD */
    const char *p = strstr(path, "/rootfs/");
    if (p != NULL) {
        fp = fopen_with_ino(p + 7, dev, ino);
        if (fp != NULL) {
            RECORD_WINNER(p + 7);
            *fp_out = fp;
            return 0;
        }
    }

    // workaround for Flatpak (https://flatpak.org/)
    //
    // libc is under /proc/<PID>/root.
    // The idea came from https://github.com/kubo/injector/pull/36.
    {
        char buf[PATH_MAX];
        snprintf(buf, sizeof(buf), "/proc/%d/root%s", pid, path);
        buf[sizeof(buf) - 1] = '\0';
        fp = fopen_with_ino(buf, dev, ino);
        if (fp != NULL) {
            RECORD_WINNER(buf);
            *fp_out = fp;
            return 0;
        }
    }

    // workaround for Snap
    //
    // libc is in a base snap (https://snapcraft.io/docs/base-snaps),
    {
        glob_t globbuf;
        if (glob("/snap/core*/*", GLOB_NOSORT, NULL, &globbuf) == 0) {
            size_t idx;
            for (idx = 0; idx < globbuf.gl_pathc; idx++) {
                char buf[512];
                snprintf(buf, sizeof(buf), "%s%s", globbuf.gl_pathv[idx], path);
                buf[sizeof(buf) - 1] = '\0';
                fp = fopen_with_ino(buf, dev, ino);
                if (fp != NULL) {
                    RECORD_WINNER(buf);
                    globfree(&globbuf);
                    *fp_out = fp;
                    return 0;
                }
            }
            globfree(&globbuf);
        }
    }
#undef RECORD_WINNER
    /* dev_t/ino_t widths differ per ABI (on x32 ino_t is `unsigned long long`
     * while %lu expects `unsigned long`), so cast explicitly and use the
     * PRI*64 macros: this used to break the -Werror x32 build. */
    injector__set_errmsg("failed to open %s. (dev:0x%" PRIx64 ", ino:%" PRIu64 ")",
                         path, (uint64_t)dev, (uint64_t)ino);
    return INJERR_NO_LIBRARY;
}

static inline int is_on_overlay_fs(int fd)
{
    struct statfs sbuf;
    if (fstatfs(fd, &sbuf) != 0) {
        DEBUG(" fstatfs() error %s\n", strerror(errno));
        return -1;
    }
#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif
    return (sbuf.f_type == OVERLAYFS_SUPER_MAGIC) ? 1 : 0;
}

static FILE *fopen_with_ino(const char *path, dev_t dev, ino_t ino)
{
    DEBUG("   checking: '%s' ...", path);
    struct stat sbuf;
    FILE *fp = fopen(path, "r");

    if (fp == NULL) {
        DEBUG(" fopen() error %s\n", strerror(errno));
        return NULL;
    }

    if (fstat(fileno(fp), &sbuf) != 0) {
        DEBUG(" fstat() error %s\n", strerror(errno));
        goto cleanup;
    }
    if (sbuf.st_ino != ino) {
        DEBUG(" unexpected inode number: expected %llu but %llu\n",
              (unsigned long long)ino, (unsigned long long)sbuf.st_ino);
        goto cleanup;
    }
    if (sbuf.st_dev != dev) {
        int rv = is_on_overlay_fs(fileno(fp));
        if (rv < 0) {
            goto cleanup;
        }
        if (rv != 1) {
            DEBUG(" unexpected device number: expected %llu but %llu\n",
                  (unsigned long long)dev, (unsigned long long)sbuf.st_dev);
            goto cleanup;
        }
        DEBUG(" ignore device number mismatch (expected %llu but %llu) on overlay file system  ... ",
              (unsigned long long)dev, (unsigned long long)sbuf.st_dev);
    }

    DEBUG(" OK\n");
    return fp;
cleanup:
    fclose(fp);
    return NULL;
}

static int read_elf_ehdr(FILE *fp, Elf_Ehdr *ehdr)
{
    if (fread(ehdr, sizeof(*ehdr), 1, fp) != 1) {
        injector__set_errmsg("failed to read ELF header. (error: %s)", strerror(errno));
        return INJERR_INVALID_ELF_FORMAT;
    }
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        injector__set_errmsg("Invalid ELF header: 0x%02x,0x%02x,0x%02x,0x%02x",
                           ehdr->e_ident[0], ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
        return INJERR_INVALID_ELF_FORMAT;
    }
    switch (ehdr->e_ident[EI_CLASS]) {
    case ELFCLASS32:
#ifdef __LP64__
        {
            Elf32_Ehdr *ehdr32 = (Elf32_Ehdr *)ehdr;
            /* copy from last */
            ehdr->e_shstrndx = ehdr32->e_shstrndx;
            ehdr->e_shnum = ehdr32->e_shnum;
            ehdr->e_shentsize = ehdr32->e_shentsize;
            ehdr->e_phnum = ehdr32->e_phnum;
            ehdr->e_phentsize = ehdr32->e_phentsize;
            ehdr->e_ehsize = ehdr32->e_ehsize;
            ehdr->e_flags = ehdr32->e_flags;
            ehdr->e_shoff = ehdr32->e_shoff;
            ehdr->e_phoff = ehdr32->e_phoff;
            ehdr->e_entry = ehdr32->e_entry;
            ehdr->e_version = ehdr32->e_version;
            ehdr->e_machine = ehdr32->e_machine;
            ehdr->e_type = ehdr32->e_type;
        }
#endif
        break;
    case ELFCLASS64:
#ifndef __LP64__
        injector__set_errmsg("64-bit target process isn't supported by 32-bit process.");
        return INJERR_UNSUPPORTED_TARGET;
#endif
        break;
    default:
        injector__set_errmsg("Invalid ELF class: 0x%x", ehdr->e_ident[EI_CLASS]);
        return INJERR_UNSUPPORTED_TARGET;
    }
    return 0;
}

/* Return the size of the file behind `fp` without disturbing the read
 * position. Returns 0 on success, -1 when the size cannot be determined. */
static int elf_file_size(FILE *fp, uint64_t *size_out)
{
    struct stat sbuf;
    fpos_t pos;
    long sz;

    if (fstat(fileno(fp), &sbuf) == 0 && S_ISREG(sbuf.st_mode) && sbuf.st_size > 0) {
        *size_out = (uint64_t)sbuf.st_size;
        return 0;
    }
    /* Not a regular file (or an fstat-less stream such as fmemopen): ask the
     * stream itself. */
    if (fgetpos(fp, &pos) != 0 || fseek(fp, 0, SEEK_END) != 0) {
        return -1;
    }
    sz = ftell(fp);
    if (fsetpos(fp, &pos) != 0 || sz < 0) {
        return -1;
    }
    *size_out = (uint64_t)sz;
    return 0;
}

/* fseek() with a 64-bit, file-controlled offset. Returns 0 on success. */
static int elf_seek(FILE *fp, uint64_t offset)
{
    if (offset > (uint64_t)LONG_MAX) {
        return -1;
    }
    return fseek(fp, (long)offset, SEEK_SET);
}

/* True when [off, off+len) lies entirely inside a file of `fsize` bytes.
 * Written so that it cannot overflow for any input. */
static int elf_range_in_file(uint64_t off, uint64_t len, uint64_t fsize)
{
    if (off > fsize) {
        return 0;
    }
    if (len > fsize - off) {
        return 0;
    }
    return 1;
}

/* Validate every attacker-controlled ELF header field that is later used to
 * compute a file offset or a buffer size. Called exactly once, right after
 * read_elf_ehdr() and before any seek/read of section or program headers.
 * `fsize_out` (optional) receives the file size. */
static int validate_elf_layout(FILE *fp, const Elf_Ehdr *ehdr, uint64_t *fsize_out)
{
    uint64_t fsize;

    if (elf_file_size(fp, &fsize) != 0) {
        injector__set_errmsg("failed to get the size of the ELF file.");
        return INJERR_INVALID_ELF_FORMAT;
    }
    if (fsize_out != NULL) {
        *fsize_out = fsize;
    }
    if (fsize < sizeof(Elf_Ehdr)) {
        injector__set_errmsg("the file is too small to be an ELF file.");
        return INJERR_INVALID_ELF_FORMAT;
    }

    if (ehdr->e_shoff != 0 && ehdr->e_shnum != 0) {
        /* e_shentsize drives an fread() into a fixed-size Elf_Shdr: a value
         * outside [sizeof(Elf32_Shdr), sizeof(Elf_Shdr)] would smash it. */
        if ((size_t)ehdr->e_shentsize < ELF_SHDR_SIZE_MIN ||
            (size_t)ehdr->e_shentsize > ELF_SHDR_SIZE_MAX) {
            injector__set_errmsg("invalid section header entry size: %u",
                                 (unsigned int)ehdr->e_shentsize);
            return INJERR_INVALID_ELF_FORMAT;
        }
        if (ehdr->e_shstrndx >= ehdr->e_shnum) {
            injector__set_errmsg("invalid section header string table index: %u (e_shnum: %u)",
                                 (unsigned int)ehdr->e_shstrndx, (unsigned int)ehdr->e_shnum);
            return INJERR_INVALID_ELF_FORMAT;
        }
        /* All arithmetic in uint64_t: e_shnum and e_shentsize are uint16_t and
         * would overflow int when multiplied. */
        if (!elf_range_in_file((uint64_t)ehdr->e_shoff,
                               (uint64_t)ehdr->e_shnum * (uint64_t)ehdr->e_shentsize, fsize)) {
            injector__set_errmsg("the section header table is out of the file.");
            return INJERR_INVALID_ELF_FORMAT;
        }
    }

    if (ehdr->e_phoff != 0 && ehdr->e_phnum != 0) {
        if ((size_t)ehdr->e_phentsize < ELF_PHDR_SIZE_MIN ||
            (size_t)ehdr->e_phentsize > ELF_PHDR_SIZE_MAX) {
            injector__set_errmsg("invalid program header entry size: %u",
                                 (unsigned int)ehdr->e_phentsize);
            return INJERR_INVALID_ELF_FORMAT;
        }
        if (!elf_range_in_file((uint64_t)ehdr->e_phoff,
                               (uint64_t)ehdr->e_phnum * (uint64_t)ehdr->e_phentsize, fsize)) {
            injector__set_errmsg("the program header table is out of the file.");
            return INJERR_INVALID_ELF_FORMAT;
        }
    }
    return 0;
}

/* Exact full-name match of a section name in the section header string table.
 * The previous fgets(buf, 8)/strcmp() pair accepted any 7-character prefix, so
 * ".dynstrXXX" or ".dynsymx" were mistaken for the real sections.
 * Returns 1 on match, 0 on no match, -1 on an I/O error. */
static int section_name_is(FILE *fp, uint64_t strtab_off, uint64_t strtab_size,
                           uint64_t name_off, const char *want)
{
    char buf[16];
    size_t wantlen = strlen(want);
    fpos_t pos;
    int rv = 0;

    if (wantlen == 0 || wantlen >= sizeof(buf)) {
        return 0;
    }
    /* The name and its terminating NUL must lie inside the string table. */
    if (name_off >= strtab_size || wantlen + 1 > strtab_size - name_off) {
        return 0;
    }
    if (fgetpos(fp, &pos) != 0) {
        return -1;
    }
    if (elf_seek(fp, strtab_off + name_off) != 0) {
        rv = (fsetpos(fp, &pos) == 0) ? 0 : -1;
        return rv;
    }
    if (fread(buf, 1, wantlen, fp) == wantlen && memcmp(buf, want, wantlen) == 0) {
        if (fgetc(fp) == '\0') {
            rv = 1;
        }
    }
    if (fsetpos(fp, &pos) != 0) {
        return -1;
    }
    return rv;
}

static int read_elf_shdr(FILE *fp, Elf_Shdr *shdr, size_t shdr_size)
{
    /* shdr_size is the file's e_shentsize. It must fit into the caller's
     * fixed-size buffer, otherwise fread() smashes the stack or the heap. */
    if (shdr_size < ELF_SHDR_SIZE_MIN || shdr_size > sizeof(*shdr)) {
        injector__set_errmsg("invalid section header entry size: %lu", (unsigned long)shdr_size);
        return INJERR_INVALID_ELF_FORMAT;
    }
    memset(shdr, 0, sizeof(*shdr));
    if (fread(shdr, shdr_size, 1, fp) != 1) {
        injector__set_errmsg("failed to read a section header. (error: %s)", strerror(errno));
        return INJERR_INVALID_ELF_FORMAT;
    }
#ifdef __LP64__
    if (shdr_size == sizeof(Elf32_Shdr)) {
        Elf32_Shdr shdr32 = *(Elf32_Shdr *)shdr;
        shdr->sh_name = shdr32.sh_name;
        shdr->sh_type = shdr32.sh_type;
        shdr->sh_flags = shdr32.sh_flags;
        shdr->sh_addr = shdr32.sh_addr;
        shdr->sh_offset = shdr32.sh_offset;
        shdr->sh_size = shdr32.sh_size;
        shdr->sh_link = shdr32.sh_link;
        shdr->sh_info = shdr32.sh_info;
        shdr->sh_addralign = shdr32.sh_addralign;
        shdr->sh_entsize = shdr32.sh_entsize;
    }
#endif
    return 0;
}

static int read_elf_sym(FILE *fp, Elf_Sym *sym, size_t sym_size)
{
    /* sym_size is the file's .dynsym sh_entsize: bound it by the caller's
     * fixed-size Elf_Sym buffer before reading. */
    if (sym_size < ELF_SYM_SIZE_MIN || sym_size > sizeof(*sym)) {
        injector__set_errmsg("invalid symbol table entry size: %lu", (unsigned long)sym_size);
        return INJERR_INVALID_ELF_FORMAT;
    }
    memset(sym, 0, sizeof(*sym));
    if (fread(sym, sym_size, 1, fp) != 1) {
        injector__set_errmsg("failed to read a symbol table entry. (error: %s)", strerror(errno));
        return INJERR_INVALID_ELF_FORMAT;
    }
#ifdef __LP64__
    if (sym_size == sizeof(Elf32_Sym)) {
        Elf32_Sym sym32 = *(Elf32_Sym *)sym;
        sym->st_name = sym32.st_name;
        sym->st_value = sym32.st_value;
        sym->st_size = sym32.st_size;
        sym->st_info = sym32.st_info;
        sym->st_other = sym32.st_other;
        sym->st_shndx = sym32.st_shndx;
    }
#endif
    return 0;
}

static int read_elf_phdr(FILE *fp, Elf_Phdr *phdr, size_t phdr_size)
{
    if (phdr_size < ELF_PHDR_SIZE_MIN || phdr_size > sizeof(*phdr)) {
        injector__set_errmsg("invalid program header entry size: %lu", (unsigned long)phdr_size);
        return INJERR_INVALID_ELF_FORMAT;
    }
    memset(phdr, 0, sizeof(*phdr));
    if (fread(phdr, phdr_size, 1, fp) != 1) {
        injector__set_errmsg("failed to read a program header. (error: %s)", strerror(errno));
        return INJERR_INVALID_ELF_FORMAT;
    }
#ifdef __LP64__
    if (phdr_size == sizeof(Elf32_Phdr)) {
        Elf32_Phdr phdr32 = *(Elf32_Phdr *)phdr;
        phdr->p_type = phdr32.p_type;
        phdr->p_offset = phdr32.p_offset;
        phdr->p_vaddr = phdr32.p_vaddr;
        phdr->p_paddr = phdr32.p_paddr;
        phdr->p_filesz = phdr32.p_filesz;
        phdr->p_memsz = phdr32.p_memsz;
        phdr->p_flags = phdr32.p_flags;
        phdr->p_align = phdr32.p_align;
    }
#endif
    return 0;
}

/* Locate the .dynstr and .dynsym section offsets/sizes by scanning the
 * section header table. Mirrors the logic that used to live inline in
 * injector__collect_libc_information. */
static int locate_dynsym(FILE *fp, const Elf_Ehdr *ehdr, uint64_t fsize, size_t *str_off, size_t *str_sz, size_t *sym_off, size_t *sym_num, size_t *sym_entsize)
{
    Elf_Shdr shdr;
    uint64_t shstrtab_offset;
    uint64_t shstrtab_size;
    uint64_t shstrtab_hdr_off;
    uint32_t idx;
    int rv;

    *str_off = *str_sz = *sym_off = *sym_num = *sym_entsize = 0;

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shentsize == 0) {
        injector__set_errmsg("failed to find the .dynstr and .dynsym sections.");
        return INJERR_INVALID_ELF_FORMAT;
    }

    /* Everything below is uint64_t arithmetic on purpose: e_shstrndx and
     * e_shentsize are uint16_t, so `e_shstrndx * e_shentsize` used to be
     * computed in `int` and overflowed (65535 * 65535). */
    shstrtab_hdr_off = (uint64_t)ehdr->e_shoff + (uint64_t)ehdr->e_shstrndx * (uint64_t)ehdr->e_shentsize;
    if (!elf_range_in_file(shstrtab_hdr_off, (uint64_t)ehdr->e_shentsize, fsize)) {
        injector__set_errmsg("the section header string table is out of the file.");
        return INJERR_INVALID_ELF_FORMAT;
    }
    if (elf_seek(fp, shstrtab_hdr_off) != 0) {
        injector__set_errmsg("failed to seek the section header string table.");
        return INJERR_INVALID_ELF_FORMAT;
    }
    rv = read_elf_shdr(fp, &shdr, (size_t)ehdr->e_shentsize);
    if (rv != 0) {
        return rv;
    }
    shstrtab_offset = (uint64_t)shdr.sh_offset;
    shstrtab_size = (uint64_t)shdr.sh_size;
    if (!elf_range_in_file(shstrtab_offset, shstrtab_size, fsize)) {
        injector__set_errmsg("the section header string table is out of the file.");
        return INJERR_INVALID_ELF_FORMAT;
    }

    if (elf_seek(fp, (uint64_t)ehdr->e_shoff) != 0) {
        injector__set_errmsg("failed to seek the section header table.");
        return INJERR_INVALID_ELF_FORMAT;
    }
    for (idx = 0; idx < (uint32_t)ehdr->e_shnum; idx++) {
        int matched;

        rv = read_elf_shdr(fp, &shdr, (size_t)ehdr->e_shentsize);
        if (rv != 0) {
            return rv;
        }
        switch (shdr.sh_type) {
        case SHT_STRTAB:
            matched = section_name_is(fp, shstrtab_offset, shstrtab_size,
                                      (uint64_t)shdr.sh_name, ".dynstr");
            if (matched < 0) {
                injector__set_errmsg("failed to read a section name.");
                return INJERR_INVALID_ELF_FORMAT;
            }
            if (matched == 1 &&
                elf_range_in_file((uint64_t)shdr.sh_offset, (uint64_t)shdr.sh_size, fsize) &&
                elf_u64_fits_size_t((uint64_t)shdr.sh_size)) {
                *str_off = (size_t)shdr.sh_offset;
                *str_sz = (size_t)shdr.sh_size;
            }
            break;
        case SHT_DYNSYM:
            matched = section_name_is(fp, shstrtab_offset, shstrtab_size,
                                      (uint64_t)shdr.sh_name, ".dynsym");
            if (matched < 0) {
                injector__set_errmsg("failed to read a section name.");
                return INJERR_INVALID_ELF_FORMAT;
            }
            if (matched == 1 &&
                elf_range_in_file((uint64_t)shdr.sh_offset, (uint64_t)shdr.sh_size, fsize)) {
                uint64_t entsize = (uint64_t)shdr.sh_entsize;
                /* Reject sh_entsize == 0 (and any other out-of-range value)
                 * BEFORE dividing by it: the old code raised SIGFPE here, and
                 * read_elf_sym() would have overflowed its Elf_Sym buffer. */
                if (entsize < (uint64_t)ELF_SYM_SIZE_MIN || entsize > (uint64_t)ELF_SYM_SIZE_MAX) {
                    injector__set_errmsg("invalid .dynsym entry size: %" PRIu64, entsize);
                    return INJERR_INVALID_ELF_FORMAT;
                }
                if (!elf_u64_fits_size_t((uint64_t)shdr.sh_offset) ||
                    !elf_u64_fits_size_t(shdr.sh_size / entsize)) {
                    injector__set_errmsg("the .dynsym section is too large.");
                    return INJERR_INVALID_ELF_FORMAT;
                }
                *sym_off = (size_t)shdr.sh_offset;
                *sym_entsize = (size_t)entsize;
                *sym_num = (size_t)(shdr.sh_size / entsize);
            }
            break;
        }
        if (*sym_off != 0 && *str_off != 0) {
            break;
        }
    }
    if (idx == (uint32_t)ehdr->e_shnum) {
        injector__set_errmsg("failed to find the .dynstr and .dynsym sections.");
        return INJERR_INVALID_ELF_FORMAT;
    }
    return 0;
}

/* Exposed small helper: open `path` and return its ELF e_machine. Used by the
 * non-intrusive target_info path to derive the target architecture without
 * attaching. Returns 0 on success (machine_out set), an INJERR_* code on
 * failure. */
int injector__read_elf_machine(const char *path, int *machine_out)
{
    FILE *fp;
    Elf_Ehdr ehdr;
    int rv;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        injector__set_errmsg("failed to open %s. (error: %s)", path, strerror(errno));
        return INJERR_FILE_NOT_FOUND;
    }
    rv = read_elf_ehdr(fp, &ehdr);
    fclose(fp);
    if (rv != 0) {
        return rv;
    }
    *machine_out = ehdr.e_machine;
    return 0;
}

int injector__elf_load_bias(const char *path, size_t map_start, size_t *bias_out)
{
    FILE *fp;
    Elf_Ehdr ehdr;
    size_t bias = 0;
    int rv;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        injector__set_errmsg("failed to open %s. (error: %s)", path, strerror(errno));
        return INJERR_FILE_NOT_FOUND;
    }
    rv = read_elf_ehdr(fp, &ehdr);
    if (rv != 0) {
        fclose(fp);
        return rv;
    }
    /* ET_EXEC: symbol values are absolute virtual addresses; the mapping is
     * already at the ELF link base, so no bias is added.
     * ET_DYN (PIE executable or shared object): symbol values are relative to
     * the link base of the first PT_LOAD segment, whose p_vaddr is 0 in
     * practice but is not guaranteed to be, so bias = map_start - p_vaddr.
     * Any failure to read the program headers keeps the historical fallback
     * (bias = map_start) instead of failing the whole attach. */
    if (ehdr.e_type == ET_DYN) {
        uint64_t fsize = 0;
        bias = map_start;
        if (ehdr.e_phoff != 0 && ehdr.e_phnum != 0 &&
            (size_t)ehdr.e_phentsize >= ELF_PHDR_SIZE_MIN &&
            (size_t)ehdr.e_phentsize <= ELF_PHDR_SIZE_MAX &&
            elf_file_size(fp, &fsize) == 0 &&
            elf_range_in_file((uint64_t)ehdr.e_phoff,
                              (uint64_t)ehdr.e_phnum * (uint64_t)ehdr.e_phentsize, fsize) &&
            elf_seek(fp, (uint64_t)ehdr.e_phoff) == 0) {
            uint16_t i;
            for (i = 0; i < ehdr.e_phnum; i++) {
                Elf_Phdr phdr;
                if (read_elf_phdr(fp, &phdr, (size_t)ehdr.e_phentsize) != 0) {
                    break;
                }
                if (phdr.p_type != PT_LOAD) {
                    continue;
                }
                if ((uint64_t)phdr.p_vaddr <= (uint64_t)map_start) {
                    bias = map_start - (size_t)phdr.p_vaddr;
                }
                break;
            }
        }
    }
    fclose(fp);
    *bias_out = bias;
    return 0;
}