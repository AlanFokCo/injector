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
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#endif

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
static int locate_dynsym(FILE *fp, const Elf_Ehdr *ehdr, size_t *str_off, size_t *str_sz, size_t *sym_off, size_t *sym_num, size_t *sym_entsize);

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

    injector->code_addr = libc_addr + ehdr.e_entry;

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

    rv = locate_dynsym(fp, &ehdr, &str_offset, &str_size, &sym_offset, &sym_num, &sym_entsize);
    if (rv != 0) {
        goto cleanup;
    }

    if (str_offset == 0 || str_size == 0 || sym_offset == 0 || sym_entsize == 0) {
        injector__set_errmsg("failed to find the .dynstr and .dynsym sections.");
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }

    /* Read .dynstr into a heap buffer once. */
    str = malloc(str_size);
    if (str == NULL) {
        rv = INJERR_NO_MEMORY;
        goto cleanup;
    }
    if (fseek(fp, str_offset, SEEK_SET) != 0 ||
        fread(str, 1, str_size, fp) != str_size) {
        injector__set_errmsg("failed to read .dynstr.");
        rv = INJERR_INVALID_ELF_FORMAT;
        goto cleanup;
    }

    /* Read .dynsym into a heap buffer of Elf_Sym (read_elf_sym handles 32->64
     * conversion on LP64). */
    syms = malloc(sym_num * sizeof(Elf_Sym));
    if (syms == NULL) {
        rv = INJERR_NO_MEMORY;
        goto cleanup;
    }
    if (fseek(fp, sym_offset, SEEK_SET) != 0) {
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
        size_t nm_off = syms[k].st_name;
        if (nm_off == 0 || nm_off >= str_size) {
            continue;
        }
        for (i = 0; i < n; i++) {
            if (addrs[i] != 0) {
                continue;
            }
            if (strcmp(str + nm_off, names[i]) == 0) {
                addrs[i] = libc_addr + syms[k].st_value;
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
    injector__set_errmsg("failed to open %s. (dev:0x%" PRIx64 ", ino:%lu)", path, dev, ino);
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

static int read_elf_shdr(FILE *fp, Elf_Shdr *shdr, size_t shdr_size)
{
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

/* Locate the .dynstr and .dynsym section offsets/sizes by scanning the
 * section header table. Mirrors the logic that used to live inline in
 * injector__collect_libc_information. */
static int locate_dynsym(FILE *fp, const Elf_Ehdr *ehdr, size_t *str_off, size_t *str_sz, size_t *sym_off, size_t *sym_num, size_t *sym_entsize)
{
    Elf_Shdr shdr;
    size_t shstrtab_offset;
    int idx;
    int rv;

    *str_off = *str_sz = *sym_off = *sym_num = *sym_entsize = 0;

    if (fseek(fp, ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize, SEEK_SET) != 0) {
        injector__set_errmsg("failed to seek the section header string table.");
        return INJERR_INVALID_ELF_FORMAT;
    }
    rv = read_elf_shdr(fp, &shdr, ehdr->e_shentsize);
    if (rv != 0) {
        return rv;
    }
    shstrtab_offset = shdr.sh_offset;

    if (fseek(fp, ehdr->e_shoff, SEEK_SET) != 0) {
        injector__set_errmsg("failed to seek the section header table.");
        return INJERR_INVALID_ELF_FORMAT;
    }
    for (idx = 0; idx < ehdr->e_shnum; idx++) {
        fpos_t pos;
        char buf[8];

        rv = read_elf_shdr(fp, &shdr, ehdr->e_shentsize);
        if (rv != 0) {
            return rv;
        }
        switch (shdr.sh_type) {
        case SHT_STRTAB:
            fgetpos(fp, &pos);
            fseek(fp, shstrtab_offset + shdr.sh_name, SEEK_SET);
            fgets(buf, sizeof(buf), fp);
            fsetpos(fp, &pos);
            if (strcmp(buf, ".dynstr") == 0) {
                *str_off = shdr.sh_offset;
                *str_sz = shdr.sh_size;
            }
            break;
        case SHT_DYNSYM:
            fgetpos(fp, &pos);
            fseek(fp, shstrtab_offset + shdr.sh_name, SEEK_SET);
            fgets(buf, sizeof(buf), fp);
            fsetpos(fp, &pos);
            if (strcmp(buf, ".dynsym") == 0) {
                *sym_off = shdr.sh_offset;
                *sym_entsize = shdr.sh_entsize;
                *sym_num = shdr.sh_size / shdr.sh_entsize;
            }
            break;
        }
        if (*sym_off != 0 && *str_off != 0) {
            break;
        }
    }
    if (idx == ehdr->e_shnum) {
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
    /* ET_EXEC: symbol values are absolute virtual addresses; the mapping is
     * already at the ELF link base, so no bias is added.
     * ET_DYN (PIE executable or shared object): symbol values are relative to
     * the first PT_LOAD (p_vaddr 0 in practice), so bias = mapping start. */
    if (ehdr.e_type == ET_DYN) {
        *bias_out = map_start;
    } else {
        *bias_out = 0;
    }
    return 0;
}