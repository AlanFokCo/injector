/* test_elf.c - unit tests for injector__elf_find_symbols (src/linux/elf.c).
 *
 * The hostile-ELF tests below synthesise little-endian ELF64 ET_DYN images
 * entirely in memory (no external tools) and write them to
 * /tmp/inj_elf_t_<pid>_<n>.elf, so they never depend on the host toolchain.
 * Every temporary file is unlinked on all paths.
 */
#include "minunit.h"
#include "injector.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <elf.h>
#include <dlfcn.h>

/* Defined in run.c and reported in its summary line. Declared here rather than
 * in minunit.h so that the skip count stays local to this suite. */
extern int tests_skipped;

/* Internal helper exposed for testing (declared in src/linux/injector_internal.h). */
int injector__elf_find_symbols(const char *path, size_t libc_addr,
                               const char *const names[], size_t addrs[], size_t n);

/* run.c registers exactly one ELF entry point, so the sub-tests are driven
 * from it through this local runner. It mirrors MU_RUN_TEST and adds a third
 * outcome: returning -1 means "deliberately skipped", which is counted and
 * printed instead of passing for free. A setup failure that used to `return 0`
 * was a lie - CI stayed green with zero coverage. */
#define RUN_ELF_SUB(t) do { int mu_rv_ = t(); tests_run++; \
    if (mu_rv_ < 0) { tests_skipped++; fprintf(stderr, "  skip: %s\n", #t); } \
    else if (mu_rv_ != 0) { tests_failed++; fprintf(stderr, "  FAIL: %s\n", #t); } \
    else fprintf(stderr, "  ok:   %s\n", #t); } while (0)

/* Skipping a sub-test is opt-in per run: without INJECTOR_ALLOW_SKIP=1 a
 * missing toolchain or an unwritable /tmp is a hard failure, so it can never
 * quietly turn a positive-path test into a no-op. */
static int elf_allow_skip(void)
{
    const char *v = getenv("INJECTOR_ALLOW_SKIP");
    return v != NULL && strcmp(v, "1") == 0;
}

#define ELF_SYM_VALUE  0x1234u
#define ELF_LIBC_BASE  ((size_t)0x7f0000000000u)
#define ELF_PATHSZ     128
#define ELF_IMGSZ      1024
#define ELF_NSECT      4u

static unsigned long elf_tmp_counter;

typedef struct {
    uint16_t e_shentsize;      /* ehdr.e_shentsize                     */
    uint16_t e_shnum;          /* ehdr.e_shnum                         */
    uint16_t e_shstrndx;       /* ehdr.e_shstrndx                      */
    uint64_t dynsym_sh_size;   /* .dynsym sh_size (verbatim)           */
    uint64_t dynsym_sh_entsize;/* .dynsym sh_entsize (verbatim)        */
    const char *strtab_name;   /* name of the string table section     */
    const char *dynsym_name;   /* name of the symbol table section     */
    int dynstr_no_nul;         /* omit the trailing NUL of .dynstr     */
} elf_opts_t;

static void elf_opts_default(elf_opts_t *o)
{
    memset(o, 0, sizeof(*o));
    o->e_shentsize = (uint16_t)sizeof(Elf64_Shdr);
    o->e_shnum = (uint16_t)ELF_NSECT;
    o->e_shstrndx = 1;
    o->dynsym_sh_size = 3u * (uint64_t)sizeof(Elf64_Sym);
    o->dynsym_sh_entsize = (uint64_t)sizeof(Elf64_Sym);
    o->strtab_name = ".dynstr";
    o->dynsym_name = ".dynsym";
    o->dynstr_no_nul = 0;
}

/* Append "s\0" to dst at offset len; return the new length (unchanged on overflow). */
static size_t elf_put_str(char *dst, size_t cap, size_t len, const char *s)
{
    size_t n = strlen(s);
    if (len + n + 1 > cap) {
        return len;
    }
    memcpy(dst + len, s, n);
    dst[len + n] = '\0';
    return len + n + 1;
}

/* Build a self-consistent ELF64 ET_DYN image: ehdr, .shstrtab, .dynstr,
 * .dynsym (NULL + defined "dlopen" + UNDEF "free"), section header table.
 * Returns the image size, or 0 if the buffer is too small. */
static size_t elf_build(const elf_opts_t *o, unsigned char *buf, size_t bufsz)
{
    char shstr[128];
    char dynstr[64];
    Elf64_Ehdr eh;
    Elf64_Shdr sh[ELF_NSECT];
    Elf64_Sym sym[3];
    size_t shstr_len, dynstr_len;
    size_t off_shstrtab_name, off_strtab_name, off_dynsym_name;
    size_t off_dlopen, off_free;
    size_t shstrtab_at, dynstr_at, dynsym_at, shdr_at, total;

    if (bufsz < ELF_IMGSZ) {
        return 0;
    }

    /* .shstrtab: "\0.shstrtab\0<strtab_name>\0<dynsym_name>\0" */
    memset(shstr, 0, sizeof(shstr));
    shstr_len = 1; /* leading NUL at offset 0 */
    off_shstrtab_name = shstr_len;
    shstr_len = elf_put_str(shstr, sizeof(shstr), shstr_len, ".shstrtab");
    off_strtab_name = shstr_len;
    shstr_len = elf_put_str(shstr, sizeof(shstr), shstr_len, o->strtab_name);
    off_dynsym_name = shstr_len;
    shstr_len = elf_put_str(shstr, sizeof(shstr), shstr_len, o->dynsym_name);
    if (shstr_len == off_dynsym_name && o->dynsym_name[0] != '\0') {
        return 0; /* overflowed */
    }

    /* .dynstr: "\0free\0dlopen" [+ "\0" unless the no-NUL variant] */
    memset(dynstr, 0, sizeof(dynstr));
    dynstr_len = 1;
    off_free = dynstr_len;
    memcpy(dynstr + dynstr_len, "free\0", 5);
    dynstr_len += 5;
    off_dlopen = dynstr_len;
    memcpy(dynstr + dynstr_len, "dlopen", 6);
    dynstr_len += 6;
    if (!o->dynstr_no_nul) {
        dynstr[dynstr_len++] = '\0';
    }

    shstrtab_at = sizeof(Elf64_Ehdr);
    dynstr_at = shstrtab_at + shstr_len;
    dynsym_at = dynstr_at + dynstr_len;
    shdr_at = dynsym_at + sizeof(sym);
    total = shdr_at + sizeof(sh);
    if (total > bufsz) {
        return 0;
    }

    memset(sh, 0, sizeof(sh));
    /* sh[0]: SHN_UNDEF / NULL section */
    /* sh[1]: .shstrtab (also the section referenced by the defined symbol) */
    sh[1].sh_name = (Elf64_Word)off_shstrtab_name;
    sh[1].sh_type = SHT_STRTAB;
    sh[1].sh_flags = SHF_ALLOC;
    sh[1].sh_addr = 0;
    sh[1].sh_offset = (Elf64_Off)shstrtab_at;
    sh[1].sh_size = (Elf64_Xword)shstr_len;
    sh[1].sh_addralign = 1;
    /* sh[2]: .dynstr */
    sh[2].sh_name = (Elf64_Word)off_strtab_name;
    sh[2].sh_type = SHT_STRTAB;
    sh[2].sh_flags = SHF_ALLOC;
    sh[2].sh_addr = 0;
    sh[2].sh_offset = (Elf64_Off)dynstr_at;
    sh[2].sh_size = (Elf64_Xword)dynstr_len;
    sh[2].sh_addralign = 1;
    /* sh[3]: .dynsym */
    sh[3].sh_name = (Elf64_Word)off_dynsym_name;
    sh[3].sh_type = SHT_DYNSYM;
    sh[3].sh_flags = SHF_ALLOC;
    sh[3].sh_addr = 0;
    sh[3].sh_offset = (Elf64_Off)dynsym_at;
    sh[3].sh_size = (Elf64_Xword)o->dynsym_sh_size;
    sh[3].sh_link = 2; /* .dynstr */
    sh[3].sh_info = 1; /* first non-local symbol */
    sh[3].sh_addralign = 8;
    sh[3].sh_entsize = (Elf64_Xword)o->dynsym_sh_entsize;

    memset(sym, 0, sizeof(sym));
    /* sym[0]: null symbol */
    /* sym[1]: "dlopen", defined, st_value = 0x1234 */
    sym[1].st_name = (Elf64_Word)off_dlopen;
    sym[1].st_info = (unsigned char)ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym[1].st_other = (unsigned char)STV_DEFAULT;
    sym[1].st_shndx = (Elf64_Half)1;
    sym[1].st_value = (Elf64_Addr)ELF_SYM_VALUE;
    sym[1].st_size = 16;
    /* sym[2]: "free", UNDEFINED - must never be reported as found */
    sym[2].st_name = (Elf64_Word)off_free;
    sym[2].st_info = (unsigned char)ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym[2].st_other = (unsigned char)STV_DEFAULT;
    sym[2].st_shndx = (Elf64_Half)SHN_UNDEF;
    sym[2].st_value = 0;
    sym[2].st_size = 0;

    memset(&eh, 0, sizeof(eh));
    eh.e_ident[EI_MAG0] = ELFMAG0;
    eh.e_ident[EI_MAG1] = ELFMAG1;
    eh.e_ident[EI_MAG2] = ELFMAG2;
    eh.e_ident[EI_MAG3] = ELFMAG3;
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB; /* little-endian */
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    eh.e_type = ET_DYN;
    eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_entry = 0;
    eh.e_phoff = 0;
    eh.e_shoff = (Elf64_Off)shdr_at;
    eh.e_flags = 0;
    eh.e_ehsize = (Elf64_Half)sizeof(Elf64_Ehdr);
    eh.e_phentsize = 0;
    eh.e_phnum = 0;
    eh.e_shentsize = o->e_shentsize;
    eh.e_shnum = o->e_shnum;
    eh.e_shstrndx = o->e_shstrndx;

    memset(buf, 0, total);
    memcpy(buf, &eh, sizeof(eh));
    memcpy(buf + shstrtab_at, shstr, shstr_len);
    memcpy(buf + dynstr_at, dynstr, dynstr_len);
    memcpy(buf + dynsym_at, sym, sizeof(sym));
    memcpy(buf + shdr_at, sh, sizeof(sh));
    return total;
}

static int elf_write_file(const char *path, const void *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    if (len != 0 && fwrite(buf, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        return -1;
    }
    return 0;
}

/* Write a synthesised image to a fresh /tmp/inj_elf_t_<pid>_<n>.elf path. */
static int elf_build_to_file(const elf_opts_t *o, char *path, size_t pathsz)
{
    unsigned char img[ELF_IMGSZ];
    size_t n;

    snprintf(path, pathsz, "/tmp/inj_elf_t_%ld_%lu.elf",
             (long)getpid(), elf_tmp_counter++);
    n = elf_build(o, img, sizeof(img));
    if (n == 0) {
        return -1;
    }
    if (elf_write_file(path, img, n) != 0) {
        unlink(path);
        return -1;
    }
    return 0;
}

/* --- sub-tests --------------------------------------------------------- */

/* Real toolchain-built .so: the pre-existing positive path must keep working. */
static int t_real_so_resolves(void)
{
    const char *src =
        "int my_sym_one(void) { return 1; }\n"
        "int my_sym_two(void) { return 2; }\n";
    char srcpath[ELF_PATHSZ];
    char sopath[ELF_PATHSZ];
    char cmd[2 * ELF_PATHSZ + 64];
    const char *names[] = { "my_sym_one", "my_sym_two", "does_not_exist" };
    size_t addrs[3] = {0};
    void *h;
    int rc = 1;
    int build_rc;

    snprintf(srcpath, sizeof(srcpath), "/tmp/inj_elf_src_%ld.c", (long)getpid());
    snprintf(sopath, sizeof(sopath), "/tmp/inj_elf_fixture_%ld.so", (long)getpid());

    FILE *f = fopen(srcpath, "w");
    if (f == NULL) {
        fprintf(stderr, "    cannot stage fixture %s: %s\n", srcpath, strerror(errno));
        if (!elf_allow_skip()) {
            fprintf(stderr,
                    "    (set INJECTOR_ALLOW_SKIP=1 to downgrade this to a counted skip)\n");
            return 1;
        }
        return -1;                      /* counted, visible skip */
    }
    if (fputs(src, f) == EOF || fclose(f) != 0) {
        unlink(srcpath);
        return 1;
    }
    snprintf(cmd, sizeof(cmd), "cc -shared -fPIC -o %s %s", sopath, srcpath);
    build_rc = system(cmd);
    if (build_rc != 0) {
        unlink(srcpath);
        fprintf(stderr, "    fixture build failed (rc=%d): %s\n", build_rc, cmd);
        if (!elf_allow_skip()) {
            fprintf(stderr,
                    "    (set INJECTOR_ALLOW_SKIP=1 to downgrade this to a counted skip)\n");
            return 1;
        }
        return -1;                      /* counted, visible skip */
    }

    if (injector__elf_find_symbols(sopath, 0, names, addrs, 3) != 0) {
        fprintf(stderr, "    resolver failed on a real .so\n");
        goto done;
    }
    if (addrs[0] == 0 || addrs[1] == 0 || addrs[2] != 0) {
        fprintf(stderr, "    addrs: %zx %zx %zx (want non-zero, non-zero, 0)\n",
                addrs[0], addrs[1], addrs[2]);
        goto done;
    }

    /* Sanity-check the fixture via dlopen. Addresses are not compared: with
     * libc_addr=0 the resolver returns st_value, dlsym returns the runtime
     * load address. */
    h = dlopen(sopath, RTLD_LAZY | RTLD_LOCAL);
    if (h == NULL) {
        fprintf(stderr, "    dlopen(%s) failed\n", sopath);
        goto done;
    }
    {
        int (*p1)(void) = (int (*)(void))(uintptr_t)dlsym(h, "my_sym_one");
        int (*p2)(void) = (int (*)(void))(uintptr_t)dlsym(h, "my_sym_two");
        if (p1 == NULL || p2 == NULL || p1() != 1 || p2() != 2) {
            fprintf(stderr, "    dlsym/call of the fixture symbols failed\n");
            dlclose(h);
            goto done;
        }
    }
    dlclose(h);
    rc = 0;

done:
    unlink(srcpath);
    unlink(sopath);
    return rc;
}

/* 1. ehdr.e_shentsize larger than the file -> non-zero, no crash. */
static int t_shentsize_too_large(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen" };
    size_t addrs[1] = {0};
    int rv;

    elf_opts_default(&o);
    o.e_shentsize = 0x1000;
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (e_shentsize=0x1000 rv=%d)\n", rv);
    MU_ASSERT(rv != 0);
    return 0;
}

/* 2. .dynsym sh_entsize == 0 -> non-zero and, critically, no SIGFPE
 *    (a divide-by-entsize would kill the process outright). */
static int t_dynsym_entsize_zero(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen" };
    size_t addrs[1] = {0};
    int rv;

    elf_opts_default(&o);
    o.dynsym_sh_entsize = 0;
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (sh_entsize=0 survived, rv=%d)\n", rv);
    MU_ASSERT(rv != 0);
    return 0;
}

/* 3. Truncated / garbage / missing inputs -> non-zero, no crash. */
static int t_truncated_and_garbage(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen" };
    size_t addrs[1] = {0};
    unsigned char img[ELF_IMGSZ];
    unsigned char cut[128];
    size_t n;
    int rv;

    elf_opts_default(&o);

    /* (a) only the 4-byte ELF magic */
    snprintf(path, sizeof(path), "/tmp/inj_elf_t_%ld_%lu.elf",
             (long)getpid(), elf_tmp_counter++);
    MU_ASSERT(elf_write_file(path, ELFMAG, SELFMAG) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    MU_ASSERT(rv != 0);

    /* (b) 64-byte header + garbage tail (e_shoff points past EOF) */
    n = elf_build(&o, img, sizeof(img));
    MU_ASSERT(n >= sizeof(cut));
    memcpy(cut, img, sizeof(cut));
    memset(cut + sizeof(Elf64_Ehdr), 0xA5, sizeof(cut) - sizeof(Elf64_Ehdr));
    snprintf(path, sizeof(path), "/tmp/inj_elf_t_%ld_%lu.elf",
             (long)getpid(), elf_tmp_counter++);
    MU_ASSERT(elf_write_file(path, cut, sizeof(cut)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    MU_ASSERT(rv != 0);

    /* (c) three arbitrary bytes */
    snprintf(path, sizeof(path), "/tmp/inj_elf_t_%ld_%lu.elf",
             (long)getpid(), elf_tmp_counter++);
    MU_ASSERT(elf_write_file(path, "\x01\x02\x03", 3) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    MU_ASSERT(rv != 0);

    /* (d) empty file */
    snprintf(path, sizeof(path), "/tmp/inj_elf_t_%ld_%lu.elf",
             (long)getpid(), elf_tmp_counter++);
    MU_ASSERT(elf_write_file(path, NULL, 0) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    MU_ASSERT(rv != 0);

    /* (e) nonexistent path */
    snprintf(path, sizeof(path), "/tmp/inj_elf_t_%ld_%lu.elf",
             (long)getpid(), elf_tmp_counter++);
    unlink(path);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    MU_ASSERT(rv != 0);
    return 0;
}

/* 4. .dynstr with no trailing NUL: "dlopen" is the last byte-run, so a
 *    parser that strcmp()s past sh_size over-reads. Must still resolve. */
static int t_dynstr_no_trailing_nul(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen" };
    size_t addrs[1] = {0};
    int rv;

    elf_opts_default(&o);
    o.dynstr_no_nul = 1;
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (no-NUL dynstr rv=%d addr=%zx)\n", rv, addrs[0]);
    MU_ASSERT(rv == 0);
    MU_ASSERT(addrs[0] == ELF_LIBC_BASE + ELF_SYM_VALUE);
    return 0;
}

/* 5. SHN_UNDEF symbols must not be reported as found. */
static int t_undef_symbol_skipped(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen", "free" };
    size_t addrs[2] = {0, 0};
    int rv;

    elf_opts_default(&o);
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 2);
    unlink(path);
    fprintf(stderr, "    (rv=%d dlopen=%zx free=%zx)\n", rv, addrs[0], addrs[1]);
    MU_ASSERT(rv == 0);
    MU_ASSERT(addrs[0] == ELF_LIBC_BASE + ELF_SYM_VALUE);
    MU_ASSERT(addrs[1] == 0);
    return 0;
}

/* 6. Section names must match exactly: ".dynsymx"/".dynstrXXX" are rejected,
 *    ".dynsym"/".dynstr" are accepted. */
static int t_section_name_exact_match(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen" };
    size_t addrs[1] = {0};
    int rv;

    /* lookalike prefixes -> rejected */
    elf_opts_default(&o);
    o.strtab_name = ".dynstrXXX";
    o.dynsym_name = ".dynsymx";
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (lookalike names rv=%d)\n", rv);
    MU_ASSERT(rv != 0);

    /* positive control: exact names -> accepted */
    elf_opts_default(&o);
    addrs[0] = 0;
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    MU_ASSERT(rv == 0);
    MU_ASSERT(addrs[0] == ELF_LIBC_BASE + ELF_SYM_VALUE);
    return 0;
}

/* 7. e_shstrndx out of range -> non-zero, no crash. */
static int t_shstrndx_out_of_range(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen" };
    size_t addrs[1] = {0};
    int rv;

    elf_opts_default(&o);
    o.e_shstrndx = o.e_shnum; /* one past the last section */
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (shstrndx==shnum rv=%d)\n", rv);
    MU_ASSERT(rv != 0);

    elf_opts_default(&o);
    o.e_shstrndx = 0xffff;
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (shstrndx=0xffff rv=%d)\n", rv);
    MU_ASSERT(rv != 0);
    return 0;
}

/* 8. shstrndx/shnum/shentsize all maximal: the section-table extent used to be
 *    computed in signed int (UB overflow). Must be rejected, not crash. */
static int t_shstrndx_entsize_int_overflow(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen" };
    size_t addrs[1] = {0};
    int rv;

    elf_opts_default(&o);
    o.e_shstrndx = 65535;
    o.e_shnum = 65535;
    o.e_shentsize = 65535;
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (shnum=shentsize=shstrndx=65535 rv=%d)\n", rv);
    MU_ASSERT(rv != 0);
    return 0;
}

/* 9. Absurd .dynsym sh_size / tiny sh_entsize on a small file -> non-zero,
 *    no giant allocation, no crash. */
static int t_huge_symtab_size(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen" };
    size_t addrs[1] = {0};
    int rv;

    elf_opts_default(&o);
    o.dynsym_sh_size = (uint64_t)0xffffffffffffffffULL;
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (sh_size=UINT64_MAX rv=%d)\n", rv);
    MU_ASSERT(rv != 0);

    elf_opts_default(&o);
    o.dynsym_sh_size = (uint64_t)0xffffffffffffffffULL;
    o.dynsym_sh_entsize = 1;
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 1);
    unlink(path);
    fprintf(stderr, "    (sh_size=UINT64_MAX,entsize=1 rv=%d)\n", rv);
    MU_ASSERT(rv != 0);
    return 0;
}

/* 10. Positive control: the synthesised image parses, bias is applied, and an
 *     absent name yields 0. */
static int t_valid_elf_resolves(void)
{
    elf_opts_t o;
    char path[ELF_PATHSZ];
    const char *names[] = { "dlopen", "no_such_symbol_anywhere" };
    size_t addrs[2] = {0, 0};
    int rv;

    elf_opts_default(&o);
    MU_ASSERT(elf_build_to_file(&o, path, sizeof(path)) == 0);
    rv = injector__elf_find_symbols(path, ELF_LIBC_BASE, names, addrs, 2);
    unlink(path);
    fprintf(stderr, "    (rv=%d dlopen=%zx absent=%zx)\n", rv, addrs[0], addrs[1]);
    MU_ASSERT(rv == 0);
    MU_ASSERT(addrs[0] == ELF_LIBC_BASE + ELF_SYM_VALUE);
    MU_ASSERT(addrs[1] == 0);
    return 0;
}

/* Entry point registered by tests/unit/run.c. */
int test_elf_resolve_known_symbols(void)
{
    int failed_before = tests_failed;

    RUN_ELF_SUB(t_real_so_resolves);
    RUN_ELF_SUB(t_valid_elf_resolves);
    RUN_ELF_SUB(t_undef_symbol_skipped);
    RUN_ELF_SUB(t_dynstr_no_trailing_nul);
    RUN_ELF_SUB(t_section_name_exact_match);
    RUN_ELF_SUB(t_shentsize_too_large);
    RUN_ELF_SUB(t_dynsym_entsize_zero);
    RUN_ELF_SUB(t_shstrndx_out_of_range);
    RUN_ELF_SUB(t_shstrndx_entsize_int_overflow);
    RUN_ELF_SUB(t_huge_symtab_size);
    RUN_ELF_SUB(t_truncated_and_garbage);

    return tests_failed != failed_before;
}
