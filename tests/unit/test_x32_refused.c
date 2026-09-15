/* test_x32_refused.c - pin injector__arch_is_unsupported() (src/linux/elf.c)
 * to exactly the ABI this project refuses.
 *
 * PRODUCT DECISION UNDER TEST: there is no x32 runtime any more. What ships is
 * x86_64 (LP64) and i386. An EM_X86_64 + ELFCLASS32 libc used to be classified
 * ARCH_X86_64_X32 and driven down remote_call.c's shared x86_64 `0f 05 cc`
 * trampoline path; it is now named and refused, before `injector->arch` is
 * assigned and before anything is written to the target.
 *
 * WHAT THIS TEST PROVES
 *   - the classifier's truth table: every x86 machine/class pair, several
 *     non-x86 machines at both ELFCLASS widths, an ELFCLASSNONE row and an
 *     unknown e_machine, each asserted against a literal expectation;
 *   - that the user-visible arch name for ARCH_X86_64_X32 says "unsupported",
 *     while the two arches we do ship do not;
 *   - that the table has not silently shrunk (row count is pinned).
 *
 * WHAT THIS TEST DOES *NOT* PROVE - do not read more into a green run
 *   - Nothing here attaches to, ptraces, or injects into anything. It calls one
 *     pure function with numbers, so it says nothing about the attach path,
 *     about error_exit detaching cleanly, or about a real x32 process.
 *   - End-to-end refusal of a REAL x32 target is not exercised here and cannot
 *     be exercised anywhere we have: it needs a kernel with CONFIG_X86_X32_ABI
 *     to execve an x32 binary at all, and neither the build host nor GitHub's
 *     runners has one. That is precisely why the path was removed instead of
 *     kept. The ordering that makes refusal safe (collect_libc_information runs
 *     before the first injector__call_syscall patches code_addr) is argued in a
 *     comment in elf.c and verified by reading injector.c - it is NOT verified
 *     by a passing test, and this file is the record of that split.
 *   - On a non-x86 build the classifier's x86 arm is compiled out and the whole
 *     REFUSED column collapses to 0, so a green run there is weaker coverage,
 *     not equal coverage.
 */
#include "minunit.h"
#include "injector.h"
#include "../src/linux/injector_internal.h"
#include <elf.h>
#include <stdio.h>
#include <string.h>

/* Literal expectations, not a restatement of the implementation's condition.
 * On an x86 build exactly one pair in the table is refused; on any other build
 * the `#if defined(__x86_64__) || defined(__i386__)` arm of the classifier is
 * compiled out, it refuses nothing, and every row expects NOT_REFUSED. */
#if defined(__x86_64__) || defined(__i386__)
#define REFUSED     1
#define NOT_REFUSED 0
#define X86_BUILD   1
#else
#define REFUSED     0
#define NOT_REFUSED 0
#define X86_BUILD   0
#endif

typedef struct {
    unsigned short e_machine;
    unsigned char  ei_class;
    const char    *what;
    int            expect_refused;
} x32_case_t;

static const x32_case_t x32_cases[] = {
    /* --- the one refusal: x86_64 machine, 32-bit class = the x32 ABI ------- */
    { EM_X86_64, ELFCLASS32, "x86_64 + ELFCLASS32 = x32 ABI",        REFUSED },

    /* --- every other x86 pair must be let through ------------------------ */
    { EM_X86_64, ELFCLASS64, "x86_64 LP64 (shipped)",                NOT_REFUSED },
    /* Not x32: a bogus class on an x86_64 machine. The classifier's answer is
     * correctly "not my business" (0) - in the real path validate_elf_layout()
     * rejects any EI_CLASS other than ELFCLASS32/64 first, with its own
     * INJERR_UNSUPPORTED_TARGET, so this header never reaches arch detection.
     * The row pins the classifier's narrow question, not the whole decision. */
    { EM_X86_64, ELFCLASSNONE, "x86_64 + ELFCLASSNONE (bogus class)", NOT_REFUSED },
    { EM_386,    ELFCLASS32, "i386 (shipped)",                       NOT_REFUSED },
    { EM_386,    ELFCLASS64, "i386 machine, 64-bit class (bogus)",   NOT_REFUSED },
    { EM_386,    ELFCLASSNONE, "i386 + ELFCLASSNONE (bogus class)",  NOT_REFUSED },

    /* --- non-x86 machines, both classes: never this classifier's business - */
    { EM_AARCH64, ELFCLASS64, "aarch64 64-bit",                      NOT_REFUSED },
    { EM_AARCH64, ELFCLASS32, "aarch64 32-bit",                      NOT_REFUSED },
    { EM_ARM,     ELFCLASS32, "arm EABI",                            NOT_REFUSED },
    { EM_ARM,     ELFCLASS64, "arm 64-bit class (bogus)",            NOT_REFUSED },
    { EM_PPC64,   ELFCLASS64, "powerpc64",                           NOT_REFUSED },
    { EM_PPC,     ELFCLASS32, "powerpc",                             NOT_REFUSED },
    { EM_MIPS,    ELFCLASS32, "mips o32",                            NOT_REFUSED },
    { EM_MIPS,    ELFCLASS64, "mips 64",                             NOT_REFUSED },
#ifdef EM_RISCV
    { EM_RISCV,   ELFCLASS64, "riscv64",                             NOT_REFUSED },
    { EM_RISCV,   ELFCLASS32, "riscv32",                             NOT_REFUSED },
#endif

    /* --- unknown / absent machines: the e_machine switch's `default:` owns
     * those, with its own INJERR_UNSUPPORTED_TARGET. Not this function. ------ */
    { EM_NONE,    ELFCLASS32, "EM_NONE",                             NOT_REFUSED },
    { EM_NONE,    ELFCLASS64, "EM_NONE",                             NOT_REFUSED },
    { 0xBEEF,     ELFCLASS32, "machine id no ELF header defines",     NOT_REFUSED },
    { 0xBEEF,     ELFCLASS64, "machine id no ELF header defines",     NOT_REFUSED },
};

#define X32_NCASES ((int)(sizeof(x32_cases) / sizeof(x32_cases[0])))

/* Row-count pin: deleting rows from the table above must not be a way to make
 * this test pass. 20 rows with EM_RISCV defined, 18 without. */
#ifdef EM_RISCV
#define X32_EXPECT_NCASES 20
#else
#define X32_EXPECT_NCASES 18
#endif

/* Entry point registered by tests/unit/run.c. Returns 0 on success; MU_ASSERT
 * returns 1 and names the file:line of the first failing row. */
int test_x32_is_refused(void)
{
    int i;
    int refused_seen = 0;

    /* The table is the test, so assert it is the table we think it is. */
    MU_ASSERT(X32_NCASES == X32_EXPECT_NCASES);

    for (i = 0; i < X32_NCASES; i++) {
        const x32_case_t *c = &x32_cases[i];
        int rv = injector__arch_is_unsupported(c->e_machine, c->ei_class);

        /* The contract is "non-zero", so compare truth values, not the raw
         * int: an implementation returning 2 must not fail here, and one
         * returning 0 for a refused pair must. */
        int matches = ((rv != 0) == (c->expect_refused != 0));
        if (!matches) {
            fprintf(stderr,
                    "    arch_is_unsupported(EM=%u, class=%u) [%s]: got %d want %s\n",
                    (unsigned)c->e_machine, (unsigned)c->ei_class, c->what,
                    rv, c->expect_refused ? "refused" : "accepted");
        }
        MU_ASSERT(matches);
        if (rv != 0) {
            refused_seen++;
        }
    }

#if X86_BUILD
    /* Exactly one row in the table is a refusal, and it is the x32 one: no
     * over-broad classifier that happens to refuse x32 too. */
    MU_ASSERT(refused_seen == 1);
    MU_ASSERT(injector__arch_is_unsupported(EM_X86_64, ELFCLASS32) != 0);
    MU_ASSERT(injector__arch_is_unsupported(EM_X86_64, ELFCLASS64) == 0);
    MU_ASSERT(injector__arch_is_unsupported(EM_386, ELFCLASS32) == 0);
#else
    MU_ASSERT(refused_seen == 0);
#endif

    /* util.c's arch-name table: the enum case stays so the switch remains
     * exhaustive, and the string is user-visible diagnostics, so it must state
     * that the ABI is unsupported - and the two arches we do ship must not
     * borrow that word. */
    {
        const char *x32_name = injector__arch2name(ARCH_X86_64_X32);
        const char *lp64_name = injector__arch2name(ARCH_X86_64);
        const char *i386_name = injector__arch2name(ARCH_I386);
        MU_ASSERT(x32_name != NULL);
        MU_ASSERT(strstr(x32_name, "unsupported") != NULL);
        MU_ASSERT(lp64_name != NULL && strstr(lp64_name, "unsupported") == NULL);
        MU_ASSERT(i386_name != NULL && strstr(i386_name, "unsupported") == NULL);
        fprintf(stderr, "    (arch2name(ARCH_X86_64_X32) = \"%s\", %d row(s) refused)\n",
                x32_name, refused_seen);
    }
    return 0;
}
