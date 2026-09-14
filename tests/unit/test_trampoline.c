/* test_trampoline.c - pin injector__code_is_trampoline() to the bytes the two
 * remote-call writers actually emit.
 *
 * Why this has its own file: it needs injector_internal.h (injector_t, code_t,
 * arch_t and the TRAMP_* macros), which the other unit tests here do not, and
 * it tests an internal symbol rather than a public guard.
 *
 * The detector is the only thing standing between a desynced target and this
 * library adopting its OWN trampoline as that target's original code - after
 * which every "restore" re-installs an int3 into libc's entry point, the
 * original bytes are unrecoverable, and the target dies at its next call. Its
 * byte patterns used to be literals retyped in three places (two writers and
 * the detector), so editing a writer silently turned the detector into a no-op:
 * no compile error, and no red test. The writers and the detector now share the
 * TRAMP_* macros and this test builds its expectations from those same macros,
 * so the coupling is asserted rather than assumed.
 *
 * Nothing here attaches to anything - the detector is fed byte patterns
 * directly - so it is safe in every environment, unlike any test that would
 * have to exercise the attach path to reach it.
 */
#include "minunit.h"
#include "injector.h"
#include "../src/linux/injector_internal.h"
#include <stdio.h>
#include <string.h>
#if defined(__x86_64__) || defined(__i386__)
/* injector__code_is_trampoline() is the only thing standing between a
 * desynced target and this library adopting its OWN trampoline as that
 * target's original code - after which every "restore" re-installs an int3
 * into libc's entry point, the original bytes are unrecoverable, and the
 * target dies at its next call. The bytes it matches used to be literals
 * retyped in three places (two writers and the detector), so editing a writer
 * silently turned the detector into a no-op: no compile error, no red test.
 * The writers and the detector now share the TRAMP_* macros, and this test
 * builds its expectations from those same macros, so the coupling is asserted
 * rather than assumed.
 *
 * It runs without attaching to anything - it feeds the detector byte patterns
 * directly - so it is safe in every environment, unlike anything that would
 * have to exercise the attach path. */
static void build_tramp(code_t *code, unsigned char b0, unsigned char b1)
{
    memset(code, 0, sizeof(*code));
    code->u8[0] = b0;
    code->u8[1] = b1;
    code->u8[2] = TRAMP_INT3;
    /* exactly what both writers do: pad to the full word with `nop` */
    memset(&code->u8[TRAMP_LEN], TRAMP_NOP, sizeof(code_t) - TRAMP_LEN);
}

static int trampoline_case(arch_t arch, unsigned char b0, unsigned char b1,
                           const char *what)
{
    injector_t inj;
    code_t code, perturbed;
    size_t i;
    int b;

    memset(&inj, 0, sizeof(inj));
    inj.arch = arch;

    build_tramp(&code, b0, b1);
    if (!injector__code_is_trampoline(&inj, &code)) {
        fprintf(stderr, "    detector did not recognise its own %s trampoline\n", what);
        return 0;
    }
    /* The match must be exact and full width. Every single-bit perturbation of
     * every byte has to be rejected, or a clean target whose prologue happened
     * to resemble the pattern would be refused - and refusing every attach is
     * as broken as detecting nothing. */
    for (i = 0; i < sizeof(code_t); i++) {
        for (b = 0; b < 8; b++) {
            perturbed = code;
            perturbed.u8[i] = (unsigned char)(perturbed.u8[i] ^ (1u << b));
            if (injector__code_is_trampoline(&inj, &perturbed)) {
                fprintf(stderr,
                        "    detector accepted a perturbed %s trampoline "
                        "(byte %u, bit %d)\n", what, (unsigned)i, b);
                return 0;
            }
        }
    }
    /* A real glibc-style prologue must never match. */
    memset(&code, 0, sizeof(code));
    code.u8[0] = 0xf3; code.u8[1] = 0x0f; code.u8[2] = 0x1e; code.u8[3] = 0xfa;
    code.u8[4] = 0x55; code.u8[5] = 0x48; code.u8[6] = 0x89; code.u8[7] = 0xe5;
    if (injector__code_is_trampoline(&inj, &code)) {
        fprintf(stderr, "    detector refused a clean prologue as %s\n", what);
        return 0;
    }
    /* Neither may an untouched word. */
    memset(&code, 0, sizeof(code));
    if (injector__code_is_trampoline(&inj, &code)) {
        fprintf(stderr, "    detector refused an all-zero word as %s\n", what);
        return 0;
    }
    return 1;
}
#endif

/* The arch guards below mirror the detector's own, so this test asks about an
 * arch only where the detector was compiled with a writer for it. Asking about
 * ARCH_X86_64 in a -m32 build would hit `default:` and correctly answer "not
 * ours", which would make the test fail for the wrong reason. */
int test_trampoline_detector_matches_the_writers(void) {
#if defined(__x86_64__) && defined(__LP64__)
    MU_ASSERT(trampoline_case(ARCH_X86_64, TRAMP_SYSCALL64_B0, TRAMP_SYSCALL64_B1,
                              "x86_64 syscall"));
    MU_ASSERT(trampoline_case(ARCH_X86_64, TRAMP_CALLFUNC_B0, TRAMP_CALLFUNC_B1,
                              "x86_64 call"));
    MU_ASSERT(trampoline_case(ARCH_X86_64_X32, TRAMP_SYSCALL64_B0, TRAMP_SYSCALL64_B1,
                              "x32 syscall"));
    MU_ASSERT(trampoline_case(ARCH_X86_64_X32, TRAMP_CALLFUNC_B0, TRAMP_CALLFUNC_B1,
                              "x32 call"));
#endif
#if defined(__x86_64__) || defined(__i386__)
    MU_ASSERT(trampoline_case(ARCH_I386, TRAMP_SYSCALL32_B0, TRAMP_SYSCALL32_B1,
                              "i386 int 0x80"));
    MU_ASSERT(trampoline_case(ARCH_I386, TRAMP_CALLFUNC_B0, TRAMP_CALLFUNC_B1,
                              "i386 call"));
#endif
    return 0;
}
