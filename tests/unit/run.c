#include "minunit.h"
#include <stdlib.h>     /* getenv */
#include <string.h>     /* strcmp */
int tests_run = 0;
int tests_failed = 0;
/* Counted skips. Kept in the summary so a test that could not set itself up is
 * visible instead of looking like a pass. */
int tests_skipped = 0;
static int test_dummy(void) { MU_ASSERT(1 + 1 == 2); return 0; }
int test_error_after_failed_attach(void);
int test_opts_default(void);
int test_opts_size_negotiation(void);
int test_opts_too_small(void);
int test_elf_resolve_known_symbols(void);
int test_proc_parse_maps_line_libc(void);
int test_proc_parse_maps_line_deleted(void);
int test_proc_parse_maps_line_anon(void);
int test_proc_target_info_self(void);
int test_library_init_idempotent(void);
int test_library_deinit_noop_when_uninit(void);
int test_null_handle_is_refused(void);
int test_failed_attach_nulls_the_handle(void);
int test_nonpositive_pid_rejected(void);
int test_proc_zero_length_buffer(void);
int test_proc_long_path_still_detects_deleted(void);
int test_trampoline_detector_matches_the_writers(void);
int test_x32_is_refused(void);
int test_handle_limits_and_affinity(void);
int test_orphan_scan_gates(void);
/* This list is the only thing that makes a test execute, and nothing at link
 * time or run time notices when it is wrong. A test_* defined in unit/test_*.c
 * and never named below still links - its symbol is simply unreferenced, and a
 * static archive is only searched for symbols somebody needs - and never runs;
 * deleting one of the lines below has the identical effect. Both leave a suite
 * that prints its summary and exits 0, which is the silent green the rest of
 * this repo's test plumbing exists to prevent. So it is checked at build time
 * instead: `make unit` first runs the unit/registration-check target in
 * tests/Makefile, which fails the build unless (1) every unit/test_*.c on disk
 * is listed in UNIT_OBJS, (2) every top-level test_* defined in those files is
 * registered here, and (3) the number of registrations equals
 * UNIT_RUN_TEST_COUNT - 21 as of this writing. Adding a test is therefore three
 * edits, and the third is the one that is enforced: bump that count in the same
 * commit. Keep the registration lines starting at column 1 plus indentation;
 * the check anchors on that. */
int main(void) {
    MU_RUN_TEST(test_dummy);
    MU_RUN_TEST(test_error_after_failed_attach);
    MU_RUN_TEST(test_opts_default);
    MU_RUN_TEST(test_opts_size_negotiation);
    MU_RUN_TEST(test_opts_too_small);
    MU_RUN_TEST(test_elf_resolve_known_symbols);
    MU_RUN_TEST(test_proc_parse_maps_line_libc);
    MU_RUN_TEST(test_proc_parse_maps_line_deleted);
    MU_RUN_TEST(test_proc_parse_maps_line_anon);
    MU_RUN_TEST(test_proc_target_info_self);
    MU_RUN_TEST(test_library_init_idempotent);
    MU_RUN_TEST(test_library_deinit_noop_when_uninit);
    MU_RUN_TEST(test_null_handle_is_refused);
    MU_RUN_TEST(test_failed_attach_nulls_the_handle);
    MU_RUN_TEST(test_nonpositive_pid_rejected);
    MU_RUN_TEST(test_proc_zero_length_buffer);
    MU_RUN_TEST(test_proc_long_path_still_detects_deleted);
    MU_RUN_TEST(test_trampoline_detector_matches_the_writers);
    MU_RUN_TEST(test_x32_is_refused);
    MU_RUN_TEST(test_handle_limits_and_affinity);
    MU_RUN_TEST(test_orphan_scan_gates);
    /* The "unit: N run, M failed" prefix is parsed by tooling - keep it and
     * only append to it. */
    fprintf(stderr, "unit: %d run, %d failed, %d skipped\n",
            tests_run, tests_failed, tests_skipped);
    if (tests_failed != 0) {
        return 1;
    }
    if (tests_skipped != 0) {
        /* A counted skip that still exits 0 is indistinguishable from a run in
         * which nothing was skipped, so the suite can go silently vacuous (a
         * missing toolchain, an unwritable /tmp, a fixture that never built)
         * while CI stays green. Make that red unless the caller explicitly
         * opts in with INJECTOR_ALLOW_SKIP=1 - which is also the knob the ELF
         * sub-tests honour before they report a skip instead of a failure. */
        const char *allow = getenv("INJECTOR_ALLOW_SKIP");
        if (allow == NULL || strcmp(allow, "1") != 0) {
            fprintf(stderr,
                    "ERROR: %d sub-test(s) were skipped, and a skipped sub-test "
                    "is not a passing one.\n"
                    "       Re-run with INJECTOR_ALLOW_SKIP=1 to accept a run "
                    "that skips.\n", tests_skipped);
            return 1;
        }
        fprintf(stderr,
                "WARNING: %d sub-test(s) skipped because INJECTOR_ALLOW_SKIP=1\n",
                tests_skipped);
    }
    return 0;
}
