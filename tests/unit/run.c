#include "minunit.h"
int tests_run = 0;
int tests_failed = 0;
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
    fprintf(stderr, "unit: %d run, %d failed\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
