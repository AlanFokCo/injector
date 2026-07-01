#include "minunit.h"
int tests_run = 0;
int tests_failed = 0;
static int test_dummy(void) { MU_ASSERT(1 + 1 == 2); return 0; }
int main(void) {
    MU_RUN_TEST(test_dummy);
    fprintf(stderr, "unit: %d run, %d failed\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
