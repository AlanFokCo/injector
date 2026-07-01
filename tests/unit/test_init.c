#include "minunit.h"
#include "injector.h"

int test_library_init_idempotent(void) {
    MU_ASSERT(injector_library_init() == 0);
    MU_ASSERT(injector_library_init() == 0);
    MU_ASSERT(injector_library_deinit() == 0);
    return 0;
}

int test_library_deinit_noop_when_uninit(void) {
    MU_ASSERT(injector_library_deinit() == 0);
    return 0;
}
