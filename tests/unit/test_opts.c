#include "minunit.h"
#include "injector.h"
#include <stddef.h>

void injector__opts_normalize(injector_opts_t *o);
int injector__opts_copy(injector_opts_t *dst, const void *src, size_t src_size);

int test_opts_default(void) {
    injector_opts_t o = INJECTOR_OPTS_INIT;
    injector__opts_normalize(&o);
    MU_ASSERT(o.call_timeout_ms == 5000);
    MU_ASSERT(o.delivery == INJECTOR_DELIVERY_AUTO);
    MU_ASSERT(o.timeout_action == INJECTOR_TIMEOUT_LEAVE);
    MU_ASSERT(o.enable_write_mem == 0);
    return 0;
}

int test_opts_size_negotiation(void) {
    struct { size_t opts_size; injector_delivery_t delivery; } small;
    small.opts_size = sizeof(small);
    small.delivery = INJECTOR_DELIVERY_PTRACE;
    /* zero the padding so the overlapped call_timeout_ms field is 0 -> default */
    char *raw = (char *)&small;
    size_t i;
    for (i = 0; i < sizeof(small); i++) raw[i] = 0;
    small.opts_size = sizeof(small);
    small.delivery = INJECTOR_DELIVERY_PTRACE;
    injector_opts_t out = INJECTOR_OPTS_INIT;
    MU_ASSERT(injector__opts_copy(&out, &small, small.opts_size) == 0);
    MU_ASSERT(out.delivery == INJECTOR_DELIVERY_PTRACE);
    MU_ASSERT(out.call_timeout_ms == 5000);
    MU_ASSERT(out.opts_size == sizeof(injector_opts_t));
    return 0;
}

int test_opts_too_small(void) {
    struct { size_t opts_size; } tiny;
    tiny.opts_size = sizeof(tiny);
    injector_opts_t out = INJECTOR_OPTS_INIT;
    MU_ASSERT(injector__opts_copy(&out, &tiny, tiny.opts_size) != 0);
    return 0;
}
