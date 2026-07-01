#define INCR_ON_INJECTION 13
#define INCR_ON_UNINJECTION 17

#include <stdint.h>
#include <unistd.h>

extern int exit_value;

__attribute__((constructor))
void init()
{
    exit_value += INCR_ON_INJECTION;
}

__attribute__((destructor))
void fini()
{
    exit_value += INCR_ON_UNINJECTION;
}

intptr_t sum_integers(intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6)
{
    return a1 + a2 + a3 + a4 + a5 + a6;
}

__attribute__((used))
intptr_t hang_forever(void) { while (1) { pause(); } return 0; }

intptr_t entry_noarg(void) { return 42; }

intptr_t entry_onearg(intptr_t a) { return a * 2; }

intptr_t entry_threeargs(intptr_t a, intptr_t b, intptr_t c) { return a + b + c; }
