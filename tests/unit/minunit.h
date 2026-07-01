#ifndef MINUNIT_H
#define MINUNIT_H
#include <stdio.h>
#include <string.h>
extern int tests_run;
extern int tests_failed;
#define MU_RUN_TEST(t) do { tests_run++; \
    if (t() != 0) { tests_failed++; fprintf(stderr, "  FAIL: %s\n", #t); } \
    else fprintf(stderr, "  ok:   %s\n", #t); } while (0)
#define MU_ASSERT(cond) do { if (!(cond)) { \
    fprintf(stderr, "    assert failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
    return 1; } } while (0)
#define MU_ASSERT_STR_EQ(a, b) do { if (strcmp((a),(b)) != 0) { \
    fprintf(stderr, "    str neq: got=\"%s\" want=\"%s\" (%s:%d)\n", (a),(b),__FILE__,__LINE__); \
    return 1; } } while (0)
#endif