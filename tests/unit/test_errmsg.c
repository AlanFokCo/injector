#include "minunit.h"
#include "injector.h"
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

int test_error_after_failed_attach(void) {
    pid_t child = fork();
    if (child == 0) _exit(0);
    if (child < 0) return 0; /* fork fail -> skip */
    waitpid(child, NULL, 0); /* child reaped; its pid is now absent */
    injector_t *inj = NULL;
    int rv = injector_attach(&inj, child); /* ESRCH -> INJERR_NO_PROCESS */
    MU_ASSERT(rv != 0);
    MU_ASSERT(inj == NULL);
    const char *e = injector_error(); /* thread-local fallback must survive */
    MU_ASSERT(e != NULL && e[0] != '\0');
    MU_ASSERT(strstr(e, "No such process") != NULL);
    return 0;
}
