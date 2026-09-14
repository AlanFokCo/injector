#ifndef INJECTOR_PROC_H
#define INJECTOR_PROC_H
#include <sys/types.h>
#include <stddef.h>

typedef struct {
    unsigned long start;           /* mapping start addr */
    unsigned long end;
    unsigned long long offset;
    unsigned int devmaj, devmin;
    unsigned long long inode;
    char path[512];                /* mapped file path (truncated) */
    int deleted;                   /* 1 if " (deleted)" */
} proc_map_t;

/* Parse ONE /proc/PID/maps line into m. Returns 0 on success (a mapping with a
 * path), -1 if the line has no path (e.g. anonymous). Bracketed special
 * mappings ([heap], [stack]) carry a path and return 0. */
int proc__parse_maps_line(const char *line, proc_map_t *m);

/* The two readers below share one contract, which tests/unit/test_guards.c and
 * tests/fuzz/fuzz_proc.c both assert and which callers are entitled to rely on:
 *
 *   1. `n` is the TOTAL size of `out` in bytes, including the NUL. At most
 *      n - 1 bytes of content are stored.
 *   2. n == 0 returns -1 and writes NOTHING AT ALL - not even a NUL. There is no
 *      length-probe mode: passing 0 never reports how long the value was, it
 *      only fails. Callers that want a length must pass a buffer.
 *   3. On error (-1) with n > 0, out[0] is set to '\0', so the buffer is always
 *      a valid empty C string and never left holding the caller's old contents.
 *   4. On success (0) the result is NUL-terminated inside `out`. A value longer
 *      than n - 1 is SILENTLY TRUNCATED: there is no return value, no errno and
 *      no other indication that it happened, so a caller that must distinguish
 *      "short value" from "truncated value" has to size the buffer itself.
 *
 * Rule 2 is what the n == 0 guards exist for. It is easy to break by adding an
 * early-exit branch that initialises the output before checking the size - that
 * is exactly the defect proc__read_comm() had, and it writes one byte into a
 * buffer the caller declared to be zero bytes long.
 */

/* Read a /proc/PID/{exe,cwd,root} symlink into out (NUL-terminated). Returns 0
 * on success, -1 on error. See the shared contract above. */
int proc__read_link(const char *proc_path, char *out, size_t n);

/* Read /proc/PID/comm into out (NUL-terminated, stripped of its trailing
 * newline). Returns 0 on success, -1 on error. See the shared contract above. */
int proc__read_comm(pid_t pid, char *out, size_t n);

#endif
