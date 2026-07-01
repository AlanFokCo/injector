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

/* Read a /proc/PID/{exe,cwd,root} symlink into out (NUL-terminated). Returns 0
 * on success, -1 on error. */
int proc__read_link(const char *proc_path, char *out, size_t n);

/* Read /proc/PID/comm into out (NUL-terminated, stripped). Returns 0/-1. */
int proc__read_comm(pid_t pid, char *out, size_t n);

#endif
