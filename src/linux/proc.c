/* -*- indent-tabs-mode: nil -*-
 *
 * injector - reusable /proc parser (internal)
 */
#include "proc.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int proc__parse_maps_line(const char *line, proc_map_t *m)
{
    int n = 0;
    if (sscanf(line, "%lx-%lx %*s %llx %x:%x %llu %n",
               &m->start, &m->end, &m->offset, &m->devmaj, &m->devmin,
               &m->inode, &n) < 6) {
        return -1;
    }
    const char *p = line + n;
    if (*p == '\0' || *p == '\n') {
        return -1;  /* anonymous mapping, no path */
    }
    size_t i = 0;
    while (*p && *p != '\n' && i < sizeof(m->path) - 1) {
        m->path[i++] = *p++;
    }
    m->path[i] = '\0';
    /* detect and strip " (deleted)" suffix */
    static const char suffix[] = " (deleted)";
    size_t len = strlen(m->path);
    size_t slen = sizeof(suffix) - 1;
    m->deleted = 0;
    if (len >= slen && strcmp(m->path + len - slen, suffix) == 0) {
        m->path[len - slen] = '\0';
        m->deleted = 1;
    }
    return 0;
}

int proc__read_link(const char *proc_path, char *out, size_t n)
{
    ssize_t r = readlink(proc_path, out, n - 1);
    if (r < 0) {
        out[0] = '\0';
        return -1;
    }
    out[r] = '\0';
    return 0;
}

int proc__read_comm(pid_t pid, char *out, size_t n)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        out[0] = '\0';
        return -1;
    }
    size_t i = 0;
    int c;
    while ((c = fgetc(fp)) != EOF && c != '\n' && i < n - 1) {
        out[i++] = (char)c;
    }
    out[i] = '\0';
    fclose(fp);
    return 0;
}
