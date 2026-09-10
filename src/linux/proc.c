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
    /* MINOR 10: the path is silently truncated at sizeof(m->path)-1 bytes.
     * Detect the " (deleted)" marker on the RAW line tail (before the newline)
     * rather than on the possibly truncated copy, otherwise a long deleted
     * mapping loses the suffix and callers (injector_target_info,
     * injector__collect_libc_information) trust a file that no longer exists. */
    static const char suffix[] = " (deleted)";
    const size_t slen = sizeof(suffix) - 1;
    const char *eol = strchr(p, '\n');
    const char *rawend = eol ? eol : p + strlen(p);
    size_t rawlen = (size_t)(rawend - p);
    size_t cplen = rawlen < sizeof(m->path) - 1 ? rawlen : sizeof(m->path) - 1;
    size_t i = 0;

    m->deleted = (rawlen >= slen && memcmp(rawend - slen, suffix, slen) == 0) ? 1 : 0;
    while (i < cplen) {
        m->path[i++] = *p++;
    }
    m->path[i] = '\0';
    if (m->deleted && i >= slen && memcmp(m->path + i - slen, suffix, slen) == 0) {
        m->path[i - slen] = '\0';
    }
    return 0;
}

int proc__read_link(const char *proc_path, char *out, size_t n)
{
    ssize_t r;
    /* MINOR 9: with n == 0, `n - 1` wraps to SIZE_MAX (size_t) and readlink
     * would overflow the caller's buffer. */
    if (n == 0) {
        return -1;
    }
    r = readlink(proc_path, out, n - 1);
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
    /* MINOR 9: guard n == 0 (`n - 1` wraps to SIZE_MAX). */
    if (n == 0) {
        fclose(fp);
        return -1;
    }
    while ((c = fgetc(fp)) != EOF && c != '\n' && i < n - 1) {
        out[i++] = (char)c;
    }
    out[i] = '\0';
    fclose(fp);
    return 0;
}
