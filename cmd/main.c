/* -*- indent-tabs-mode: nil -*-
 *
 * injector - Library for injecting a shared library into a Linux process
 *
 * URL: https://github.com/kubo/injector
 *
 * ------------------------------------------------------
 *
 * Copyright (C) 2018 Kubo Takehiro <kubo@jiubao.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include "injector.h"

#define INVALID_PID -1
static pid_t find_process(const char *name)
{
    DIR *dir = opendir("/proc");
    struct dirent *dent;
    pid_t pid = -1;

    if (dir == NULL) {
        fprintf(stderr, "Failed to read proc file system.\n");
        exit(1);
    }
    while ((dent = readdir(dir)) != NULL) {
        char path[sizeof(dent->d_name) + 11];
        char exepath[PATH_MAX];
        ssize_t len;
        char *exe;

        if (dent->d_name[0] < '1' || '9' < dent->d_name[0]) {
            continue;
        }
        sprintf(path, "/proc/%s/exe", dent->d_name);
        len = readlink(path, exepath, sizeof(exepath) - 1);
        if (len == -1) {
            continue;
        }
        exepath[len] = '\0';
        exe = strrchr(exepath, '/');
        if (exe != NULL && strcmp(exe + 1, name) == 0) {
            pid = atoi(dent->d_name);
            break;
        }
    }
    closedir(dir);
    return pid;
}

int main(int argc, char **argv)
{
    injector_pid_t pid = INVALID_PID;
    injector_t *injector;
    int opt;
    int i;
    char *endptr;
    int rv = 0;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    const char *optstring = "n:p:T";
    int cloned_thread = 0;
#else
    const char *optstring = "n:p:";
#endif

    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
        case 'n':
            pid = find_process(optarg);
            if (pid == INVALID_PID) {
                fprintf(stderr, "could not find the process: %s\n", optarg);
                return 1;
            }
            printf("targeting process \"%s\" with pid %d\n", optarg, pid);
            break;
        case 'p':
            pid = strtol(optarg, &endptr, 10);
            if (pid <= 0 || *endptr != '\0') {
                fprintf(stderr, "invalid process id number: %s\n", optarg);
                return 1;
            }
            printf("targeting process with pid %d\n", pid);
            break;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        case 'T':
            cloned_thread = 1;
            break;
#endif
        }
    }
    if (pid == INVALID_PID) {
        fprintf(stderr, "Usage: %s [-n process-name] [-p pid] library-to-inject ...\n", argv[0]);
        return 1;
    }

    if (injector_attach(&injector, pid) != 0) {
        printf("%s\n", injector_error());
        return 1;
    }
    for (i = optind; i < argc; i++) {
        char *libname = argv[i];
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        if (cloned_thread) {
            if (injector_inject_in_cloned_thread(injector, libname, NULL) == 0) {
                printf("clone thread to inject \"%s\" was created.\n", libname);
            } else {
                fprintf(stderr, "could not create cloned thread \"%s\"\n", libname);
                fprintf(stderr, "  %s\n", injector_error());
                rv = 1;
            }
            continue;
        }
#endif
        if (injector_inject(injector, libname, NULL) == 0) {
            printf("\"%s\" successfully injected\n", libname);
        } else {
            fprintf(stderr, "could not inject \"%s\"\n", libname);
            fprintf(stderr, "  %s\n", injector_error());
            rv = 1;
        }
    }
    injector_detach(injector);
    return rv;
}
