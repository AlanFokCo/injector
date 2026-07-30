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
#include <getopt.h>
#include <inttypes.h>
#include "injector.h"

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] [library-to-inject ...]\n"
        "\n"
        "Target (one required):\n"
        "  -p, --pid PID           target process id\n"
        "  -n, --name NAME         find target by executable basename\n"
        "\n"
        "Actions:\n"
        "  (default)               inject libraries listed after options\n"
        "  -r, --run LIB:SYMBOL    one-shot: inject LIB, call SYMBOL, detach\n"
        "  -d, --delivery MODE     one-shot delivery: auto|nonstop|ptrace (default: auto)\n"
        "                          use 'ptrace' for CUDA/heavy targets (nonstop dlopen\n"
        "                          from a TLS-less clone can fault in ld.so)\n"
        "  -a, --arg VALUE         argument for --run (up to 6, integer or 0x hex)\n"
        "  -i, --info              print target info (non-intrusive) and exit\n"
        "\n"
        "Options:\n"
        "  -t, --timeout MS        remote-call timeout in milliseconds (default: 5000)\n"
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        "  -T, --cloned-thread     use clone()-based injection (x86_64 only)\n"
#endif
        "  -V, --version           print version and exit\n"
        "  -h, --help              print this help and exit\n",
        prog);
}

static void print_version(void)
{
    printf("injector %s (ABI %u)\n", injector_version_string(), injector_abi_version());
}

static int cmd_info(pid_t pid)
{
    injector_target_info_t info;
    int rv = injector_target_info(pid, &info);
    if (rv != 0) {
        fprintf(stderr, "injector_target_info: %s\n", injector_last_error(NULL));
        return 1;
    }
    printf("pid:            %d\n", (int)info.pid);
    printf("alive:          %s\n", info.alive ? "yes" : "no");
    printf("ptrace_allowed: %s\n", info.ptrace_allowed ? "yes (heuristic)" : "no (heuristic)");
    printf("arch:           %s\n", info.arch);
    printf("libc:           %s\n", info.libc);
    printf("exe:            %s\n", info.exe[0] ? info.exe : "(unreadable)");
    printf("comm:           %s\n", info.comm[0] ? info.comm : "(unreadable)");
    printf("cwd:            %s\n", info.cwd[0] ? info.cwd : "(unreadable)");
    printf("root:           %s\n", info.root[0] ? info.root : "(unreadable)");
    return 0;
}

static int cmd_run(pid_t pid, const char *spec, unsigned timeout_ms,
                   const intptr_t *run_args, int run_argc,
                   injector_delivery_t delivery)
{
    char buf[4096];
    const char *colon = strchr(spec, ':');
    if (colon == NULL) {
        fprintf(stderr, "error: --run expects LIB:SYMBOL (missing ':')\n");
        return 1;
    }
    size_t liblen = (size_t)(colon - spec);
    if (liblen == 0 || liblen >= sizeof(buf)) {
        fprintf(stderr, "error: library path too long or empty\n");
        return 1;
    }
    memcpy(buf, spec, liblen);
    buf[liblen] = '\0';
    const char *symbol = colon + 1;
    if (*symbol == '\0') {
        fprintf(stderr, "error: symbol name is empty\n");
        return 1;
    }

    injector_opts_t opts = INJECTOR_OPTS_INIT;
    opts.call_timeout_ms = timeout_ms;
    opts.delivery = delivery;
    injector_result_t r;
    int rv = injector_run(pid, buf, symbol,
                          run_argc > 0 ? run_args : NULL, run_argc,
                          &opts, &r);
    if (rv != 0) {
        fprintf(stderr, "injector_run failed (rc=%d): %s\n", rv, r.errmsg);
        return 1;
    }
    printf("%" PRIdPTR "\n", r.retval);
    return 0;
}

int main(int argc, char **argv)
{
    pid_t pid = -1;
    unsigned timeout_ms = 5000;
    int do_info = 0;
    const char *run_spec = NULL;
    intptr_t run_args[INJECTOR_MAX_INVOKE_ARGS];
    int run_argc = 0;
    injector_delivery_t delivery = INJECTOR_DELIVERY_AUTO;
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    int cloned_thread = 0;
#endif

    static struct option long_opts[] = {
        {"pid",            required_argument, NULL, 'p'},
        {"name",           required_argument, NULL, 'n'},
        {"run",            required_argument, NULL, 'r'},
        {"delivery",       required_argument, NULL, 'd'},
        {"arg",            required_argument, NULL, 'a'},
        {"info",           no_argument,       NULL, 'i'},
        {"timeout",        required_argument, NULL, 't'},
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        {"cloned-thread",  no_argument,       NULL, 'T'},
#endif
        {"version",        no_argument,       NULL, 'V'},
        {"help",           no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    const char *optstring = "p:n:r:a:d:it:TVh";
#else
    const char *optstring = "p:n:r:a:d:it:Vh";
#endif

    int opt;
    while ((opt = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': {
            char *endptr;
            long v = strtol(optarg, &endptr, 10);
            if (v <= 0 || *endptr != '\0') {
                fprintf(stderr, "invalid process id: %s\n", optarg);
                return 1;
            }
            pid = (pid_t)v;
            break;
        }
        case 'n':
            pid = injector_find_process(optarg);
            if (pid <= 0) {
                fprintf(stderr, "could not find process: %s\n", optarg);
                return 1;
            }
            fprintf(stderr, "found \"%s\" at pid %d\n", optarg, (int)pid);
            break;
        case 'r':
            run_spec = optarg;
            break;
        case 'd':
            if (strcmp(optarg, "auto") == 0) delivery = INJECTOR_DELIVERY_AUTO;
            else if (strcmp(optarg, "nonstop") == 0) delivery = INJECTOR_DELIVERY_NONSTOP;
            else if (strcmp(optarg, "ptrace") == 0) delivery = INJECTOR_DELIVERY_PTRACE;
            else { fprintf(stderr, "invalid --delivery: %s (auto|nonstop|ptrace)\n", optarg); return 1; }
            break;
        case 'a': {
            if (run_argc >= INJECTOR_MAX_INVOKE_ARGS) {
                fprintf(stderr, "too many --arg values (max %d)\n", INJECTOR_MAX_INVOKE_ARGS);
                return 1;
            }
            char *endptr;
            run_args[run_argc++] = (intptr_t)strtoimax(optarg, &endptr, 0);
            if (*endptr != '\0') {
                fprintf(stderr, "invalid --arg value: %s\n", optarg);
                return 1;
            }
            break;
        }
        case 'i':
            do_info = 1;
            break;
        case 't': {
            char *endptr;
            long v = strtol(optarg, &endptr, 10);
            if (v <= 0 || *endptr != '\0') {
                fprintf(stderr, "invalid timeout: %s\n", optarg);
                return 1;
            }
            timeout_ms = (unsigned)v;
            break;
        }
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        case 'T':
            cloned_thread = 1;
            break;
#endif
        case 'V':
            print_version();
            return 0;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (pid <= 0) {
        fprintf(stderr, "error: --pid or --name is required\n");
        print_usage(argv[0]);
        return 1;
    }

    if (do_info) {
        return cmd_info(pid);
    }

    if (run_spec != NULL) {
        return cmd_run(pid, run_spec, timeout_ms, run_args, run_argc, delivery);
    }

    if (optind >= argc) {
        fprintf(stderr, "error: no libraries to inject\n");
        print_usage(argv[0]);
        return 1;
    }

    injector_t *injector;
    injector_opts_t opts = INJECTOR_OPTS_INIT;
    opts.call_timeout_ms = timeout_ms;
    if (injector_attach_with_opts(&injector, pid, &opts) != 0) {
        fprintf(stderr, "attach failed: %s\n", injector_last_error(NULL));
        return 1;
    }

    int rv = 0;
    for (int i = optind; i < argc; i++) {
        const char *libname = argv[i];
#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
        if (cloned_thread) {
            if (injector_inject_in_cloned_thread(injector, libname, NULL) == 0) {
                printf("\"%s\" injected (cloned thread)\n", libname);
            } else {
                fprintf(stderr, "could not inject \"%s\": %s\n", libname, injector_last_error(injector));
                rv = 1;
            }
            continue;
        }
#endif
        if (injector_inject(injector, libname, NULL) == 0) {
            printf("\"%s\" injected\n", libname);
        } else {
            fprintf(stderr, "could not inject \"%s\": %s\n", libname, injector_last_error(injector));
            rv = 1;
        }
    }
    injector_detach(injector);
    return rv;
}
