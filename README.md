# injector

[![License: LGPL-2.1+](https://img.shields.io/badge/license-LGPL--2.1%2B%20%2F%20GPL--2%2B-blue.svg)](./LICENSE_LGPL.txt)
[![Language: C](https://img.shields.io/badge/language-C-00599C.svg)](#)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-FCC624.svg?logo=linux&logoColor=black)](#)
[![Version: 1.0.0](https://img.shields.io/badge/version-1.0.0-4CAF50.svg)](#)
[![API reference](https://img.shields.io/badge/docs-API_reference-blue.svg)](http://www.jiubao.org/injector/injector_8h.html)

**A production-grade library for injecting a shared library into a running Linux process.**

This is an active fork of [`kubo/injector`](https://github.com/kubo/injector),
hardened for production use and FFI consumption (Go bindings, etc.). It keeps
the original minimal-overhead ptrace technique and adds a clean, layered C
API: bounded remote calls with timeouts and guaranteed state restoration,
per-handle error reporting, non-intrusive target introspection, memory
read/write, module listing, and a one-shot `injector_run` helper. The shared
library carries SONAME `libinjector.so.1` and ships a pkg-config file.

---

## Features

- **One-shot injection** — `injector_run(pid, lib, "entry", opts, &result)`
  attaches, injects, calls a no-arg entry symbol, captures the return value,
  and detaches in a single call.
- **Bounded remote calls** — every remote call has a configurable timeout
  (`call_timeout_ms`, default 5 s). On timeout the target's original registers
  and code are restored and the call returns `INJERR_TIMEOUT`; the target is
  never left hijacked.
- **Failure isolation** — an injected entry method that *fails* (returns an
  error, throws a caught exception, `pthread_exit`s, leaves a lock held) is
  confined to the injected thread and does not corrupt the target's main
  threads. See [Production contract](#production-contract).
- **Per-handle, thread-safe errors** — each `injector_t` carries its own
  error buffer; concurrent operations on different targets from different
  threads don't clobber each other's diagnostics.
- **Non-intrusive introspection** — `injector_target_info` / `injector_can_attach`
  read `/proc` to report a target's arch, libc, exe, cwd, root, and ptrace
  feasibility *without attaching*.
- **Target memory I/O** — `injector_read_mem` / `injector_write_mem` (gated)
  / `injector_resolve_symbol` expose the target's address space to the caller.
- **Module management** — `injector_list_modules` enumerates loaded libraries
  (non-intrusive); `injector_uninject_all` tears down everything a handle
  injected.
- **Fast, portable transport** — bulk memory transfer via `process_vm_readv` /
  `process_vm_writev` with a ptrace word-at-a-time fallback for kernels or
  pages that reject the vector path.
- **Signal-free** — the library installs no signal handlers and uses no
  `SIGALRM`; it is safe to embed in a Go-runtime (cgo) host.
- **Packaged** — `make install`, versioned SONAME, `libinjector.pc`,
  `injector_abi_version()`, and a unit + integration test suite (`make unit`,
  `make check`).

## Table of contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Production contract](#production-contract)
- [C API](#c-api)
- [Command line program](#command-line-program)
- [Installation](#installation)
- [Tested architectures](#tested-architectures)
- [Caveats](#caveats)
- [Roadmap](#roadmap)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Quick start

```shell
$ git clone https://github.com/AlanFokCo/injector.git
$ cd injector
$ make            # builds libinjector.{a,so} and cmd/injector
$ make check      # integration tests
$ make unit       # unit tests
```

Inject a library and call its `entry` symbol in one line:

```c
#include <injector.h>
#include <stdio.h>

int main(void) {
    injector_result_t r;
    int rc = injector_run(1234, "/path/to/libprobe.so", "entry", NULL, &r);
    if (rc != 0) { fprintf(stderr, "failed (rc=%d): %s\n", rc, r.errmsg); return 1; }
    printf("entry returned %ld\n", (long)r.retval);
    return 0;
}
```

```shell
$ cc -o probe probe.c $(pkg-config --cflags --libs libinjector)
```

## How it works

`injector` was inspired by [`linux-inject`][] and shares its basic idea, but
the way `__libc_dlopen_mode` / `dlopen` is invoked in the target's `libc.so.6`
is thoroughly different:

- `linux-inject` writes ~80 bytes of code to the target on x86_64; this
  writes only 4–16 bytes.
- `linux-inject` writes code at the first executable region it finds, which
  other threads may be using. This writes at
  [the entry point of `libc.so.6`][libc_main], which is referenced by nobody
  unless libc is executed as a program.

Symbols (`dlopen`, `dlsym`, `dlclose`, `clone`, …) are resolved from the
target's on-disk libc ELF in a single pass; remote calls are emitted as a
tiny architecture-specific snippet (`syscall`/`call` + `int3`/`brk`) at the
libc entry, executed under ptrace, and the original bytes are restored on
every exit path.

[libc_main]: https://sourceware.org/git/?p=glibc.git;a=blob;f=csu/version.c;h=8c0ed79c01223e1f12b54d19f90b5e5b7dd78d27;hb=c804cd1c00adde061ca51711f63068c103e94eef#l67

## Production contract

This fork targets production use. The contract below governs the bounded-call
APIs (`injector_invoke`, `injector_run`, and the granular
`injector_attach_with_opts` + `injector_inject` flow).

> [!WARNING]
> The ptrace inject path interrupts the target. Bounded APIs restore the
> target's state on timeout/failure, but a carelessly written entry method
> can still stop or crash the target. Read this section and [Caveats](#caveats).

**Failure isolation.** An injected entry method that *fails* — returns an
error code, throws a caught exception, `longjmp`s, `pthread_exit`s, or leaves
a lock held — is confined to the injected thread and does not affect the
target's main threads. The entry method MUST be `extern "C"`, must catch its
own C++ exceptions, and must convert failures to return codes. An *uncaught*
exception, `SIGSEGV`, or `SIGABRT` is a **crash**, not a "failure" — it will
terminate the target process (not isolated). Write entry methods defensively.

**Bounded timeout.** Remote calls have a configurable `call_timeout_ms`
(default 5000 ms, set via `injector_opts_t`). On timeout the target's original
state is restored and the call returns `INJERR_TIMEOUT`. With
`INJECTOR_TIMEOUT_KILL_THREAD` (roadmap: M3) the injected thread is terminated;
with `INJECTOR_TIMEOUT_LEAVE` (the default) it is left in place after state
restoration.

**ptrace permission.** The injector needs ptrace access to the target: run as
root, grant `CAP_SYS_PTRACE`, or set `kernel.yama.ptrace_scope=0` for
non-parent targets. In containers, pass `--cap-add=SYS_PTRACE` (and a
sufficient kernel version — see [Caveats](#caveats)).

**Per-handle errors.** Use `injector_last_error(inj)` to read a handle's last
error, or the `errmsg` field of `injector_result_t` returned from
`injector_run`. `injector_error()` is deprecated — it reads a thread-local
fallback intended only for the attach-failure case where no handle exists.

**Thread safety.** An `injector_t` handle is not safe for concurrent use from
multiple threads. Use a handle from a single thread, or serialize access per
handle. Different handles targeting different processes may be used
concurrently from different threads.

## C API

The API is layered. Tier 1 is the simplest one-shot path; Tier 2 gives
granular control over an attached handle; Tier 3 is non-intrusive
introspection that never ptrace-attaches.

| Tier | Entry point | Use when |
|---|---|---|
| 1 — one-shot | `injector_run` | You want attach + inject + call + detach in one call |
| 2 — granular | `injector_attach_with_opts` → `injector_inject` / `injector_invoke` / `injector_read_mem` / `injector_write_mem` / `injector_resolve_symbol` / `injector_list_modules` / `injector_uninject_all` → `injector_detach` | You need multi-step control or to read/write target memory |
| 3 — introspection | `injector_target_info` / `injector_can_attach` / `injector_find_process` | You want to inspect a target before deciding to inject (no attach) |

### Tier 1 — One-shot

```c
#include <injector.h>
#include <stdio.h>

int main(void) {
    injector_result_t r;
    /* attach + inject + call + detach. NULL opts => defaults. */
    int rc = injector_run(1234, "/path/to/libprobe.so", "entry", NULL, &r);
    if (rc != 0) { fprintf(stderr, "injector_run (rc=%d): %s\n", rc, r.errmsg); return 1; }
    printf("entry returned %ld\n", (long)r.retval);
    return 0;
}
```

### Tier 2 — Granular attached handle

```c
#include <injector.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    injector_t *inj;
    injector_opts_t opts = INJECTOR_OPTS_INIT;
    opts.call_timeout_ms = 2000;   /* 2 s remote-call budget */
    opts.enable_write_mem = 1;     /* allow injector_write_mem */

    if (injector_attach_with_opts(&inj, 1234, &opts) != 0) {
        fprintf(stderr, "attach: %s\n", injector_error());   /* no handle yet */
        return 1;
    }

    void *handle = NULL;
    if (injector_inject(inj, "/path/to/libprobe.so", &handle) != 0) {
        fprintf(stderr, "inject: %s\n", injector_last_error(inj));
        injector_detach(inj);
        return 1;
    }

    injector_result_t r;
    if (injector_invoke(inj, "/path/to/libprobe.so", "entry", &r) == 0)
        printf("entry returned %ld\n", (long)r.retval);

    /* resolve and read a remote global */
    uintptr_t addr = 0;
    if (injector_resolve_symbol(inj, NULL, "g_counter", &addr) == 0) {
        long val = 0;
        if (injector_read_mem(inj, addr, &val, sizeof(val)) == 0)
            printf("g_counter = %ld\n", val);
    }

    /* enumerate loaded modules (non-intrusive) */
    long n = injector_list_modules(inj, NULL, 0);
    if (n >= 0) {
        injector_module_t mods[64];
        injector_list_modules(inj, mods, n < 64 ? (size_t)n : 64);
    }

    injector_uninject_all(inj);   /* dlclose everything this handle injected */
    injector_detach(inj);
    return 0;
}
```

### Tier 3 — Non-intrusive introspection

These never ptrace-attach and never execute code in the target — safe to call
before deciding whether to inject.

```c
#include <injector.h>
#include <stdio.h>

int main(void) {
    injector_target_info_t info;
    if (injector_target_info(1234, &info) != 0) { fprintf(stderr, "target_info failed\n"); return 1; }
    printf("pid=%d alive=%d arch=%s libc=%s exe=%s\n",
           info.pid, info.alive, info.arch, info.libc, info.exe);

    if (!injector_can_attach(1234))
        fprintf(stderr, "ptrace attach unlikely (check YAMA scope / caps)\n");

    pid_t pid = injector_find_process("mysvc");
    if (pid > 0) printf("found mysvc at pid %d\n", (int)pid);
    return 0;
}
```

### Bindings, link flags, ABI

Cgo and other FFI bindings should call `injector_library_init()` once at
startup (idempotent; currently near-no-op, reserved for future use) and
`injector_library_deinit()` at shutdown. Link with
`pkg-config --libs libinjector` (`-linjector`); the versioned SONAME is
`libinjector.so.1`. The ABI version is available at runtime via
`injector_abi_version()` and matches the `INJECTOR_ABI_VERSION` compile-time
macro.

### Legacy attach path

The original `injector_attach` + `injector_inject` + `injector_uninject` +
`injector_detach` sequence is still supported. `injector_error()` (the
thread-local fallback) is deprecated in favor of `injector_last_error(inj)`.

## Command line program

`cmd/injector` is a thin CLI around the library:

```shell
$ ./cmd/injector -p <pid> /path/to/lib.so           # inject by pid
$ ./cmd/injector -n <process-name> /path/to/lib.so  # inject by name (via injector_find_process)
```

For general usage and samples, see the [`Usage` section of linux-inject][`inject`]
and substitute `inject` with `injector`.

## Installation

```shell
$ make            # build first
$ make install    # default prefix /usr/local
```

`make install` installs:

| destination | description |
|---|---|
| `<PREFIX>/include/injector.h` | public header |
| `<PREFIX>/lib/libinjector.so.1` | versioned shared library (SONAME) |
| `<PREFIX>/lib/libinjector.so` | dev symlink |
| `<PREFIX>/lib/libinjector.a` | static library |
| `<PREFIX>/lib/pkgconfig/libinjector.pc` | pkg-config file |

Override the install prefix with `PREFIX=` and stage into a root with
`DESTDIR=`:

```shell
$ make install PREFIX=/opt/injector DESTDIR=/tmp/stage
```

Link against the installed library with pkg-config:

```shell
$ cc -o myapp myapp.c $(pkg-config --cflags --libs libinjector)
```

## Tested architectures

### Linux — x86_64

| injector \ target | x86_64 | i386 | x32(*1) |
|---|---|---|---|
| **x86_64** | :smiley: success(*2) | :smiley: success(*3) | :smiley: success(*6) |
| **i386**   | :skull: failure(*4) | :smiley: success(*3) | :skull: failure(*5) |
| **x32**(*1) | :skull: failure(*4) | :smiley: success(*6) | :skull: failure(*5) |

*1: [x32 ABI](https://en.wikipedia.org/wiki/X32_ABI)
*2: tested on GitHub Actions with both glibc and musl.
*3: tested on GitHub Actions with glibc.
*4: failure with `64-bit target process isn't supported by 32-bit process`.
*5: failure with `x32-ABI target process is supported only by x86_64`.
*6: tested on a local machine. `CONFIG_X86_X32` isn't enabled in GitHub Actions.

### ARM

| injector \ target | arm64 | armhf | armel |
|---|---|---|---|
| **arm64** | :smiley: success | :smiley: success | :smiley: success |
| **armhf** | :skull: failure(*1) | :smiley: success | :smiley: success |
| **armel** | :skull: failure(*1) | :smiley: success | :smiley: success |

*1: failure with `64-bit target process isn't supported by 32-bit process`.

### MIPS

| injector \ target | mips64el | mipsel (n32) | mipsel (o32) |
|---|---|---|---|
| **mips64el** | :smiley: success (*1) | :smiley: success (*1) | :smiley: success (*1) |
| **mipsel (n32)** | :skull: failure(*2) | :smiley: success (*1) | :smiley: success (*1) |
| **mipsel (o32)** | :skull: failure(*2) | :smiley: success (*1) | :smiley: success (*1) |

*1: tested on [debian 11 mips64el](https://www.debian.org/releases/bullseye/mips64el/ch02s01.en.html#idm271) on [QEMU](https://www.qemu.org/).
*2: failure with `64-bit target process isn't supported by 32-bit process`.

### PowerPC

- **ppc64le** (tested on [alpine 3.16.2 ppc64le](https://dl-cdn.alpinelinux.org/alpine/v3.16/releases/ppc64le/) on [QEMU](https://www.qemu.org/))
- **powerpc (big endian)** (tested on [ubuntu 16.04 powerpc](https://old-releases.ubuntu.com/releases/xenial/) on [QEMU](https://www.qemu.org/))

### RISC-V

- **riscv64** (tested on [Ubuntu 22.04.1 riscv64 on QEMU](https://wiki.ubuntu.com/RISC-V#Booting_with_QEMU))

## Caveats

> The following restrictions apply on Linux.

`injector` does not work where `ptrace()` is disallowed:

- Non-children processes (see [Caveat about `ptrace()`][]).
- Docker containers on docker < 19.03 or kernel < 4.8. Pass
  [`--cap-add=SYS_PTRACE`](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)
  to `docker run`.
- Linux inside UserLAnd (Android app) (see [issue #17](https://github.com/kubo/injector/issues/17#issuecomment-1113990177)).

`injector` calls functions inside a target process interrupted by `ptrace()`.
If the target is interrupted while holding a non-reentrant lock and `injector`
calls a function requiring the same lock, the process stops forever. If the
lock is reentrant, state guarded by it may become inconsistent. As far as
observed, `dlopen()` internally calls `malloc()` (non-reentrant lock) and also
uses a reentrant lock to guard loaded-file information.

On Linux x86_64, `injector_inject_in_cloned_thread` in place of
`injector_inject` may mitigate the locking issue — it calls `dlopen()` in a
thread created by [`clone()`]. Note that some resources allocated by
[`pthread_create()`] are absent in the `clone()`-ed thread; use it at your own
risk.

The bounded-call APIs (`injector_invoke` / `injector_run`) restore target
state on timeout, but the lock-reentrancy caveat above still applies to
whatever the injected entry method does. Keep entry methods short and
async-signal-safe where possible.

## Roadmap

This fork is developed in milestones:

- **M1 (done)** — stability baseline: bounded timeouts with guaranteed state
  restoration, per-handle errors, `process_vm_readv`/`writev`, one-pass ELF
  resolution, `/proc` parser, target introspection, memory read/write,
  module listing, `injector_invoke`/`injector_run`, packaging, unit +
  integration tests.
- **M2** — non-stop threaded delivery: a C-blob thread entry (zero-relocation
  build gate) replaces direct ptrace `dlopen` so the target's main thread is
  not interrupted; `injector_invoke`/`run` switch to the threaded path with
  automatic ptrace fallback; timeout `LEAVE`.
- **M3** — aarch64 C-blob + `INJECTOR_TIMEOUT_KILL_THREAD` (terminate the
  injected thread via `SYS_exit` on timeout).
- **M4** — polish: CLI switches, runtime log handler, ASan/UBSan builds,
  expanded CI matrix (aarch64, musl).

## License

Files under [`include`][] and [`src`][] are licensed under **LGPL 2.1 or
later**. Files under [`cmd`][] are licensed under **GPL 2 or later**. See
[`LICENSE_LGPL.txt`](./LICENSE_LGPL.txt) and [`LICENSE_GPL.txt`](./LICENSE_GPL.txt).

## Acknowledgements

- [`kubo/injector`](https://github.com/kubo/injector) — the original project
  this fork builds on.
- [`linux-inject`][] — the inspiration for the injection technique.

[`linux-inject`]: https://github.com/gaffe23/linux-inject
[Caveat about `ptrace()`]: https://github.com/gaffe23/linux-inject#caveat-about-ptrace
[`inject`]: https://github.com/gaffe23/linux-inject#usage
[`clone()`]: https://man7.org/linux/man-pages/man2/clone.2.html
[`pthread_create()`]: https://man7.org/linux/man-pages/man3/pthread_create.3.html
[`cmd`]: cmd
[`include`]: include
[`src`]: src
