# Injector

[![Static Badge](https://img.shields.io/badge/docs-API_reference-blue)](http://www.jiubao.org/injector/injector_8h.html)

**Library for injecting a shared library into a Linux process**

This is an active fork maintained by AlanFokCo for production use. It extends
the original [kubo/injector](https://github.com/kubo/injector) with a
production-grade C API: bounded ptrace-based remote calls with timeouts,
per-handle error storage, non-intrusive target introspection, memory
read/write, module listing, and a one-shot `injector_run` helper. The shared
library carries SONAME `libinjector.so.1` and installs a pkg-config file.

## Linux

> [!WARNING]  
> The original ptrace-based inject path interrupts the target process. The
> bounded-call APIs (`injector_invoke`/`injector_run`) restore the target's
> original state on timeout, but a carelessly written entry method can still
> stop or crash the target. See [Production contract](#production-contract)
> and [Caveats](#caveats).

I was inspired by [`linux-inject`][] and the basic idea came from it.
However the way to call `__libc_dlopen_mode` in `libc.so.6` is
thoroughly different.

* `linux-inject` writes about 80 bytes of code to the target process
  on x86_64. This writes only 4 ~ 16 bytes.
* `linux-inject` writes code at the firstly found executable region
  of memory, which may be referred by other threads. This writes it
  at [the entry point of `libc.so.6`][libc_main], which will be referred by
  nobody unless the libc itself is executed as a program.

[libc_main]: https://sourceware.org/git/?p=glibc.git;a=blob;f=csu/version.c;h=8c0ed79c01223e1f12b54d19f90b5e5b7dd78d27;hb=c804cd1c00adde061ca51711f63068c103e94eef#l67

# Production contract

This fork is intended for production use. The contract below governs the
bounded-call APIs (`injector_invoke`, `injector_run`, and the granular
`injector_attach_with_opts` + `injector_inject` flow).

**Failure isolation.** When using `injector_invoke`/`injector_run` (M2 will
make this the default non-stop path; M1 uses bounded ptrace), an injected
entry method that *fails* — returns an error code, throws a caught exception,
longjmps, pthread_exits, or leaves a lock held — is confined to the injected
thread and does not affect the target's main threads. The entry method MUST
be `extern "C"`, catch its own C++ exceptions, and convert failures to return
codes. An *uncaught* exception, `SIGSEGV`, or `SIGABRT` is a crash, not a
"failure" — it will terminate the target process (not isolated). Write the
entry defensively.

**Bounded timeout.** Remote calls have a configurable `call_timeout_ms`
(default 5000 ms, set via `injector_opts_t`). On timeout, the target's
original state is restored and the call returns `INJERR_TIMEOUT`. With
`INJECTOR_TIMEOUT_KILL_THREAD` (M3), the injected thread is terminated;
with `INJECTOR_TIMEOUT_LEAVE` (the default) it is left in place after
state restoration.

**ptrace permission.** The injector needs ptrace access to the target: run
as root, or grant `CAP_SYS_PTRACE`, or set `kernel.yama.ptrace_scope=0` for
non-parent targets. In containers, pass `--cap-add=SYS_PTRACE` (and a
sufficient kernel version — see [Caveats](#caveats)).

**Per-handle errors.** Use `injector_last_error(inj)` to read a handle's
last error, or the `errmsg` field of `injector_result_t` returned from
`injector_run`. `injector_error()` is deprecated — it reads a thread-local
fallback intended only for the attach-failure case where no handle exists.

**Thread safety.** An `injector_t` handle is not safe for concurrent use
from multiple threads. Use a handle from a single thread, or serialize
access per handle. Different handles targeting different processes may be
used concurrently from different threads.

# Compilation

## Linux

```shell
$ git clone https://github.com/kubo/injector.git
$ cd injector
$ make
```

The `make` command creates:

| filename | - |
|---|---|
|`src/linux/libinjector.a`  |a static library|
|`src/linux/libinjector.so` |a shared library (SONAME `libinjector.so.1`)|
|`cmd/injector`             |a command line program linked with the static library|

## Installation

```shell
$ make            # build first
$ make install    # default prefix /usr/local
```

`make install` installs:

| destination | - |
|---|---|
|`<PREFIX>/include/injector.h`            |public header|
|`<PREFIX>/lib/libinjector.so.1`         |versioned shared library (SONAME)|
|`<PREFIX>/lib/libinjector.so`           |dev symlink|
|`<PREFIX>/lib/pkgconfig/libinjector.pc` |pkg-config file|

Override the install prefix with `PREFIX=` and stage into a root with
`DESTDIR=`:

```shell
$ make install PREFIX=/opt/injector DESTDIR=/tmp/stage
```

Link against the installed library with pkg-config:

```shell
$ cc -o myapp myapp.c $(pkg-config --cflags --libs libinjector)
```

`pkg-config --libs libinjector` yields `-linjector`; `--cflags` adds the
include path when the header is outside the default search path.

The ABI version is available at runtime via `injector_abi_version()` and
matches the `INJECTOR_ABI_VERSION` compile-time macro.

# Usage

## C API

The API is split into three tiers. Tier 1 is the simplest one-shot path;
Tier 2 gives granular control over an attached handle; Tier 3 is
non-intrusive introspection that never ptrace-attaches.

### Tier 1 — One-shot

`injector_run` attaches with options, injects a library, resolves a
no-argument symbol returning an integer, calls it, captures the result, and
detaches — all in one call.

```c
#include <injector.h>
#include <stdio.h>

int main(void) {
    injector_result_t result;
    /* attach + inject + call + detach. NULL opts => defaults. */
    int rc = injector_run(1234, "/path/to/libprobe.so", "entry", NULL, &result);
    if (rc != 0) {
        /* result.errmsg is filled on failure. */
        fprintf(stderr, "injector_run failed (rc=%d): %s\n", rc, result.errmsg);
        return 1;
    }
    printf("entry returned %ld\n", (long)result.retval);
    return 0;
}
```

### Tier 2 — Granular attached handle

Use `injector_attach_with_opts` with `INJECTOR_OPTS_INIT` to set timeouts
and the memory-write gate, then drive `injector_inject`/`injector_invoke`/
`injector_read_mem`/`injector_write_mem`/`injector_resolve_symbol`/
`injector_list_modules`/`injector_uninject_all` yourself, and finish with
`injector_detach`.

```c
#include <injector.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    injector_t *inj;
    injector_opts_t opts = INJECTOR_OPTS_INIT;
    opts.call_timeout_ms = 2000;   /* 2s remote-call budget */
    opts.enable_write_mem = 1;     /* allow injector_write_mem */

    if (injector_attach_with_opts(&inj, 1234, &opts) != 0) {
        /* no handle yet; use the thread-local fallback here. */
        fprintf(stderr, "attach: %s\n", injector_error());
        return 1;
    }

    void *handle = NULL;
    if (injector_inject(inj, "/path/to/libprobe.so", &handle) != 0) {
        fprintf(stderr, "inject: %s\n", injector_last_error(inj));
        injector_detach(inj);
        return 1;
    }

    injector_result_t result;
    if (injector_invoke(inj, "/path/to/libprobe.so", "entry", &result) != 0) {
        fprintf(stderr, "invoke: %s\n", result.errmsg);
    } else {
        printf("entry returned %ld\n", (long)result.retval);
    }

    /* resolve and read a remote symbol */
    uintptr_t addr = 0;
    if (injector_resolve_symbol(inj, NULL, "g_counter", &addr) == 0) {
        long val = 0;
        if (injector_read_mem(inj, addr, &val, sizeof(val)) == 0) {
            printf("g_counter = %ld\n", val);
        }
    }

    /* enumerate loaded modules (non-intrusive) */
    long n = injector_list_modules(inj, NULL, 0);  /* count only */
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

These never ptrace-attach and never execute code in the target. Safe to call
before deciding whether to inject.

```c
#include <injector.h>
#include <stdio.h>

int main(void) {
    injector_target_info_t info;
    if (injector_target_info(1234, &info) != 0) {
        fprintf(stderr, "target_info failed\n");
        return 1;
    }
    printf("pid=%d alive=%d arch=%s libc=%s exe=%s\n",
           info.pid, info.alive, info.arch, info.libc, info.exe);

    if (!injector_can_attach(1234)) {
        fprintf(stderr, "ptrace attach unlikely (check YAMA scope / caps)\n");
    }

    pid_t pid = injector_find_process("mysvc");
    if (pid > 0) {
        printf("found mysvc at pid %d\n", (int)pid);
    }
    return 0;
}
```

### Bindings and link flags

Cgo and other FFI bindings should call `injector_library_init()` once at
startup (idempotent, currently near-no-op, reserved for future use) and
`injector_library_deinit()` at shutdown. Link with
`pkg-config --libs libinjector` (`-linjector`); the versioned SONAME is
`libinjector.so.1`.

### Legacy attach path

The original `injector_attach` + `injector_inject` + `injector_uninject` +
`injector_detach` sequence is still supported. `injector_error()` (the
thread-local fallback) is deprecated in favor of `injector_last_error(inj)`.

## Command line program

See [`Usage` section and `Sample` section in linux-inject][`inject`] and substitute
`inject` with `injector` in the page.

# Tested Architectures

## Linux

x86_64:

injector process \ target process | x86_64 | i386 | x32(*1)
---|---|---|---
**x86_64** | :smiley: success(*2) | :smiley: success(*3) | :smiley: success(*6)
**i386**   | :skull:  failure(*4) | :smiley: success(*3) | :skull:  failure(*5)
**x32**(*1) | :skull:  failure(*4) | :smiley: success(*6) | :skull:  failure(*5)

*1: [x32 ABI](https://en.wikipedia.org/wiki/X32_ABI)  
*2: tested on github actions with both glibc and musl.  
*3: tested on github actions with glibc.  
*4: failure with `64-bit target process isn't supported by 32-bit process`.  
*5: failure with `x32-ABI target process is supported only by x86_64`.  
*6: tested on a local machine. `CONFIG_X86_X32` isn't enabled in github actions.  

ARM:

injector process \ target process | arm64 | armhf | armel
---|---|---|---
**arm64** | :smiley: success     | :smiley: success | :smiley: success
**armhf** | :skull:  failure(*1) | :smiley: success | :smiley: success
**armel** | :skull:  failure(*1) | :smiley: success | :smiley: success

*1: failure with `64-bit target process isn't supported by 32-bit process`.  

MIPS:

injector process \ target process | mips64el | mipsel (n32) | mipsel (o32)
---|---|---|---
**mips64el** | :smiley: success (*1)    | :smiley: success (*1) | :smiley: success (*1)
**mipsel (n32)** | :skull:  failure(*2) | :smiley: success (*1) | :smiley: success (*1)
**mipsel (o32)** | :skull:  failure(*2) | :smiley: success (*1) | :smiley: success (*1)

*1: tested on [debian 11 mips64el](https://www.debian.org/releases/bullseye/mips64el/ch02s01.en.html#idm271) on [QEMU](https://www.qemu.org/).  
*2: failure with `64-bit target process isn't supported by 32-bit process`.  

PowerPC:

* **ppc64le** (tested on [alpine 3.16.2 ppc64le](https://dl-cdn.alpinelinux.org/alpine/v3.16/releases/ppc64le/) on [QEMU](https://www.qemu.org/))
* **powerpc (big endian)** (tested on [ubuntu 16.04 powerpc](https://old-releases.ubuntu.com/releases/xenial/) on [QEMU](https://www.qemu.org/))

RISC-V:

* **riscv64** (tested on [Ubuntu 22.04.1 riscv64 on QEMU](https://wiki.ubuntu.com/RISC-V#Booting_with_QEMU))

# Caveats

**The following restrictions are only on Linux.**

Injector doesn't work where `ptrace()` is disallowed.

* Non-children processes (See [Caveat about `ptrace()`][])
* Docker containers on docker version < 19.03 or linux kernel version < 4.8. You need to pass [`--cap-add=SYS_PTRACE`](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)
to `docker run` to allow it in the environments.
* Linux inside of UserLAnd (Android App) (See [here](https://github.com/kubo/injector/issues/17#issuecomment-1113990177))

Injector calls functions inside of a target process interrupted by `ptrace()`.
If the target process is interrupted while holding a non-reentrant lock and
injector calls a function requiring the same lock, the process stops forever.
If the lock type is reentrant, the status guarded by the lock may become inconsistent.
As far as I checked, `dlopen()` internally calls `malloc()` requiring non-reentrant
locks. `dlopen()` also uses a reentrant lock to guard information about loaded files.

On Linux x86_64 `injector_inject_in_cloned_thread` in place of `injector_inject`
may be a solution of the locking issue. It calls `dlopen()` in a thread created by
[`clone()`]. Note that no wonder there are unexpected pitfalls because some resources
allocated in [`pthread_create()`] lack in the `clone()`-ed thread. Use it at
your own risk.

The bounded-call APIs (`injector_invoke`/`injector_run`) restore target state on
timeout, but the lock-reentrancy caveat above still applies to whatever the
injected entry method does. Keep entry methods short and async-signal-safe where
possible.

# License

Files under [`include`][] and [`src`][] are licensed under LGPL 2.1 or later.  
Files under [`cmd`][] are licensed under GPL 2 or later.

[`linux-inject`]: https://github.com/gaffe23/linux-inject
[Caveat about `ptrace()`]: https://github.com/gaffe23/linux-inject#caveat-about-ptrace
[`inject`]: https://github.com/gaffe23/linux-inject#usage
[`clone()`]: https://man7.org/linux/man-pages/man2/clone.2.html
[`cmd`]: cmd
[`include`]: include
[`pthread_create()`]: https://man7.org/linux/man-pages/man3/pthread_create.3.html
[`src`]: src