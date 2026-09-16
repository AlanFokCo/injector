# injector

[![License: LGPL-2.1+](https://img.shields.io/badge/license-LGPL--2.1%2B%20%2F%20GPL--2%2B-blue.svg)](./LICENSE_LGPL.txt)
[![Language: C](https://img.shields.io/badge/language-C-00599C.svg)](#)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-FCC624.svg?logo=linux&logoColor=black)](#)
[![Version: 1.0.0](https://img.shields.io/badge/version-1.0.0-4CAF50.svg)](#)
[![API reference](https://img.shields.io/badge/docs-API_reference-blue.svg)](http://www.jiubao.org/injector/injector_8h.html)

**Inject a shared library into a running Linux process, then call a function it exports.**

This is an active fork of [`kubo/injector`](https://github.com/kubo/injector),
hardened for production use and FFI consumption. It keeps the original
minimal-overhead ptrace technique and adds a clean, layered C API: bounded
remote calls with timeouts and guaranteed state restoration, per-handle error
reporting, non-intrusive target introspection, memory read/write, module
listing, and a one-shot `injector_run` helper. Official bindings are provided
for **Go**, **Python**, and **Rust**. The shared library carries SONAME
`libinjector.so.1` and ships a pkg-config file.

---

## Features

`injector_run(pid, lib, "entry", args, argc, opts, &result)` attaches, injects,
calls a symbol with up to `INJECTOR_MAX_INVOKE_ARGS` (6) `intptr_t` arguments,
captures the return value, and detaches. The pieces underneath are public too:
`injector_inject` / `injector_uninject` for library lifetime, `injector_invoke`
for bounded remote calls, `injector_read_mem` / `injector_write_mem` /
`injector_resolve_symbol` for the target's address space, `injector_list_modules`
and `injector_uninject_all` for bookkeeping.

Remote calls are bounded. `opts.call_timeout_ms` (default 5000 ms) sets the
budget; on expiry the target's original registers and the patched libc bytes are
put back and the call returns `INJERR_TIMEOUT`. There is one documented gap: if
the `SIGSTOP` used to re-stop the target fails, the target keeps running the
hijacked code, libc's `e_entry` stays patched, and the handle is marked
desynchronised (`handle_timeout` in `src/linux/remote_call.c`). See
[Caveats](#caveats).

Errors are per-handle. `injector_last_error(inj)` reads that handle's own buffer,
so concurrent work on different targets does not clobber diagnostics.
Introspection needs no attach either: `injector_target_info`,
`injector_can_attach` and `injector_find_process` read `/proc` and never ptrace
(`can_attach` also probes with `kill(pid, 0)` and compares `geteuid()`), so you can
judge a target before touching it.

Bulk memory transfer goes through `process_vm_readv` / `process_vm_writev`, with
a ptrace word-at-a-time fallback for kernels or pages that reject the vector
path. The library installs no signal handlers and never raises `SIGALRM`, so it
is safe to embed in a cgo host. Packaging covers `make install`, SONAME
`libinjector.so.1`, `libinjector.pc`, `injector_abi_version()`, `make unit` and
`make check`.

Two rules a caller can actually break on:

- **Handles are thread-affine.** `injector_attach` records the attaching OS
  thread's tid, and every later ptrace operation on that handle — including
  `injector_detach` — must come from that same thread. See [Thread affinity and
  handle lifetime](#thread-affinity-and-handle-lifetime).
- **x32 is not supported.** This build ships x86_64 (LP64) and i386 runtimes.
  An x32-ABI target is refused at attach with `INJERR_UNSUPPORTED_TARGET`,
  before anything is written to it.

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Production contract](#production-contract)
- [C API](#c-api)
  - [Tier 1 — One-shot](#tier-1--one-shot)
  - [Tier 2 — Granular attached handle](#tier-2--granular-attached-handle)
  - [Thread affinity and handle lifetime](#thread-affinity-and-handle-lifetime)
  - [Tier 3 — Non-intrusive introspection](#tier-3--non-intrusive-introspection)
  - [Delivery modes](#delivery-modes)
  - [Error codes](#error-codes)
  - [Other public API](#other-public-api)
  - [Link flags, ABI, and init](#link-flags-abi-and-init)
  - [Legacy attach path](#legacy-attach-path)
- [Language bindings](#language-bindings)
  - [Go](#go)
  - [Python](#python)
  - [Rust](#rust)
- [Command line program](#command-line-program)
- [Installation](#installation)
- [Tested architectures](#tested-architectures)
  - [Linux — x86_64 and i386](#linux--x86_64-and-i386)
  - [Non-x86 results are upstream's, not re-verified here](#non-x86-results-are-upstreams-not-re-verified-here)
  - [ARM](#arm)
  - [MIPS](#mips)
  - [PowerPC](#powerpc)
  - [RISC-V](#risc-v)
- [Caveats](#caveats)
  - [Never target `init`/PID 1 or other critical system processes](#never-target-initpid-1-or-other-critical-system-processes)
  - [NONSTOP delivery runs `dlopen` without TLS](#nonstop-delivery-runs-dlopen-without-tls)
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
    int rc = injector_run(1234, "/path/to/libprobe.so", "entry",
                          NULL, 0, NULL, &r);
    if (rc != 0) { fprintf(stderr, "failed (rc=%d): %s\n", rc, r.errmsg); return 1; }
    printf("entry returned %ld\n", (long)r.retval);
    return 0;
}
```

```shell
$ cc -o probe probe.c $(pkg-config --cflags --libs libinjector)
```

Choose the pid deliberately: never target PID 1, and never target a process you
cannot afford to lose. `pid <= 1` is refused outright; the rest is on you. See
[Never target `init`/PID 1 or other critical system
processes](#never-target-initpid-1-or-other-critical-system-processes).

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

Failure isolation depends on which delivery mode ran the payload. With
`INJECTOR_DELIVERY_NONSTOP`, the default on x86_64, the payload runs in a helper
task created by `clone()` inside the target, so an entry method that returns an
error code, throws and catches its own exception, `longjmp`s, `pthread_exit`s or
leaves a lock held is confined to that helper and never touches the target's own
threads. Ptrace delivery gives no such isolation, because there the entry runs on
a hijacked thread of the target itself; that is the only path on i386 and what
`-d ptrace` selects.

A crash does not kill the target under either delivery, which is worth stating
precisely because it is not what "the entry ran in the target" suggests. On the
ptrace path the target is stopped and traced, so a fatal signal raised inside the
hijacked thread becomes a signal-delivery-stop that the library sees through
`waitpid`: `injector_invoke` returns `INJERR_OTHER` with the message "The target
process unexpectedly stopped by signal 6", the thread's registers and patched code
are restored, and the target goes on running. Measured on kernel 6.8 for both
`abort()` and `SIGSEGV`, with a clean `injector_detach` afterwards. Under NONSTOP
the crash kills only the helper, and the call surfaces as `INJERR_TIMEOUT`. The
target does die if it crashes after you detach, or in a thread the library was
never driving.

That is an argument about what survives, not about what works. Write entry
methods defensively: `extern "C"`, catch your own C++ exceptions, convert
failures to return codes.

Each remote call is bounded by `opts.call_timeout_ms`, which defaults to 5000 ms.
On expiry the target's original state is restored and the call returns
`INJERR_TIMEOUT`; `opts.timeout_action` decides what happens to the stuck task.
`INJECTOR_TIMEOUT_LEAVE`, the default, re-stops the target and restores it.
`INJECTOR_TIMEOUT_KILL_THREAD` sends `SIGKILL` to the task running the hijacked
code, and the name should be read literally: Linux has no per-thread `SIGKILL`,
so one sent to a single tid takes down its whole thread group. On the ptrace path
the hijacked task is a thread of the target, so `KILL_THREAD` kills the entire
target process. Only NONSTOP delivery can kill the helper alone, because there
the stuck task is a separate process; that timeout loop lives in
`src/linux/injector.c`. `handle_timeout` in `src/linux/remote_call.c` is the
ptrace path, and it kills the target.

The injector needs ptrace access to the target: run as root, grant
`CAP_SYS_PTRACE`, or set `kernel.yama.ptrace_scope=0` for non-parent targets. In
containers pass `--cap-add=SYS_PTRACE`, and check the kernel version note in
[Caveats](#caveats).

Read a handle's error with `injector_last_error(inj)`, or from the `errmsg` field
of the `injector_result_t` that `injector_run` fills in. `injector_error()` is
deprecated: it reads a thread-local fallback meant only for the attach-failure
case, where no handle exists yet.

A handle is bound to the OS thread that attached it, which is a stronger rule
than "not reentrant". Every later ptrace operation, `injector_detach` included,
must come from that thread, and a refused cross-thread detach still frees the
handle. The full rules, the double-free hazard and the recovery path are in
[Thread affinity and handle lifetime](#thread-affinity-and-handle-lifetime).
Different handles on different processes may be driven concurrently from
different threads.

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

`injector_run(pid, path, symbol, args, argc, opts, result)` attaches, injects,
calls and detaches in one call, and is what [Quick start](#quick-start) compiles
and runs. Pass `NULL` for `opts` to get the defaults. The return code says
whether the sequence completed; `result->retval` is what your entry method
returned, and `result->errmsg` carries the failure message, so a caller that
wants the reason does not have to reach for a separate error function.

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
        /* no handle yet: NULL reads the thread-local fallback */
        fprintf(stderr, "attach: %s\n", injector_last_error(NULL));
        return 1;
    }

    void *handle = NULL;
    if (injector_inject(inj, "/path/to/libprobe.so", &handle) != 0) {
        fprintf(stderr, "inject: %s\n", injector_last_error(inj));
        injector_detach(inj);
        return 1;
    }

    injector_result_t r;
    if (injector_invoke(inj, "/path/to/libprobe.so", "entry",
                        NULL, 0, &r) == 0)
        printf("entry returned %ld\n", (long)r.retval);

    /* up to INJECTOR_MAX_INVOKE_ARGS (6) intptr_t arguments */
    intptr_t args[] = {42, 100};
    if (injector_invoke(inj, "/path/to/libprobe.so", "add_values",
                        args, 2, &r) == 0)
        printf("add_values returned %ld\n", (long)r.retval);

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

    /* dlclose everything this handle injected.
     * Refuses musl-libc targets: INJERR_UNSUPPORTED_TARGET (footnote *2). */
    injector_uninject_all(inj);
    injector_detach(inj);
    return 0;
}
```

### Thread affinity and handle lifetime

`injector_attach` records the tid of the calling OS thread as the handle's owner.
Linux pins a tracee to its tracer *thread*, so from any other thread of your
process the kernel answers `PTRACE_GETREGS`/`SETREGS`/`POKETEXT`/`DETACH` for
that target with `ESRCH`, as if it were not traced at all. Measured on Linux
6.8/x86_64: attach in thread A, then from thread B both `PTRACE_GETREGS` and
`PTRACE_DETACH` fail `ESRCH` while the target keeps reporting `State: t` and a
`TracerPid` pointing at A.

Everything below must therefore run on the attaching thread: `injector_detach`,
`injector_inject`, `injector_uninject`, `injector_uninject_all`,
`injector_call`, `injector_remote_func_addr`, `injector_remote_call`,
`injector_remote_vcall`, `injector_invoke`, `injector_run` (it attaches, invokes
and detaches, so all three legs), `injector_inject_in_cloned_thread`, and the
`PEEKTEXT`/`POKETEXT` fallback inside `injector_read_mem` /
`injector_write_mem`. A violation is refused *before* anything reaches the
target, with `INJERR_OTHER`, `errno == ESRCH`, and a message naming both tids.
The `process_vm_readv`/`writev` fast path of those two is not ptrace-scoped and
does work from another thread, which is why the refusal surfaces at the fallback
rather than at their entry point.

Two consequences to design around:

- **A refused cross-thread detach still frees the handle.** `injector_detach`
  destroys the handle whether or not the detach succeeded. Detaching that pointer
  a second time is a double free — empirically `double free or corruption
  (!prev)`, then `SIGABRT`. This is documented behaviour, not a bug to file.
  Detach a given pointer once; after a refused detach the pointer is dead, and
  the target is left stopped and traced.
- **Only the owning thread can release the target.** No ptrace request moves a
  tracee to a different tracer, so nothing done from another thread helps.
  Exiting the owning thread does release it (measured: the target returned to
  `State: S` with `TracerPid: 0`). That is the recovery path when the owner can
  no longer be used.

The Go binding takes care of this: `Attach`/`AttachWithOpts` call
`runtime.LockOSThread`, so the goroutine stays on the thread that attached
(both `Attach` and `AttachWithOpts` in `pkg/injector/injector.go`). In C, and in the Python and Rust bindings,
keeping attach and every later call on one thread is yours to arrange.

### Tier 3 — Non-intrusive introspection

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

### Delivery modes

`opts.delivery` in C, `-d/--delivery` on the command line, and `DeliveryMode` in
the Go and Rust bindings all select how the payload reaches the target.

| mode | what happens |
|---|---|
| `INJECTOR_DELIVERY_AUTO` (default) | NONSTOP on x86_64, ptrace everywhere else. |
| `INJECTOR_DELIVERY_NONSTOP` | The call runs in a helper task created inside the target with `clone()`. The target's own threads are not interrupted, and a timeout can kill just the helper. x86_64 only: elsewhere `injector_invoke` returns `INJERR_UNSUPPORTED_TARGET`. |
| `INJECTOR_DELIVERY_PTRACE` | The stopped thread's registers are saved, pointed at an injected snippet, and restored afterwards. The entry runs on a thread of the target, so there is no failure isolation. Works on every supported architecture. |

The CLI spells out the trade-off in its own `--help`: nonstop `dlopen` runs in a
`clone()` with no TLS, so it can fault inside `ld.so`; use `-d ptrace` for CUDA
and other heavy targets.

### Error codes

All public entry points return one of these; `injector_last_error(inj)` (or
`injector_result_t.errmsg`) carries the detail.

| code | value | when you get it |
|---|---|---|
| `INJERR_SUCCESS` | 0 | The only non-negative code. |
| `INJERR_OTHER` | -1 | Unclassified — read the message. Also covers two refusals that leave the target untouched: no FP-state slot free (`errno` is `EMFILE`), and a ptrace request from a thread other than the one that attached (`errno` is `ESRCH`). |
| `INJERR_NO_MEMORY` | -2 | A local allocation failed. |
| `INJERR_NO_PROCESS` | -3 | The pid is invalid, does not exist, or is one the library refuses to touch at all — notably pid 1 / `init`. |
| `INJERR_NO_LIBRARY` | -4 | The library to inject, or libc in the target, could not be found or opened. |
| `INJERR_ERROR_IN_TARGET` | -5 | The injected code failed inside the target; `dlopen` returning NULL is the usual cause. The message carries the target-side reason when there is one. |
| `INJERR_FILE_NOT_FOUND` | -6 | A path could not be opened, or was too long to fit the target's data page. |
| `INJERR_INVALID_MEMORY_AREA` | -7 | `ptrace(2)` reported `EFAULT`: the address is not valid in the target's address space. |
| `INJERR_PERMISSION` | -8 | `ptrace(2)` denied (`EPERM`/`EACCES` — Yama, missing `CAP_SYS_PTRACE`), or `injector_write_mem` on a handle attached without `opts.enable_write_mem`. |
| `INJERR_UNSUPPORTED_TARGET` | -9 | The target's architecture, ABI or libc is not supported by this build: an x32-ABI target, or `injector_uninject` / `injector_uninject_all` against a musl-libc target, which cannot `dlclose` what was loaded. This is the only libc gate in the API: inject and invoke check architecture alone. |
| `INJERR_INVALID_ELF_FORMAT` | -10 | The ELF file is malformed, truncated, or has fields the library refuses to trust. |
| `INJERR_WAIT_TRACEE` | -11 | The ptrace/waitpid protocol for this handle is out of sync: an earlier remote call timed out and could not leave the target stopped, or the desync table overflowed. The message says whether the target can still be repaired — read it before retrying. |
| `INJERR_FUNCTION_MISSING` | -12 | The symbol was not found in the target, or the name was NULL or too long. |
| `INJERR_TIMEOUT` | -13 | A remote call did not complete within `opts.call_timeout_ms`. `opts.timeout_action` decides what happens to the target next. |

`INJERR_NO_FUNCTION` is a deprecated alias for `INJERR_FUNCTION_MISSING`.

### Other public API

Beyond the examples above, `include/injector.h` also exports:

- `injector_call(inj, handle, name)` — call a no-argument function in a library
  this handle injected; shorthand for `injector_remote_func_addr` plus
  `injector_remote_call`.
- `injector_remote_func_addr(inj, handle, name, &func_addr)` — address of a
  function inside an injected library.
- `injector_remote_call(inj, &retval, func_addr, ...)` and
  `injector_remote_vcall(inj, &retval, func_addr, ap)` — call an arbitrary
  address in the target, variadic or `va_list`. Both exist only when
  `INJECTOR_HAS_REMOTE_CALL_FUNCS` is defined.
- `injector_version_string()` — runtime version string, the same value as
  `INJECTOR_VERSION` ("1.0.0"). `injector_abi_version()` returns
  `INJECTOR_ABI_VERSION` (currently 1); compare it against your headers before
  trusting a handle.
- `injector_library_init()` / `injector_library_deinit()` — idempotent hooks for
  FFI hosts; near-no-ops today, reserved for future use.
- `injector_inject_in_cloned_thread(inj, path, &handle)` — `dlopen` from a
  `clone()`d thread, defined only when `INJECTOR_HAS_INJECT_IN_CLONED_THREAD` is
  (Linux x86_64). `#ifdef` both feature macros before use.

One ABI detail that bites: `injector_module_t.name` is a fixed 256-byte field
hardcoded into the binding layouts, so a path longer than 255 characters is
truncated, though still NUL-terminated. Compare by suffix, or resolve the real
path yourself, when targets live under something like `/nix/store` or a snap
mount.

### Link flags, ABI, and init

Link with `pkg-config --cflags --libs libinjector`, which yields `-linjector`
and the include path; the versioned SONAME is `libinjector.so.1`. No `-ldl` and
no `-lrt` are needed: the archive resolves `dlopen` and `dlsym` inside the
target through generated shellcode and never calls them itself, and
`clock_gettime` has been in libc since glibc 2.17. The init and version hooks
are listed above with the rest of the API.

### Legacy attach path

The original `injector_attach` + `injector_inject` + `injector_uninject` +
`injector_detach` sequence is still supported. `injector_error()` (the
thread-local fallback) is deprecated in favor of `injector_last_error(inj)`.

## Language bindings

Official bindings for Go, Python, and Rust. Go and Rust vendor a prebuilt
`libinjector.a`, so those two need no system install. Python vendors nothing: it
`ctypes`-loads a `libinjector.so` from beside the package, from
`ctypes.util.find_library("injector")`, or from the plain loader path, and if it
finds none it raises with instructions to build one
(`bindings/python/injector/_ffi.py`).

### Go

**Import path:** `github.com/AlanFokCo/injector/pkg/injector`

The Go binding uses cgo with a vendored static library. Requires Go 1.21+.

#### One-shot injection

```go
package main

import (
    "fmt"
    "log"

    "github.com/AlanFokCo/injector/pkg/injector"
)

func main() {
    result, err := injector.Run(1234, "/path/to/libprobe.so", "entry", nil, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("entry returned %d\n", result.RetVal)
}
```

#### Granular control

```go
package main

import (
    "fmt"
    "log"

    inj "github.com/AlanFokCo/injector/pkg/injector"
)

func main() {
    i, err := inj.AttachWithOpts(1234, &inj.Opts{
        CallTimeoutMs:  2000,
        EnableWriteMem: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer i.Close()

    handle, err := i.Inject("/path/to/libprobe.so")
    if err != nil {
        log.Fatal(err)
    }
    _ = handle

    // Call a function with arguments
    result, err := i.Invoke("/path/to/libprobe.so", "add_values", 42, 100)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("add_values returned %d\n", result.RetVal)

    // List loaded modules
    mods, err := i.ListModules()
    if err != nil {
        log.Fatal(err)
    }
    for _, m := range mods {
        fmt.Printf("  %s @ %#x\n", m.Name, m.Base)
    }

    // Read target memory
    addr, err := i.ResolveSymbol("", "g_counter")
    if err == nil {
        data, err := i.ReadMem(addr, 8)
        if err == nil {
            fmt.Printf("g_counter bytes: %v\n", data)
        }
    }
}
```

#### Introspection (no attach)

```go
info, err := injector.GetTargetInfo(1234)
if err == nil {
    fmt.Printf("pid=%d arch=%s libc=%s exe=%s\n",
        info.PID, info.Arch, info.Libc, info.Exe)
}

if injector.CanAttach(1234) {
    fmt.Println("ptrace attach is feasible")
}

pid, err := injector.FindProcess("mysvc")
```

#### API reference

| Function | Description |
|---|---|
| `Run(pid, lib, sym, args, opts)` | One-shot: attach + inject + call + detach |
| `Attach(pid)` | Attach with default options |
| `AttachWithOpts(pid, opts)` | Attach with custom options |
| `(*Injector).Close()` | Detach from target |
| `(*Injector).Inject(path)` | Load a shared library, returns handle |
| `(*Injector).Uninject(handle)` | Unload a previously injected library |
| `(*Injector).UninjectAll()` | Unload all injected libraries |
| `(*Injector).Invoke(path, sym, args...)` | Call a symbol in an injected library |
| `(*Injector).ListModules()` | List loaded modules |
| `(*Injector).ResolveSymbol(lib, sym)` | Resolve a symbol address in target |
| `(*Injector).ReadMem(addr, size)` | Read target memory |
| `(*Injector).WriteMem(addr, data)` | Write target memory |
| `(*Injector).RemoteFuncAddr(handle, name)` | Get function address from handle |
| `(*Injector).LastError()` | Last error message |
| `GetTargetInfo(pid)` | Target introspection (no attach) |
| `CanAttach(pid)` | Check ptrace feasibility |
| `FindProcess(name)` | Find PID by process name |
| `Version()` / `ABIVersion()` | Library version info |

---

### Python

**Package:** `injector` (under `bindings/python/`)

The Python binding uses ctypes and needs no compilation of its own. It declares
`requires-python = ">=3.8"` and uses no construct newer than 3.8, but CI runs a
single interpreter (whatever `setup-python` with `3.x` resolves to), so 3.8
through 3.11 rest on that reading rather than on a test run. It needs a
system-installed `libinjector.so`: build with `make` and `make install`, or copy
the `.so` next to the package.

#### One-shot injection

```python
from injector import run

result = run(1234, "/path/to/libprobe.so", "entry")
print(f"entry returned {result.retval}")
```

#### With arguments

```python
from injector import run

result = run(1234, "/path/to/libprobe.so", "add_values", args=[42, 100])
print(f"add_values returned {result.retval}")
```

#### Granular control (context manager)

```python
from injector import Injector, Opts

with Injector(1234, opts=Opts(call_timeout_ms=2000, enable_write_mem=True)) as inj:
    handle = inj.inject("/path/to/libprobe.so")

    result = inj.invoke("/path/to/libprobe.so", "add_values", 42, 100)
    print(f"add_values returned {result.retval}")

    # List loaded modules
    for mod in inj.list_modules():
        print(f"  {mod.name} @ {mod.base:#x}")

    # Read target memory
    addr = inj.resolve_symbol(None, "g_counter")
    data = inj.read_mem(addr, 8)
    print(f"g_counter bytes: {data}")
```

#### Introspection (no attach)

```python
from injector import target_info, can_attach, find_process

info = target_info(1234)
print(f"pid={info.pid} arch={info.arch} libc={info.libc} exe={info.exe}")

if can_attach(1234):
    print("ptrace attach is feasible")

pid = find_process("mysvc")
```

#### Error handling

```python
from injector import Injector, InjectorError

try:
    with Injector(9999) as inj:
        inj.inject("/nonexistent.so")
except InjectorError as e:
    print(f"error code={e.code}: {e}")
```

#### API reference

| Function / Method | Description |
|---|---|
| `run(pid, lib, sym, args=None, opts=None)` | One-shot: attach + inject + call + detach |
| `Injector(pid, opts=None)` | Attach (use as context manager) |
| `.close()` | Detach from target |
| `.inject(path)` | Load a shared library, returns handle |
| `.uninject(handle)` | Unload a previously injected library |
| `.uninject_all()` | Unload all injected libraries |
| `.invoke(path, sym, *args)` | Call a symbol in an injected library |
| `.list_modules()` | List loaded modules |
| `.resolve_symbol(lib, sym)` | Resolve a symbol address in the **target executable** (`lib` is reserved and ignored; pass `None`/`""`) |
| `.read_mem(addr, size)` | Read target memory |
| `.write_mem(addr, data)` | Write target memory |
| `.remote_func_addr(handle, name)` | Get function address from handle |
| `.last_error()` | Last error message |
| `target_info(pid)` | Target introspection (no attach) |
| `can_attach(pid)` | Check ptrace feasibility |
| `find_process(name)` | Find PID by process name |
| `version()` / `abi_version()` | Library version info |

---

### Rust

**Crates:** `injector` (safe wrapper) and `injector-sys` (raw FFI), under
`bindings/rust/`.

The Rust binding provides a safe `Injector` type with RAII (auto-detach on
drop). Both crates declare `edition = "2021"` and neither manifest sets
`rust-version`, so there is no MSRV to quote — any toolchain that accepts the
2021 edition builds them. Uses a vendored static library; no system install
needed.

#### Cargo.toml

```toml
[dependencies]
injector = { path = "bindings/rust/injector" }
```

Or if published to a registry:

```toml
[dependencies]
injector = "1.0"
```

#### One-shot injection

```rust
use injector::run;

fn main() -> Result<(), injector::InjectorError> {
    let result = run(1234, "/path/to/libprobe.so", "entry", &[], None)?;
    println!("entry returned {}", result.retval);
    Ok(())
}
```

#### Granular control

```rust
use injector::{Injector, Opts, DeliveryMode};

fn main() -> Result<(), injector::InjectorError> {
    let opts = Opts {
        call_timeout_ms: 2000,
        enable_write_mem: true,
        ..Opts::default()
    };
    let mut inj = Injector::attach_with_opts(1234, &opts)?;

    let handle = inj.inject("/path/to/libprobe.so")?;

    // Call a function with arguments
    let result = inj.invoke("/path/to/libprobe.so", "add_values", &[42, 100])?;
    println!("add_values returned {}", result.retval);

    // List loaded modules
    for m in inj.list_modules()? {
        println!("  {} @ {:#x}", m.name, m.base);
    }

    // Read target memory
    if let Ok(addr) = inj.resolve_symbol(None, "g_counter") {
        let data = inj.read_mem(addr, 8)?;
        println!("g_counter bytes: {:?}", data);
    }

    inj.uninject(handle)?;
    // Injector auto-detaches on drop
    Ok(())
}
```

#### Introspection (no attach)

```rust
use injector::{get_target_info, can_attach, find_process};

fn main() {
    if let Ok(info) = get_target_info(1234) {
        println!("pid={} arch={} libc={} exe={}",
            info.pid, info.arch, info.libc, info.exe);
    }

    if can_attach(1234) {
        println!("ptrace attach is feasible");
    }

    if let Some(pid) = find_process("mysvc") {
        println!("found mysvc at pid {}", pid);
    }
}
```

#### API reference

| Function / Method | Description |
|---|---|
| `run(pid, lib, sym, args, opts)` | One-shot: attach + inject + call + detach |
| `Injector::attach(pid)` | Attach with default options |
| `Injector::attach_with_opts(pid, opts)` | Attach with custom options |
| `.inject(path)` | Load a shared library, returns `Handle` |
| `.uninject(handle)` | Unload a previously injected library |
| `.uninject_all()` | Unload all injected libraries |
| `.invoke(path, sym, args)` | Call a symbol in an injected library |
| `.list_modules()` | List loaded modules |
| `.resolve_symbol(lib, sym)` | Resolve a symbol address in the **target executable** (`lib` is reserved and ignored; pass `None`/`""`) |
| `.read_mem(addr, len)` | Read target memory |
| `.write_mem(addr, data)` | Write target memory |
| `.remote_func_addr(handle, name)` | Get function address from handle |
| `.last_error()` | Last error message |
| `get_target_info(pid)` | Target introspection (no attach) |
| `can_attach(pid)` | Check ptrace feasibility |
| `find_process(name)` | Find PID by process name |
| `version()` / `abi_version()` | Library version info |

## Command line program

`cmd/injector` is a thin CLI around the library. `--help` prints this verbatim
(output of `./cmd/injector --help` on an x86_64 build):

```text
Usage: ./cmd/injector [options] [library-to-inject ...]

Target (one required):
  -p, --pid PID           target process id
  -n, --name NAME         find target by executable basename

Actions:
  (default)               inject libraries listed after options
  -r, --run LIB:SYMBOL    one-shot: inject LIB, call SYMBOL, detach
  -d, --delivery MODE     one-shot delivery: auto|nonstop|ptrace (default: auto)
                          use 'ptrace' for CUDA/heavy targets (nonstop dlopen
                          from a TLS-less clone can fault in ld.so)
  -a, --arg VALUE         argument for --run (up to 6, integer or 0x hex)
  -i, --info              print target info (non-intrusive) and exit

Options:
  -t, --timeout MS        remote-call timeout in milliseconds (default: 5000)
  -T, --cloned-thread     use clone()-based injection (x86_64 only)
  -V, --version           print version and exit
  -h, --help              print this help and exit
```

`-T/--cloned-thread` is present only in x86_64 builds, where
`INJECTOR_HAS_INJECT_IN_CLONED_THREAD` is defined.

```shell
$ ./cmd/injector -p 4242 /path/to/lib.so                 # inject by pid
$ ./cmd/injector -n mysvc /path/to/lib.so                # inject by basename
$ ./cmd/injector -p 4242 -i                             # target info, no attach
$ ./cmd/injector -p 4242 -r /path/to/lib.so:entry       # inject, call, detach
$ ./cmd/injector -p 4242 -r /path/to/lib.so:add -a 42 -a 100
$ ./cmd/injector -p 4242 -d ptrace -t 2000 -r /path/to/lib.so:entry
```

`-r/--run` prints the entry's return value on stdout. `-a/--arg` may be repeated
up to 6 times and accepts decimal or `0x` hex. `-i/--info` reads only `/proc`.

`-p` rejects anything outside 1-4194304, so a value like `8589934593` cannot
silently truncate to pid 1. Pid 1 itself is refused by the library:

```shell
$ ./cmd/injector -p 1 --run /tmp/x.so:entry
injector_run failed (rc=-3): refusing to attach to pid 1: attaching to init patches an int3 trampoline into its libc and will panic the host
```

## Installation

Building needs a C compiler (gcc or clang) and GNU make. `make fuzz` and
`make fuzz-regress` additionally need clang.

```shell
$ make            # build first
$ make install    # default prefix /usr/local
```

`make install` installs:

| destination | description |
|---|---|
| `<PREFIX>/include/injector.h` | public header |
| `<PREFIX>/lib/libinjector.so.1.0.0` | the real shared library file |
| `<PREFIX>/lib/libinjector.so.1` | symlink to `libinjector.so.1.0.0`; the SONAME |
| `<PREFIX>/lib/libinjector.so` | symlink to `libinjector.so.1`, for linking |
| `<PREFIX>/lib/libinjector.a` | static library |
| `<PREFIX>/lib/pkgconfig/libinjector.pc` | pkg-config file |

`libinjector.pc` lists `Libs: -L${libdir} -linjector`. If you link the static
archive by hand instead, add `-ldl` — that is what `cmd/Makefile` does.

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

### Linux — x86_64 and i386

These rows come from this fork's CI (GitHub Actions).

| injector \ target | x86_64 | i386 | x32(*1) |
|---|---|---|---|
| **x86_64** | OK(*2) | OK(*3) | refused(*4) |
| **i386**   | FAIL(*5) | OK(*3) | refused(*4) |
| **x32**(*1)(*6) | not built(*6) | not built(*6) | not built(*6) |

*1: [x32 ABI](https://en.wikipedia.org/wiki/X32_ABI)
*2: tested in CI with both glibc and musl. Injection works on musl; unloading
does not. `injector_uninject` and `injector_uninject_all` return
`INJERR_UNSUPPORTED_TARGET` for a musl-libc target, because musl's `dlclose`
cannot unload a library. That is the only libc gate in the API: the inject and
invoke paths check architecture alone, and CI runs `--invoke` on glibc only.
*3: tested in CI with glibc.
*4: refused by design, not a test result. During attach, before anything is
written to the target, `injector__arch_is_unsupported()` is asked about
`EM_X86_64` + `ELFCLASS32` and the attach fails with `INJERR_UNSUPPORTED_TARGET`
and the message `x86_64 x32-ABI target process is not supported: this build
injects only into LP64 x86_64 and i386 targets.`, then detaches, so the target's
text is never touched. Pinned by `tests/unit/test_x32_refused.c`.
*5: failure with `64-bit target process isn't supported by 32-bit process`.
*6: no x32 injector exists — informational, not coverage. The `-mx32` build
target and the `x86_64 -> x32` / `x32 -> i386` pairs were removed from
`tests/Makefile` together with the x32 runtime.

### Non-x86 results are upstream's, not re-verified here

The ARM, MIPS, PowerPC and RISC-V results below are as reported by upstream
[`kubo/injector`](https://github.com/kubo/injector). This fork's CI runs four
jobs — Ubuntu x86_64/i686, the ASan/UBSan fuzz build, the language bindings, and
Alpine x86_64 — and tests no arm, mips, ppc or riscv target. Treat these rows as
provenance, not as current coverage.

### ARM

| injector \ target | arm64 | armhf | armel |
|---|---|---|---|
| **arm64** | OK | OK | OK |
| **armhf** | FAIL(*1) | OK | OK |
| **armel** | FAIL(*1) | OK | OK |

*1: failure with `64-bit target process isn't supported by 32-bit process`.

### MIPS

| injector \ target | mips64el | mipsel (n32) | mipsel (o32) |
|---|---|---|---|
| **mips64el** | OK(*1) | OK(*1) | OK(*1) |
| **mipsel (n32)** | FAIL(*2) | OK(*1) | OK(*1) |
| **mipsel (o32)** | FAIL(*2) | OK(*1) | OK(*1) |

*1: reported from [debian 11 mips64el](https://www.debian.org/releases/bullseye/mips64el/ch02s01.en.html#idm271) on [QEMU](https://www.qemu.org/).
*2: failure with `64-bit target process isn't supported by 32-bit process`.

### PowerPC

- **ppc64le** (reported from [alpine 3.16.2 ppc64le](https://dl-cdn.alpinelinux.org/alpine/v3.16/releases/ppc64le/) on [QEMU](https://www.qemu.org/))
- **powerpc (big endian)** (reported from [ubuntu 16.04 powerpc](https://old-releases.ubuntu.com/releases/xenial/) on [QEMU](https://www.qemu.org/))

### RISC-V

- **riscv64** (reported from [Ubuntu 22.04.1 riscv64 on QEMU](https://wiki.ubuntu.com/RISC-V#Booting_with_QEMU))

## Caveats

> The following restrictions apply on Linux.

`injector` does not work where `ptrace()` is disallowed:

- Non-children processes (see [Caveat about `ptrace()`][]).
- Docker containers on docker < 19.03 or kernel < 4.8. Pass
  [`--cap-add=SYS_PTRACE`](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)
  to `docker run`.
- Linux inside UserLAnd (Android app) (see [issue #17](https://github.com/kubo/injector/issues/17#issuecomment-1113990177)).

### Never target `init`/PID 1 or other critical system processes

To run a function inside the target, `injector` temporarily patches a short
`call *%rax; int3` trampoline into the target's libc and restores the original
bytes afterwards — the target is *modified*, however briefly. If PID 1 reaches
that `int3` with no tracer to intercept it, PID 1 dies, and the kernel answers
with `Kernel panic - not syncing: Attempted to kill init!`: the whole machine
goes down. While a tracer is attached the `SIGTRAP` goes to the tracer instead,
which is why the failure needs the trampoline left in place and nobody watching
it.

The attach path therefore refuses `pid <= 1`, with `INJERR_NO_PROCESS` and the
message `refusing to attach to pid 1: attaching to init patches an int3
trampoline into its libc and will panic the host`. More generally, only target
processes you own and can afford to lose.

### NONSTOP delivery runs `dlopen` without TLS

`INJECTOR_DELIVERY_NONSTOP` — what `INJECTOR_DELIVERY_AUTO` resolves to on
x86_64 — creates the helper task with `clone()`. That task has no TLS, so
`dlopen` can fault inside `ld.so` on targets whose loader or preloaded libraries
need one; CUDA and other heavy runtimes are the case `cmd/main.c` names in its
own `--help`. Use `-d ptrace` / `INJECTOR_DELIVERY_PTRACE` for those targets, and
accept that ptrace delivery interrupts a thread of the target and gives up the
failure isolation described in [Production contract](#production-contract).
NONSTOP is x86_64 only; elsewhere `injector_invoke` returns
`INJERR_UNSUPPORTED_TARGET`.

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

Shipped: bounded timeouts with state restoration, per-handle errors,
`process_vm_readv`/`writev`, one-pass ELF resolution, the `/proc` parser, target
introspection, memory read/write, module listing, `injector_invoke` /
`injector_run`, packaging, and unit + integration tests (M1); Go, Python and Rust
bindings (M1.5); NONSTOP delivery with automatic ptrace fallback and
`INJECTOR_TIMEOUT_LEAVE` (M2); `INJECTOR_TIMEOUT_KILL_THREAD`, the ASan/UBSan
fuzz build, musl CI and the full CLI switch set (M3/M4).

Still open:

- **aarch64 NONSTOP delivery.** The `clone()`-based path is gated on `__x86_64__`
  (`INJECTOR_HAS_INJECT_IN_CLONED_THREAD`), so aarch64 targets fall back to
  ptrace delivery and get no failure isolation.
- **Runtime log handler.** No public hook for the library's diagnostics; errors
  surface only through `injector_last_error()`.
- **CI beyond x86.** The workflow runs Ubuntu x86_64/i686, the fuzz job, the
  bindings job and Alpine x86_64 — no arm, mips, ppc or riscv coverage, which is
  why those rows under [Tested architectures](#tested-architectures) are labelled
  as upstream's.

## License

Files under [`include`][] and [`src`][] are licensed under **LGPL 2.1 or
later**. Files under [`cmd`][] are licensed under **GPL 2 or later**. See
[`LICENSE_LGPL.txt`](./LICENSE_LGPL.txt) and [`LICENSE_GPL.txt`](./LICENSE_GPL.txt).

## Acknowledgements

- [`kubo/injector`](https://github.com/kubo/injector), the original project this
  fork builds on.
- [`linux-inject`][] — the inspiration for the injection technique.

[`linux-inject`]: https://github.com/gaffe23/linux-inject
[Caveat about `ptrace()`]: https://github.com/gaffe23/linux-inject#caveat-about-ptrace
[`clone()`]: https://man7.org/linux/man-pages/man2/clone.2.html
[`pthread_create()`]: https://man7.org/linux/man-pages/man3/pthread_create.3.html
[`cmd`]: cmd
[`include`]: include
[`src`]: src
