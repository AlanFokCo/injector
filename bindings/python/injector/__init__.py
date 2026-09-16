"""ctypes bindings for libinjector: inject a shared library into a running
Linux process over ptrace, call a symbol in it, and read or write its memory.

Thread affinity
---------------
``injector_attach`` performs PTRACE_ATTACH from the calling OS thread, and every
later ptrace operation on that handle - :meth:`Injector.close` included - must
come from that same OS thread. From any other thread the library refuses the
operation before sending anything to the target, with ``INJERR_OTHER`` and a
message naming both tids; the kernel's own answer to such a request would be
``errno == ESRCH``. In practice:

* use one :class:`Injector` from one thread and do not hand it to another;
* always close it, and prefer the context manager (``with Injector(pid) as
  inj:``), which cannot be skipped by an exception;
* :meth:`Injector.__del__` cannot repair a missed close. It runs on whichever
  thread dropped the last reference, where the detach would be refused, so it
  only issues a ``RuntimeWarning``. The target stays ptrace-stopped until
  something detaches it.

Prerequisite: a loadable libinjector.so
---------------------------------------
This package is pure Python and vendors no shared library: there is no ``.so``
in the source tree beside these files and none in the installed package. At
import time ``injector._ffi`` looks for ``libinjector.so`` or
``libinjector.so.1`` next to this file, then for a system-installed copy through
``ctypes.util.find_library``, then falls back to ``CDLL("libinjector.so")``
on the loader's search path. When none of those resolve, ``import injector``
itself raises :class:`OSError` naming the paths it tried; a library that loads
but reports a different ABI raises :class:`RuntimeError` instead. Build the
library with ``make`` at the top of the repository, then either ``sudo make
install`` it or copy ``libinjector.so`` next to this file.

Supported targets
-----------------
This build ships x86_64 (LP64) and i386 runtimes. x32 is not a supported
runtime: attaching to an x32-ABI target (``EM_X86_64`` with ``ELFCLASS32``)
raises :class:`InjectorError` with code ``INJERR_UNSUPPORTED_TARGET``.

Names re-exported from private modules
--------------------------------------
``Opts``, ``TargetInfo``, ``Module``, ``InvokeResult``, ``MAX_INVOKE_ARGS`` and
the ``DELIVERY_*`` constants are defined in ``injector._types``;
``InjectorError``, its five specific subclasses (each also exported under an
``Injector*Error`` alias, for callers who would rather not shadow a builtin),
the ``INJERR_*`` codes and the ``check`` helper are defined in
``injector._errors``. Every failure reported by the C library arrives as an
``InjectorError`` or one of those subclasses. A handle used after
:meth:`Injector.close` is a programming error rather than a library failure and
raises :class:`ValueError` instead.
"""
import ctypes
import warnings

from ._ffi import get_lib, InjectorOptsC, TargetInfoC, ModuleC, InvokeResultC
from ._errors import (
    InjectorError, check,
    NoProcessError, PermissionError, TimeoutError, FileNotFoundError,
    FunctionMissingError,
    InjectorNoProcessError, InjectorPermissionError, InjectorTimeoutError,
    InjectorFileNotFoundError, InjectorFunctionMissingError,
    INJERR_SUCCESS, INJERR_OTHER, INJERR_NO_MEMORY, INJERR_NO_PROCESS,
    INJERR_NO_LIBRARY, INJERR_ERROR_IN_TARGET, INJERR_FILE_NOT_FOUND,
    INJERR_INVALID_MEMORY_AREA, INJERR_PERMISSION, INJERR_UNSUPPORTED_TARGET,
    INJERR_INVALID_ELF_FORMAT, INJERR_WAIT_TRACEE, INJERR_FUNCTION_MISSING,
    INJERR_TIMEOUT,
)
from ._types import (
    Opts, TargetInfo, Module, InvokeResult,
    MAX_INVOKE_ARGS, DELIVERY_AUTO, DELIVERY_NONSTOP, DELIVERY_PTRACE,
)

__all__ = [
    "Injector", "Opts", "TargetInfo", "Module", "InvokeResult",
    "run", "target_info", "can_attach", "find_process",
    "abi_version", "version", "library_init", "library_deinit",
    "InjectorError", "NoProcessError", "PermissionError", "TimeoutError",
    "FileNotFoundError", "FunctionMissingError",
    "InjectorNoProcessError", "InjectorPermissionError", "InjectorTimeoutError",
    "InjectorFileNotFoundError", "InjectorFunctionMissingError",
    "MAX_INVOKE_ARGS", "DELIVERY_AUTO", "DELIVERY_NONSTOP", "DELIVERY_PTRACE",
]


def _encode(s):
    return s.encode("utf-8") if isinstance(s, str) else s


def _make_copts(opts):
    copts = InjectorOptsC()
    copts.opts_size = ctypes.sizeof(InjectorOptsC)
    if opts is not None:
        copts.delivery = opts.delivery
        copts.call_timeout_ms = opts.call_timeout_ms
        copts.timeout_action = opts.timeout_action
        copts.enable_write_mem = 1 if opts.enable_write_mem else 0
    return copts


def _make_args_array(args):
    if not args:
        return None, 0
    if len(args) > MAX_INVOKE_ARGS:
        raise ValueError(f"too many args: {len(args)} (max {MAX_INVOKE_ARGS})")
    arr = (ctypes.c_ssize_t * len(args))(*args)
    return arr, len(args)


class Injector:
    """A ptrace attachment to one target process.

    Thread affinity: ``injector_attach`` performs PTRACE_ATTACH from the calling
    OS thread and every later ptrace operation on the handle - including the
    PTRACE_DETACH in :meth:`close` - must come from that same thread. Use one
    Injector from a single thread, and always close it (prefer the context
    manager). Dropping it without closing leaves the target ptrace-stopped;
    :meth:`__del__` can only warn about that, not repair it.
    """

    def __init__(self, pid, opts=None):
        """Attach to ``pid``.

        ``opts`` is an :class:`Opts` or ``None`` for the library defaults: the
        delivery mode, a per-remote-call timeout in milliseconds
        (``call_timeout_ms=0`` means the library's 5000 ms default), the action
        to take when that timeout expires, and ``enable_write_mem``, without
        which :meth:`write_mem` is refused with ``INJERR_PERMISSION``.

        The attachment belongs to this OS thread; see the module docstring.
        """
        self._lib = get_lib()
        self._ptr = ctypes.c_void_p()
        if opts is not None:
            copts = _make_copts(opts)
            rc = self._lib.injector_attach_with_opts(
                ctypes.byref(self._ptr), pid, ctypes.byref(copts))
        else:
            rc = self._lib.injector_attach(ctypes.byref(self._ptr), pid)
        check(rc, None, self._lib)

    def _check_open(self):
        """Raise instead of passing a NULL handle into the C API."""
        if self._ptr is None or self._ptr.value is None:
            raise ValueError(
                "injector handle is closed (or was never attached); "
                "create a new Injector")

    def __enter__(self):
        """Return self, so ``with Injector(pid) as inj:`` works."""
        return self

    def __exit__(self, *exc):
        """Call :meth:`close`. Exceptions are not suppressed."""
        self.close()

    def close(self):
        """Detach from the target. Safe to call more than once.

        Raises InjectorError if the detach itself failed, because a failed
        detach can leave the target process ptrace-stopped - that must not be
        reported as success.
        """
        if self._ptr is None or self._ptr.value is None:
            return
        ptr, self._ptr = self._ptr, ctypes.c_void_p()
        rc = self._lib.injector_detach(ptr)
        # injector_detach() frees the C handle, so `ptr` must not be handed back
        # to injector_last_error() - that would be a use-after-free read and
        # ctypes would then decode a dangling pointer. Pass None: the message is
        # in the thread-local buffer.
        check(rc, None, self._lib)

    def __del__(self):
        """Warn, without detaching, when an Injector is collected still open.

        This cannot detach: ``__del__`` runs on whichever thread dropped the
        last reference, and a ptrace request from any thread other than the one
        that attached is refused. The target therefore stays ptrace-attached and
        may be left stopped. Use the context manager or call :meth:`close`.
        """
        # Safety net for an Injector that was dropped without close().
        #
        # This deliberately does NOT call injector_detach(): the ptrace
        # attachment belongs to the OS thread that attached, while __del__ runs
        # on whichever thread dropped the last reference (or on the GC thread),
        # so PTRACE_DETACH there fails with EPERM/ESRCH and its result would be
        # discarded anyway. Warning loudly is honest; pretending to clean up is
        # not. Always use `with Injector(pid) as inj:` or call close() yourself.
        try:
            ptr = getattr(self, "_ptr", None)
            if ptr is not None and ptr.value is not None:
                warnings.warn(
                    "injector.Injector was garbage collected without close(); "
                    "the target process is still ptrace-attached and may be "
                    "left stopped",
                    RuntimeWarning, stacklevel=2)
        except Exception:  # interpreter shutdown: never raise from __del__
            pass

    def inject(self, path):
        """Load the shared library at ``path`` into the target.

        Returns an opaque integer handle for :meth:`uninject` and
        :meth:`remote_func_addr` (0 when the library handed back a NULL one).
        """
        self._check_open()
        handle = ctypes.c_void_p()
        rc = self._lib.injector_inject(self._ptr, _encode(path), ctypes.byref(handle))
        check(rc, self._ptr, self._lib)
        return handle.value or 0

    def uninject(self, handle):
        """Unload (``dlclose``) the library :meth:`inject` returned ``handle`` for."""
        self._check_open()
        rc = self._lib.injector_uninject(self._ptr, ctypes.c_void_p(handle))
        check(rc, self._ptr, self._lib)

    def uninject_all(self):
        """Unload every library this handle injected.

        The remaining ones are still attempted after a failure, and the error
        raised is the first non-zero code the library reported.
        """
        self._check_open()
        rc = self._lib.injector_uninject_all(self._ptr)
        check(rc, self._ptr, self._lib)

    def invoke(self, path, symbol, *args):
        """Inject ``path``, resolve ``symbol`` in it, call it and return the result.

        ``symbol`` must name a function returning ``intptr_t``. At most
        ``MAX_INVOKE_ARGS`` positional ``args`` are accepted; more raises
        :class:`ValueError` before any C call is made. The result is an
        :class:`InvokeResult` whose ``retval`` is what the remote function
        returned and whose ``errmsg`` is the message it left behind. On x86_64
        the call runs in a cloned helper thread when the delivery mode is
        ``DELIVERY_NONSTOP`` or ``DELIVERY_AUTO``, and over ptrace otherwise.
        """
        self._check_open()
        arr, argc = _make_args_array(args)
        result = InvokeResultC()
        rc = self._lib.injector_invoke(
            self._ptr, _encode(path), _encode(symbol),
            arr, argc, ctypes.byref(result))
        if rc != 0:
            msg = result.errmsg.decode("utf-8", errors="replace").rstrip("\x00")
            if not msg:
                raw = self._lib.injector_last_error(self._ptr)
                msg = raw.decode("utf-8", errors="replace") if raw else ""
            raise InjectorError(rc, msg)
        return InvokeResult(
            retval=result.retval,
            errmsg=result.errmsg.decode("utf-8", errors="replace").rstrip("\x00"),
        )

    def list_modules(self):
        """Return the shared libraries loaded in the target, as :class:`Module` objects.

        This reads ``/proc/<pid>/maps`` and neither ptraces the target nor
        executes code there, so it is safe on an attached handle. A library is
        listed once per contiguous group of mappings, so a non-contiguously
        mapped one can appear twice; anonymous mappings and bracketed
        pseudo-paths such as ``[vdso]`` are never listed. Names longer than 255
        bytes are truncated, because the C field is a fixed 256 bytes and part
        of the stable ABI.
        """
        self._check_open()
        count = self._lib.injector_list_modules(self._ptr, None, 0)
        if count < 0:
            raise InjectorError(-1, self.last_error())
        if count == 0:
            return []
        buf = (ModuleC * count)()
        n = self._lib.injector_list_modules(self._ptr, buf, count)
        if n < 0:
            raise InjectorError(-1, self.last_error())
        return [
            Module(
                name=buf[i].name.decode("utf-8", errors="replace").rstrip("\x00"),
                base=buf[i].base,
            )
            for i in range(min(n, count))
        ]

    def resolve_symbol(self, libname, symbol):
        """Return the address of ``symbol`` as loaded in the target.

        ``libname`` is accepted for API symmetry and does not scope the lookup:
        only the target executable's own dynamic symbol table is searched,
        parsed out of ``/proc/<pid>/exe``. There is no remote ``dlsym`` and no
        other loaded library is consulted. For a symbol inside a library you
        injected, use :meth:`remote_func_addr` with the handle :meth:`inject`
        returned. A symbol that is not there raises ``FunctionMissingError``.
        """
        self._check_open()
        clib = _encode(libname) if libname else None
        addr = ctypes.c_size_t()
        rc = self._lib.injector_resolve_symbol(
            self._ptr, clib, _encode(symbol), ctypes.byref(addr))
        check(rc, self._ptr, self._lib)
        return addr.value

    def read_mem(self, addr, size):
        """Return ``size`` bytes of the target's memory at ``addr``.

        A negative ``size`` raises :class:`ValueError` and ``size == 0`` returns
        ``b""`` without touching the target, so no zero-length read ever reaches
        the library.
        """
        self._check_open()
        if size < 0:
            raise ValueError(f"negative read size: {size}")
        if size == 0:
            return b""
        buf = (ctypes.c_char * size)()
        rc = self._lib.injector_read_mem(self._ptr, addr, buf, size)
        check(rc, self._ptr, self._lib)
        return bytes(buf)

    def write_mem(self, addr, data):
        """Write ``data`` to the target's memory at ``addr``.

        Refused with ``INJERR_PERMISSION`` unless the handle was created with
        ``Opts(enable_write_mem=True)``: writing into a target is destructive
        and is off by default. Empty ``data`` returns without a C call, so no
        zero-length write reaches the library.
        """
        self._check_open()
        if len(data) == 0:
            return
        buf = (ctypes.c_char * len(data))(*data)
        rc = self._lib.injector_write_mem(self._ptr, addr, buf, len(data))
        check(rc, self._ptr, self._lib)

    def remote_func_addr(self, handle, name):
        """Return the address of the function ``name`` inside the injected library.

        ``handle`` is the one :meth:`inject` returned. The address is the
        remote one, valid in the target's address space only.
        """
        self._check_open()
        addr = ctypes.c_size_t()
        rc = self._lib.injector_remote_func_addr(
            self._ptr, ctypes.c_void_p(handle), _encode(name), ctypes.byref(addr))
        check(rc, self._ptr, self._lib)
        return addr.value

    def last_error(self):
        """Return the message the library recorded for this handle's last failure.

        An empty string means no error was recorded for it. Raises
        :class:`ValueError` on a closed handle, like every other method here.
        """
        self._check_open()
        raw = self._lib.injector_last_error(self._ptr)
        return raw.decode("utf-8", errors="replace") if raw else ""


# --- Module-level functions ---

def run(pid, lib, symbol, args=None, opts=None):
    """Attach to ``pid``, inject ``lib``, call ``symbol`` and detach again.

    One-shot form of :class:`Injector`: the whole sequence happens inside a
    single C call, so no handle outlives it and there is nothing to close.
    ``symbol`` must name a function returning ``intptr_t``; ``args`` is a
    sequence of at most ``MAX_INVOKE_ARGS`` integers and ``opts`` an
    :class:`Opts` or ``None`` for the library defaults. Returns an
    :class:`InvokeResult`.
    """
    _lib = get_lib()
    arr, argc = _make_args_array(args or [])
    copts = _make_copts(opts)
    result = InvokeResultC()
    rc = _lib.injector_run(pid, _encode(lib), _encode(symbol),
                           arr, argc, ctypes.byref(copts), ctypes.byref(result))
    if rc != 0:
        msg = result.errmsg.decode("utf-8", errors="replace").rstrip("\x00")
        if not msg:
            raw = _lib.injector_last_error(None)
            msg = raw.decode("utf-8", errors="replace") if raw else ""
        raise InjectorError(rc, msg)
    return InvokeResult(
        retval=result.retval,
        errmsg=result.errmsg.decode("utf-8", errors="replace").rstrip("\x00"),
    )


def target_info(pid):
    """Return a :class:`TargetInfo` for ``pid``, read from ``/proc/<pid>``.

    The process is never ptrace-attached, so this is safe to call before
    deciding whether to inject. Raises ``NoProcessError`` when ``pid`` does not
    exist and :class:`InjectorError` on a read error; a field that could not be
    read comes back empty.
    """
    _lib = get_lib()
    info = TargetInfoC()
    rc = _lib.injector_target_info(pid, ctypes.byref(info))
    check(rc, None, _lib)
    return TargetInfo(
        pid=info.pid,
        alive=bool(info.alive),
        ptrace_allowed=bool(info.ptrace_allowed),
        arch=info.arch.decode("utf-8", errors="replace") if info.arch else "",
        libc=info.libc.decode("utf-8", errors="replace") if info.libc else "",
        exe=info.exe.decode("utf-8", errors="replace").rstrip("\x00"),
        cwd=info.cwd.decode("utf-8", errors="replace").rstrip("\x00"),
        root=info.root.decode("utf-8", errors="replace").rstrip("\x00"),
        comm=info.comm.decode("utf-8", errors="replace").rstrip("\x00"),
    )


def can_attach(pid):
    """Return whether attaching to ``pid`` would probably succeed.

    A best-effort heuristic over ``/proc/sys/kernel/yama/ptrace_scope`` and the
    caller's euid; it does not attach. ``Injector(pid)`` is the authoritative
    check.
    """
    return get_lib().injector_can_attach(pid) != 0


def find_process(name):
    """Return the pid of a running process whose executable basename is ``name``.

    Scans ``/proc``, reading each ``/proc/<pid>/exe`` symlink and comparing the
    basename. No such process is a normal outcome rather than a failure of the
    scan, so ``find_process`` returns ``None`` for it - where the Go binding
    returns an error and the Rust one an ``Option``.
    """
    pid = get_lib().injector_find_process(_encode(name))
    if pid < 0:
        return None
    return pid


def abi_version():
    """Return the ABI version the loaded library was built with.

    Compare it against the version your code expects before trusting a handle.
    """
    return get_lib().injector_abi_version()


def version():
    """Return the library's version as a string, for example ``"1.0.0"``."""
    raw = get_lib().injector_version_string()
    return raw.decode("utf-8") if raw else ""


def library_init():
    """Run the library's initialisation hook.

    Idempotent, so calling it more than once is supported, and currently a
    near-no-op that exists so a program can initialise the library at a
    predictable point.
    """
    rc = get_lib().injector_library_init()
    check(rc, None, get_lib())


def library_deinit():
    """Idempotent counterpart of ``library_init()``.

    It does not detach live handles; close those first.
    """
    rc = get_lib().injector_library_deinit()
    check(rc, None, get_lib())
