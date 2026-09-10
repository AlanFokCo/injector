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
        return self

    def __exit__(self, *exc):
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
        self._check_open()
        handle = ctypes.c_void_p()
        rc = self._lib.injector_inject(self._ptr, _encode(path), ctypes.byref(handle))
        check(rc, self._ptr, self._lib)
        return handle.value or 0

    def uninject(self, handle):
        self._check_open()
        rc = self._lib.injector_uninject(self._ptr, ctypes.c_void_p(handle))
        check(rc, self._ptr, self._lib)

    def uninject_all(self):
        self._check_open()
        rc = self._lib.injector_uninject_all(self._ptr)
        check(rc, self._ptr, self._lib)

    def invoke(self, path, symbol, *args):
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
        self._check_open()
        clib = _encode(libname) if libname else None
        addr = ctypes.c_size_t()
        rc = self._lib.injector_resolve_symbol(
            self._ptr, clib, _encode(symbol), ctypes.byref(addr))
        check(rc, self._ptr, self._lib)
        return addr.value

    def read_mem(self, addr, size):
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
        self._check_open()
        if len(data) == 0:
            return
        buf = (ctypes.c_char * len(data))(*data)
        rc = self._lib.injector_write_mem(self._ptr, addr, buf, len(data))
        check(rc, self._ptr, self._lib)

    def remote_func_addr(self, handle, name):
        self._check_open()
        addr = ctypes.c_size_t()
        rc = self._lib.injector_remote_func_addr(
            self._ptr, ctypes.c_void_p(handle), _encode(name), ctypes.byref(addr))
        check(rc, self._ptr, self._lib)
        return addr.value

    def last_error(self):
        self._check_open()
        raw = self._lib.injector_last_error(self._ptr)
        return raw.decode("utf-8", errors="replace") if raw else ""


# --- Module-level functions ---

def run(pid, lib, symbol, args=None, opts=None):
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
    return get_lib().injector_can_attach(pid) != 0


def find_process(name):
    pid = get_lib().injector_find_process(_encode(name))
    if pid < 0:
        return None
    return pid


def abi_version():
    return get_lib().injector_abi_version()


def version():
    raw = get_lib().injector_version_string()
    return raw.decode("utf-8") if raw else ""


def library_init():
    rc = get_lib().injector_library_init()
    check(rc, None, get_lib())


def library_deinit():
    rc = get_lib().injector_library_deinit()
    check(rc, None, get_lib())
