"""Regression tests for the Python binding's safety properties.

These cover defects that used to crash the interpreter outright, so they are
written to run without a real target process wherever possible.
"""
import ctypes
import os
import sys
import warnings

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import injector
from injector._ffi import get_lib


def _bare_injector():
    """An Injector that is 'closed': no C handle, without touching ptrace."""
    inj = injector.Injector.__new__(injector.Injector)
    inj._lib = get_lib()
    inj._ptr = ctypes.c_void_p()   # NULL handle == closed
    return inj


def test_closed_handle_is_safe():
    """Every method must raise instead of passing NULL into the C API.

    The C side dereferences injector_t* unconditionally, so this used to
    SIGSEGV the whole interpreter - an uncatchable crash.
    """
    inj = _bare_injector()
    calls = [
        lambda: inj.inject("/tmp/does-not-matter.so"),
        lambda: inj.uninject(0),
        lambda: inj.uninject_all(),
        lambda: inj.invoke("/tmp/x.so", "sym"),
        lambda: inj.list_modules(),
        lambda: inj.resolve_symbol("", "malloc"),
        lambda: inj.read_mem(0x1000, 16),
        lambda: inj.write_mem(0x1000, b"\x01\x02"),
        lambda: inj.remote_func_addr(0, "sym"),
        lambda: inj.last_error(),
    ]
    for i, fn in enumerate(calls):
        try:
            fn()
        except ValueError:
            continue
        raise AssertionError("call #%d on a closed handle did not raise ValueError" % i)
    inj.close()   # must be a no-op, not a crash


def test_closed_handle_after_close():
    """close() twice is safe, and use-after-close raises."""
    inj = _bare_injector()
    inj.close()
    inj.close()
    try:
        inj.inject("/tmp/x.so")
    except ValueError:
        return
    raise AssertionError("use after close did not raise")


def test_error_classes_are_catchable_as_builtins():
    """The specific errors used to shadow the builtins without inheriting them.

    `except OSError:` and `except PermissionError:` therefore missed them.
    """
    assert issubclass(injector.PermissionError, OSError)
    assert issubclass(injector.PermissionError, injector.InjectorError)
    assert issubclass(injector.TimeoutError, OSError)
    assert issubclass(injector.TimeoutError, injector.InjectorError)
    assert issubclass(injector.FileNotFoundError, OSError)
    assert issubclass(injector.NoProcessError, injector.InjectorError)
    assert issubclass(injector.FunctionMissingError, injector.InjectorError)

    # and they are actually raised as those types by check()
    from injector._errors import check, INJERR_PERMISSION, INJERR_TIMEOUT
    for code, cls in ((INJERR_PERMISSION, OSError), (INJERR_TIMEOUT, OSError)):
        try:
            check(code, None, None)
        except cls:
            pass
        else:
            raise AssertionError("code %s was not catchable as %s" % (code, cls))


def test_public_names_are_exported():
    for name in injector.__all__:
        assert hasattr(injector, name), "missing export: %s" % name
    # unambiguous aliases exist for the builtin-shadowing names
    assert injector.InjectorPermissionError is injector.PermissionError
    assert injector.InjectorTimeoutError is injector.TimeoutError
    assert injector.InjectorFileNotFoundError is injector.FileNotFoundError


class _RecordingLib:
    """Stand-in for the ctypes handle: records every call, touches no real C
    code. Used to assert that a validation path returned *before* the C API was
    reached - an assertion about absence, so the recorder must be explicit
    rather than relying on an attribute that was never going to exist."""
    def __init__(self):
        self.calls = []

    def _rec(self, name):
        def fn(*args):
            self.calls.append((name,) + args)
            return 0
        return fn

    def injector_detach(self, ptr):
        return self._rec("injector_detach")(ptr)

    def injector_read_mem(self, *a):
        return self._rec("injector_read_mem")(*a)

    def injector_write_mem(self, *a):
        return self._rec("injector_write_mem")(*a)

    def names(self):
        return [c[0] for c in self.calls]


def test_finalizer_warns_instead_of_silently_leaking():
    """The warning path is the whole point of __del__, so exercise it."""
    inj = _bare_injector()
    inj._ptr = ctypes.c_void_p(0)      # already closed -> no warning expected
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        inj.__del__()
        assert len(w) == 0, "should not warn for an already-closed handle"

    # An *open* handle that is collected without close() must warn exactly once.
    inj = _bare_injector()
    inj._lib = _RecordingLib()
    inj._ptr = ctypes.c_void_p(0xDEAD)  # non-NULL: looks "attached"
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        inj.__del__()
        assert len(w) == 1, "expected exactly one RuntimeWarning, got %d" % len(w)
        assert issubclass(w[0].category, RuntimeWarning), w[0].category
        assert "without close()" in str(w[0].message), str(w[0].message)
    # __del__ must NOT attempt a detach: it runs on an arbitrary thread, where
    # PTRACE_DETACH cannot succeed, and the result would be discarded.
    assert "injector_detach" not in inj._lib.names(), (
        "__del__ called into the C API: %r" % (inj._lib.calls,))
    inj._ptr = ctypes.c_void_p()   # do not warn again when this object is freed


def _open_looking_injector():
    """An Injector whose handle is non-NULL, so _check_open() passes.

    Only safe for the size-validation paths, which raise BEFORE any C call is
    made - never use this to exercise a method that reaches the C API.
    """
    inj = _bare_injector()
    inj._lib = _RecordingLib()
    inj._ptr = ctypes.c_void_p(0xDEAD)
    return inj


def test_read_mem_rejects_negative_size():
    """Must reach the size check, not just trip the closed-handle guard."""
    inj = _open_looking_injector()
    try:
        try:
            inj.read_mem(0x1000, -1)
        except ValueError as e:
            assert "negative read size" in str(e), (
                "wrong ValueError (probably the closed-handle guard, so the "
                "size check was never reached): %s" % e)
        else:
            raise AssertionError("negative size was accepted")
        assert inj._lib.names() == [], "C API reached for a negative size: %r" % (inj._lib.calls,)
        # a zero-length read short-circuits without touching C
        assert inj.read_mem(0x1000, 0) == b""
        assert inj._lib.names() == [], "C API reached for a zero-length read: %r" % (inj._lib.calls,)
    finally:
        inj._ptr = ctypes.c_void_p()   # avoid a stray GC warning later


def test_write_mem_empty_is_a_noop():
    inj = _open_looking_injector()
    try:
        inj.write_mem(0x1000, b"")     # must return before any C call
        assert inj._lib.names() == [], (
            "empty write reached the C API: %r" % (inj._lib.calls,))
    finally:
        inj._ptr = ctypes.c_void_p()


def test_closed_guard_message_is_distinct():
    """Keep the two ValueError paths distinguishable, so the tests above cannot
    silently degrade into passing on the wrong branch again."""
    inj = _bare_injector()
    try:
        inj.read_mem(0x1000, -1)
    except ValueError as e:
        assert "closed" in str(e), str(e)
    else:
        raise AssertionError("closed handle did not raise")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("PASS:", fn.__name__)
    print("ALL PASSED (%d tests)" % len(fns))
