import builtins

INJERR_SUCCESS = 0
INJERR_OTHER = -1
INJERR_NO_MEMORY = -2
INJERR_NO_PROCESS = -3
INJERR_NO_LIBRARY = -4
INJERR_ERROR_IN_TARGET = -5
INJERR_FILE_NOT_FOUND = -6
INJERR_INVALID_MEMORY_AREA = -7
INJERR_PERMISSION = -8
INJERR_UNSUPPORTED_TARGET = -9
INJERR_INVALID_ELF_FORMAT = -10
INJERR_WAIT_TRACEE = -11
INJERR_FUNCTION_MISSING = -12
INJERR_TIMEOUT = -13


class InjectorError(Exception):
    """Base class of every error this binding raises.

    `code` is an INJERR_* value from libinjector, `message` the text that
    injector_last_error() returned for it.
    """

    def __new__(cls, *args, **kwargs):
        # MINOR: the specific errors below also derive from the builtin OSError
        # family, whose __new__ *rewrites the instance type*: OSError(errno.EACCES,
        # "x") hands back a builtins.PermissionError, not an OSError. If that
        # errno -> builtin-subclass mapping ever applied to a construction like
        # `injector.PermissionError(errno.EACCES, "x")`, the object handed back
        # would be the *builtin* class and `except InjectorError:` would silently
        # miss it - exactly the trap the builtin inheritance below was added to
        # close.
        #
        # So pin the type in the shared base - it is first in the MRO of every
        # specific error, including the OSError-derived ones - by never letting
        # errno-shaped arguments reach OSError.__new__: build those instances from
        # `cls` alone. type() calls __init__ right after whenever __new__ returns
        # an instance of `cls`, which it now always does, and __init__ below fills
        # in the state from those same arguments. Keeping the arguments away from
        # __new__ also leaves errno/strerror/filename unset, as they always were.
        # The plain InjectorError-only classes are unaffected by the mapping, so
        # they keep the untouched __new__ call and its argument handling.
        if issubclass(cls, OSError):
            return super().__new__(cls)
        return super().__new__(cls, *args, **kwargs)

    def __init__(self, code, message=""):
        self.code = code
        self.message = message
        msg = f"[{code}] {message}"
        super().__init__(msg)
        # Overriding __new__ above flips CPython's oserror_use_init() heuristic
        # (it defers argument handling to __init__ only when __init__ is
        # overridden *and* __new__ is not), which turns OSError.__init__ into a
        # no-op for the OSError-derived errors below. Set args explicitly so
        # str(), repr() and .args stay exactly what they were before this pin,
        # on CPython and on implementations that do not use that heuristic.
        self.args = (msg,)


_CODE_MAP = {
    INJERR_NO_PROCESS: "NoProcessError",
    INJERR_PERMISSION: "PermissionError",
    INJERR_TIMEOUT: "TimeoutError",
    INJERR_FILE_NOT_FOUND: "FileNotFoundError",
    INJERR_FUNCTION_MISSING: "FunctionMissingError",
}


# These classes used to subclass only InjectorError while *shadowing* the
# builtin names of the same spelling. The result was a trap: user code writing
# `except PermissionError:` or `except OSError:` silently failed to catch them,
# and the classes were not even exported from the package, so they could not be
# referenced as `injector.PermissionError` at all.
#
# They now also derive from the matching builtin, so both the builtin hierarchy
# (`except OSError`) and `except InjectorError` work, and they are exported.
class NoProcessError(InjectorError):
    """Target process does not exist (INJERR_NO_PROCESS)."""


class PermissionError(InjectorError, builtins.PermissionError):
    """ptrace/permission denied (INJERR_PERMISSION)."""


class TimeoutError(InjectorError, builtins.TimeoutError):
    """Remote call timed out (INJERR_TIMEOUT)."""


class FileNotFoundError(InjectorError, builtins.FileNotFoundError):
    """Library file not found (INJERR_FILE_NOT_FOUND)."""


class FunctionMissingError(InjectorError):
    """Symbol not present in the injected library (INJERR_FUNCTION_MISSING)."""


# Unambiguous aliases, for callers who would rather not rely on a name that
# also exists as a builtin.
InjectorNoProcessError = NoProcessError
InjectorPermissionError = PermissionError
InjectorTimeoutError = TimeoutError
InjectorFileNotFoundError = FileNotFoundError
InjectorFunctionMissingError = FunctionMissingError


_EXCEPTIONS = {
    INJERR_NO_PROCESS: NoProcessError,
    INJERR_PERMISSION: PermissionError,
    INJERR_TIMEOUT: TimeoutError,
    INJERR_FILE_NOT_FOUND: FileNotFoundError,
    INJERR_FUNCTION_MISSING: FunctionMissingError,
}


def check(rc, inj_ptr=None, lib=None):
    if rc == 0:
        return
    msg = ""
    if lib is not None:
        raw = lib.injector_last_error(inj_ptr)
        if raw:
            msg = raw.decode("utf-8", errors="replace")
    exc_cls = _EXCEPTIONS.get(rc, InjectorError)
    raise exc_cls(rc, msg)
