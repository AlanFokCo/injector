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
    def __init__(self, code, message=""):
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


_CODE_MAP = {
    INJERR_NO_PROCESS: "NoProcessError",
    INJERR_PERMISSION: "PermissionError",
    INJERR_TIMEOUT: "TimeoutError",
    INJERR_FILE_NOT_FOUND: "FileNotFoundError",
    INJERR_FUNCTION_MISSING: "FunctionMissingError",
}


class NoProcessError(InjectorError):
    pass


class PermissionError(InjectorError):
    pass


class TimeoutError(InjectorError):
    pass


class FileNotFoundError(InjectorError):
    pass


class FunctionMissingError(InjectorError):
    pass


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
