import ctypes
import ctypes.util
import os

# --- C struct definitions ---

class InjectorOptsC(ctypes.Structure):
    _fields_ = [
        ("opts_size", ctypes.c_size_t),
        ("delivery", ctypes.c_int),
        ("call_timeout_ms", ctypes.c_uint),
        ("timeout_action", ctypes.c_int),
        ("enable_write_mem", ctypes.c_int),
    ]


class TargetInfoC(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_int),
        ("alive", ctypes.c_int),
        ("ptrace_allowed", ctypes.c_int),
        ("arch", ctypes.c_char_p),
        ("libc", ctypes.c_char_p),
        ("exe", ctypes.c_char * 4096),
        ("cwd", ctypes.c_char * 4096),
        ("root", ctypes.c_char * 4096),
        ("comm", ctypes.c_char * 16),
    ]


class ModuleC(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 256),
        ("base", ctypes.c_size_t),
    ]


class InvokeResultC(ctypes.Structure):
    _fields_ = [
        ("retval", ctypes.c_ssize_t),
        ("_reserved", ctypes.c_int),
        ("errmsg", ctypes.c_char * 256),
    ]


def _load_lib():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "libinjector.so"),
        os.path.join(here, "libinjector.so.1"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return ctypes.CDLL(path)

    found = ctypes.util.find_library("injector")
    if found:
        return ctypes.CDLL(found)

    return ctypes.CDLL("libinjector.so")


_lib = _load_lib()

# --- argtypes / restype declarations ---

_lib.injector_abi_version.argtypes = []
_lib.injector_abi_version.restype = ctypes.c_uint

_lib.injector_version_string.argtypes = []
_lib.injector_version_string.restype = ctypes.c_char_p

_lib.injector_library_init.argtypes = []
_lib.injector_library_init.restype = ctypes.c_int

_lib.injector_library_deinit.argtypes = []
_lib.injector_library_deinit.restype = ctypes.c_int

_lib.injector_attach.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int]
_lib.injector_attach.restype = ctypes.c_int

_lib.injector_attach_with_opts.argtypes = [
    ctypes.POINTER(ctypes.c_void_p), ctypes.c_int,
    ctypes.POINTER(InjectorOptsC),
]
_lib.injector_attach_with_opts.restype = ctypes.c_int

_lib.injector_detach.argtypes = [ctypes.c_void_p]
_lib.injector_detach.restype = ctypes.c_int

_lib.injector_inject.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p),
]
_lib.injector_inject.restype = ctypes.c_int

_lib.injector_uninject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_lib.injector_uninject.restype = ctypes.c_int

_lib.injector_uninject_all.argtypes = [ctypes.c_void_p]
_lib.injector_uninject_all.restype = ctypes.c_int

_lib.injector_last_error.argtypes = [ctypes.c_void_p]
_lib.injector_last_error.restype = ctypes.c_char_p

_lib.injector_invoke.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ssize_t), ctypes.c_int,
    ctypes.POINTER(InvokeResultC),
]
_lib.injector_invoke.restype = ctypes.c_int

_lib.injector_run.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ssize_t), ctypes.c_int,
    ctypes.POINTER(InjectorOptsC), ctypes.POINTER(InvokeResultC),
]
_lib.injector_run.restype = ctypes.c_int

_lib.injector_target_info.argtypes = [ctypes.c_int, ctypes.POINTER(TargetInfoC)]
_lib.injector_target_info.restype = ctypes.c_int

_lib.injector_can_attach.argtypes = [ctypes.c_int]
_lib.injector_can_attach.restype = ctypes.c_int

_lib.injector_find_process.argtypes = [ctypes.c_char_p]
_lib.injector_find_process.restype = ctypes.c_int

_lib.injector_list_modules.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ModuleC), ctypes.c_size_t,
]
_lib.injector_list_modules.restype = ctypes.c_long

_lib.injector_resolve_symbol.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.injector_resolve_symbol.restype = ctypes.c_int

_lib.injector_read_mem.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
]
_lib.injector_read_mem.restype = ctypes.c_int

_lib.injector_write_mem.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
]
_lib.injector_write_mem.restype = ctypes.c_int

_lib.injector_remote_func_addr.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.injector_remote_func_addr.restype = ctypes.c_int


def get_lib():
    return _lib
