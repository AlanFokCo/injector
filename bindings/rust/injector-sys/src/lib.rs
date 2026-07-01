#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};

pub const INJERR_SUCCESS: c_int = 0;
pub const INJERR_OTHER: c_int = -1;
pub const INJERR_NO_MEMORY: c_int = -2;
pub const INJERR_NO_PROCESS: c_int = -3;
pub const INJERR_NO_LIBRARY: c_int = -4;
pub const INJERR_ERROR_IN_TARGET: c_int = -5;
pub const INJERR_FILE_NOT_FOUND: c_int = -6;
pub const INJERR_INVALID_MEMORY_AREA: c_int = -7;
pub const INJERR_PERMISSION: c_int = -8;
pub const INJERR_UNSUPPORTED_TARGET: c_int = -9;
pub const INJERR_INVALID_ELF_FORMAT: c_int = -10;
pub const INJERR_WAIT_TRACEE: c_int = -11;
pub const INJERR_FUNCTION_MISSING: c_int = -12;
pub const INJERR_TIMEOUT: c_int = -13;

pub const INJECTOR_ABI_VERSION: c_uint = 1;
pub const INJECTOR_MAX_INVOKE_ARGS: usize = 6;

#[repr(C)]
pub struct injector_t {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct injector_opts_t {
    pub opts_size: usize,
    pub delivery: c_int,
    pub call_timeout_ms: c_uint,
    pub timeout_action: c_int,
    pub enable_write_mem: c_int,
}

#[repr(C)]
pub struct injector_target_info_t {
    pub pid: c_int,
    pub alive: c_int,
    pub ptrace_allowed: c_int,
    pub arch: *const c_char,
    pub libc: *const c_char,
    pub exe: [c_char; 4096],
    pub cwd: [c_char; 4096],
    pub root: [c_char; 4096],
    pub comm: [c_char; 16],
}

#[repr(C)]
pub struct injector_module_t {
    pub name: [c_char; 256],
    pub base: usize,
}

#[repr(C)]
pub struct injector_result_t {
    pub retval: isize,
    pub _reserved: c_int,
    pub errmsg: [c_char; 256],
}

extern "C" {
    pub fn injector_abi_version() -> c_uint;
    pub fn injector_version_string() -> *const c_char;
    pub fn injector_library_init() -> c_int;
    pub fn injector_library_deinit() -> c_int;

    pub fn injector_attach(out: *mut *mut injector_t, pid: c_int) -> c_int;
    pub fn injector_attach_with_opts(
        out: *mut *mut injector_t,
        pid: c_int,
        opts: *const injector_opts_t,
    ) -> c_int;
    pub fn injector_detach(inj: *mut injector_t) -> c_int;

    pub fn injector_inject(
        inj: *mut injector_t,
        path: *const c_char,
        handle: *mut *mut c_void,
    ) -> c_int;
    pub fn injector_uninject(inj: *mut injector_t, handle: *mut c_void) -> c_int;
    pub fn injector_uninject_all(inj: *mut injector_t) -> c_int;

    pub fn injector_last_error(inj: *mut injector_t) -> *const c_char;

    pub fn injector_invoke(
        inj: *mut injector_t,
        path: *const c_char,
        symbol: *const c_char,
        args: *const isize,
        argc: c_int,
        out: *mut injector_result_t,
    ) -> c_int;

    pub fn injector_run(
        pid: c_int,
        lib: *const c_char,
        symbol: *const c_char,
        args: *const isize,
        argc: c_int,
        opts: *const injector_opts_t,
        out: *mut injector_result_t,
    ) -> c_int;

    pub fn injector_target_info(pid: c_int, out: *mut injector_target_info_t) -> c_int;
    pub fn injector_can_attach(pid: c_int) -> c_int;
    pub fn injector_find_process(name: *const c_char) -> c_int;

    pub fn injector_list_modules(
        inj: *mut injector_t,
        out: *mut injector_module_t,
        cap: usize,
    ) -> c_long;

    pub fn injector_resolve_symbol(
        inj: *mut injector_t,
        libname: *const c_char,
        symbol: *const c_char,
        addr: *mut usize,
    ) -> c_int;

    pub fn injector_read_mem(
        inj: *mut injector_t,
        addr: usize,
        buf: *mut c_void,
        len: usize,
    ) -> c_int;

    pub fn injector_write_mem(
        inj: *mut injector_t,
        addr: usize,
        buf: *const c_void,
        len: usize,
    ) -> c_int;

    pub fn injector_remote_func_addr(
        inj: *mut injector_t,
        handle: *mut c_void,
        name: *const c_char,
        addr: *mut usize,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_abi_version() {
        assert_eq!(unsafe { injector_abi_version() }, INJECTOR_ABI_VERSION);
    }

    #[test]
    fn test_version_string() {
        let ptr = unsafe { injector_version_string() };
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(s, "1.0.0");
    }

    #[test]
    fn test_library_init_deinit() {
        assert_eq!(unsafe { injector_library_init() }, 0);
        assert_eq!(unsafe { injector_library_init() }, 0);
        assert_eq!(unsafe { injector_library_deinit() }, 0);
    }
}
