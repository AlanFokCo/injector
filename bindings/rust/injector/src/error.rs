use std::fmt;

#[derive(Debug, Clone)]
pub struct InjectorError {
    pub code: i32,
    pub message: String,
}

impl fmt::Display for InjectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "injector error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for InjectorError {}

pub const ERR_SUCCESS: i32 = injector_sys::INJERR_SUCCESS;
pub const ERR_OTHER: i32 = injector_sys::INJERR_OTHER;
pub const ERR_NO_MEMORY: i32 = injector_sys::INJERR_NO_MEMORY;
pub const ERR_NO_PROCESS: i32 = injector_sys::INJERR_NO_PROCESS;
pub const ERR_NO_LIBRARY: i32 = injector_sys::INJERR_NO_LIBRARY;
pub const ERR_ERROR_IN_TARGET: i32 = injector_sys::INJERR_ERROR_IN_TARGET;
pub const ERR_FILE_NOT_FOUND: i32 = injector_sys::INJERR_FILE_NOT_FOUND;
pub const ERR_INVALID_MEMORY_AREA: i32 = injector_sys::INJERR_INVALID_MEMORY_AREA;
pub const ERR_PERMISSION: i32 = injector_sys::INJERR_PERMISSION;
pub const ERR_UNSUPPORTED_TARGET: i32 = injector_sys::INJERR_UNSUPPORTED_TARGET;
pub const ERR_INVALID_ELF: i32 = injector_sys::INJERR_INVALID_ELF_FORMAT;
pub const ERR_WAIT_TRACEE: i32 = injector_sys::INJERR_WAIT_TRACEE;
pub const ERR_FUNCTION_MISSING: i32 = injector_sys::INJERR_FUNCTION_MISSING;
pub const ERR_TIMEOUT: i32 = injector_sys::INJERR_TIMEOUT;
