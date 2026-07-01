pub mod error;
pub mod types;

pub use error::InjectorError;
pub use types::*;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;

pub const MAX_INVOKE_ARGS: usize = injector_sys::INJECTOR_MAX_INVOKE_ARGS;

type Result<T> = std::result::Result<T, InjectorError>;

unsafe fn last_error(inj: *mut injector_sys::injector_t) -> String {
    let p = injector_sys::injector_last_error(inj);
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

fn check(rc: i32, inj: *mut injector_sys::injector_t) -> Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(InjectorError {
            code: rc,
            message: unsafe { last_error(inj) },
        })
    }
}

unsafe fn cstr_array_to_string(arr: *const c_char, _len: usize) -> String {
    if arr.is_null() {
        return String::new();
    }
    CStr::from_ptr(arr).to_string_lossy().into_owned()
}

pub struct Injector {
    raw: *mut injector_sys::injector_t,
}

impl std::fmt::Debug for Injector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injector")
            .field("raw", &self.raw)
            .finish()
    }
}

unsafe impl Send for Injector {}

impl Injector {
    pub fn attach(pid: i32) -> Result<Self> {
        let mut raw: *mut injector_sys::injector_t = ptr::null_mut();
        let rc = unsafe { injector_sys::injector_attach(&mut raw, pid) };
        check(rc, ptr::null_mut())?;
        Ok(Self { raw })
    }

    pub fn attach_with_opts(pid: i32, opts: &Opts) -> Result<Self> {
        let copts = injector_sys::injector_opts_t {
            opts_size: std::mem::size_of::<injector_sys::injector_opts_t>(),
            delivery: opts.delivery as i32,
            call_timeout_ms: opts.call_timeout_ms,
            timeout_action: opts.timeout_action as i32,
            enable_write_mem: if opts.enable_write_mem { 1 } else { 0 },
        };
        let mut raw: *mut injector_sys::injector_t = ptr::null_mut();
        let rc = unsafe { injector_sys::injector_attach_with_opts(&mut raw, pid, &copts) };
        check(rc, ptr::null_mut())?;
        Ok(Self { raw })
    }

    pub fn inject(&mut self, path: &str) -> Result<Handle> {
        let cpath = CString::new(path).map_err(|_| InjectorError {
            code: error::ERR_OTHER,
            message: "path contains null byte".into(),
        })?;
        let mut handle: *mut c_void = ptr::null_mut();
        let rc = unsafe { injector_sys::injector_inject(self.raw, cpath.as_ptr(), &mut handle) };
        check(rc, self.raw)?;
        Ok(Handle(handle as usize))
    }

    pub fn uninject(&mut self, handle: Handle) -> Result<()> {
        let rc = unsafe { injector_sys::injector_uninject(self.raw, handle.0 as *mut c_void) };
        check(rc, self.raw)
    }

    pub fn uninject_all(&mut self) -> Result<()> {
        let rc = unsafe { injector_sys::injector_uninject_all(self.raw) };
        check(rc, self.raw)
    }

    pub fn invoke(&mut self, path: &str, symbol: &str, args: &[isize]) -> Result<InvokeResult> {
        if args.len() > MAX_INVOKE_ARGS {
            return Err(InjectorError {
                code: error::ERR_OTHER,
                message: format!("too many args: {} (max {})", args.len(), MAX_INVOKE_ARGS),
            });
        }
        let cpath = CString::new(path).map_err(|_| InjectorError {
            code: error::ERR_OTHER,
            message: "path contains null byte".into(),
        })?;
        let csym = CString::new(symbol).map_err(|_| InjectorError {
            code: error::ERR_OTHER,
            message: "symbol contains null byte".into(),
        })?;
        let args_ptr = if args.is_empty() { ptr::null() } else { args.as_ptr() };
        let mut result: injector_sys::injector_result_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            injector_sys::injector_invoke(
                self.raw,
                cpath.as_ptr(),
                csym.as_ptr(),
                args_ptr,
                args.len() as i32,
                &mut result,
            )
        };
        if rc != 0 {
            let msg = unsafe { cstr_array_to_string(result.errmsg.as_ptr(), 256) };
            let msg = if msg.is_empty() { unsafe { last_error(self.raw) } } else { msg };
            return Err(InjectorError { code: rc, message: msg });
        }
        Ok(InvokeResult {
            retval: result.retval as i64,
            errmsg: unsafe { cstr_array_to_string(result.errmsg.as_ptr(), 256) },
        })
    }

    pub fn list_modules(&self) -> Result<Vec<Module>> {
        let count = unsafe { injector_sys::injector_list_modules(self.raw, ptr::null_mut(), 0) };
        if count < 0 {
            return Err(InjectorError {
                code: error::ERR_OTHER,
                message: unsafe { last_error(self.raw) },
            });
        }
        if count == 0 {
            return Ok(vec![]);
        }
        let cap = count as usize;
        let mut buf: Vec<injector_sys::injector_module_t> = Vec::with_capacity(cap);
        unsafe { buf.set_len(cap) };
        let n = unsafe { injector_sys::injector_list_modules(self.raw, buf.as_mut_ptr(), cap) };
        if n < 0 {
            return Err(InjectorError {
                code: error::ERR_OTHER,
                message: unsafe { last_error(self.raw) },
            });
        }
        let actual = std::cmp::min(n as usize, cap);
        Ok(buf[..actual]
            .iter()
            .map(|m| Module {
                name: unsafe { cstr_array_to_string(m.name.as_ptr(), 256) },
                base: m.base,
            })
            .collect())
    }

    pub fn resolve_symbol(&self, libname: Option<&str>, symbol: &str) -> Result<usize> {
        let clib = libname
            .map(|s| {
                CString::new(s).map_err(|_| InjectorError {
                    code: error::ERR_OTHER,
                    message: "libname contains null byte".into(),
                })
            })
            .transpose()?;
        let csym = CString::new(symbol).map_err(|_| InjectorError {
            code: error::ERR_OTHER,
            message: "symbol contains null byte".into(),
        })?;
        let mut addr: usize = 0;
        let rc = unsafe {
            injector_sys::injector_resolve_symbol(
                self.raw,
                clib.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                csym.as_ptr(),
                &mut addr,
            )
        };
        check(rc, self.raw)?;
        Ok(addr)
    }

    pub fn read_mem(&self, addr: usize, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let rc = unsafe {
            injector_sys::injector_read_mem(
                self.raw,
                addr,
                buf.as_mut_ptr() as *mut c_void,
                len,
            )
        };
        check(rc, self.raw)?;
        Ok(buf)
    }

    pub fn write_mem(&mut self, addr: usize, data: &[u8]) -> Result<()> {
        let rc = unsafe {
            injector_sys::injector_write_mem(
                self.raw,
                addr,
                data.as_ptr() as *const c_void,
                data.len(),
            )
        };
        check(rc, self.raw)
    }

    pub fn remote_func_addr(&self, handle: &Handle, name: &str) -> Result<usize> {
        let cname = CString::new(name).map_err(|_| InjectorError {
            code: error::ERR_OTHER,
            message: "name contains null byte".into(),
        })?;
        let mut addr: usize = 0;
        let rc = unsafe {
            injector_sys::injector_remote_func_addr(
                self.raw,
                handle.0 as *mut c_void,
                cname.as_ptr(),
                &mut addr,
            )
        };
        check(rc, self.raw)?;
        Ok(addr)
    }

    pub fn last_error(&self) -> String {
        unsafe { last_error(self.raw) }
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { injector_sys::injector_detach(self.raw) };
            self.raw = ptr::null_mut();
        }
    }
}

// --- Free functions ---

pub fn run(pid: i32, lib: &str, symbol: &str, args: &[isize], opts: Option<&Opts>) -> Result<InvokeResult> {
    if args.len() > MAX_INVOKE_ARGS {
        return Err(InjectorError {
            code: error::ERR_OTHER,
            message: format!("too many args: {} (max {})", args.len(), MAX_INVOKE_ARGS),
        });
    }
    let clib = CString::new(lib).map_err(|_| InjectorError {
        code: error::ERR_OTHER,
        message: "lib contains null byte".into(),
    })?;
    let csym = CString::new(symbol).map_err(|_| InjectorError {
        code: error::ERR_OTHER,
        message: "symbol contains null byte".into(),
    })?;
    let args_ptr = if args.is_empty() { ptr::null() } else { args.as_ptr() };
    let default_opts = Opts::default();
    let o = opts.unwrap_or(&default_opts);
    let copts = injector_sys::injector_opts_t {
        opts_size: std::mem::size_of::<injector_sys::injector_opts_t>(),
        delivery: o.delivery as i32,
        call_timeout_ms: o.call_timeout_ms,
        timeout_action: o.timeout_action as i32,
        enable_write_mem: if o.enable_write_mem { 1 } else { 0 },
    };
    let mut result: injector_sys::injector_result_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        injector_sys::injector_run(
            pid,
            clib.as_ptr(),
            csym.as_ptr(),
            args_ptr,
            args.len() as i32,
            &copts,
            &mut result,
        )
    };
    if rc != 0 {
        let msg = unsafe { cstr_array_to_string(result.errmsg.as_ptr(), 256) };
        let msg = if msg.is_empty() { unsafe { last_error(ptr::null_mut()) } } else { msg };
        return Err(InjectorError { code: rc, message: msg });
    }
    Ok(InvokeResult {
        retval: result.retval as i64,
        errmsg: unsafe { cstr_array_to_string(result.errmsg.as_ptr(), 256) },
    })
}

pub fn get_target_info(pid: i32) -> Result<TargetInfo> {
    let mut info: injector_sys::injector_target_info_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { injector_sys::injector_target_info(pid, &mut info) };
    check(rc, ptr::null_mut())?;
    Ok(TargetInfo {
        pid: info.pid,
        alive: info.alive != 0,
        ptrace_allowed: info.ptrace_allowed != 0,
        arch: if info.arch.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(info.arch) }.to_string_lossy().into_owned()
        },
        libc: if info.libc.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(info.libc) }.to_string_lossy().into_owned()
        },
        exe: unsafe { cstr_array_to_string(info.exe.as_ptr(), 4096) },
        cwd: unsafe { cstr_array_to_string(info.cwd.as_ptr(), 4096) },
        root: unsafe { cstr_array_to_string(info.root.as_ptr(), 4096) },
        comm: unsafe { cstr_array_to_string(info.comm.as_ptr(), 16) },
    })
}

pub fn can_attach(pid: i32) -> bool {
    unsafe { injector_sys::injector_can_attach(pid) != 0 }
}

pub fn find_process(name: &str) -> Option<i32> {
    let cname = CString::new(name).ok()?;
    let pid = unsafe { injector_sys::injector_find_process(cname.as_ptr()) };
    if pid < 0 { None } else { Some(pid) }
}

pub fn abi_version() -> u32 {
    unsafe { injector_sys::injector_abi_version() }
}

pub fn version() -> &'static str {
    unsafe {
        let p = injector_sys::injector_version_string();
        if p.is_null() {
            ""
        } else {
            CStr::from_ptr(p).to_str().unwrap_or("")
        }
    }
}

pub fn library_init() -> Result<()> {
    let rc = unsafe { injector_sys::injector_library_init() };
    check(rc, ptr::null_mut())
}

pub fn library_deinit() -> Result<()> {
    let rc = unsafe { injector_sys::injector_library_deinit() };
    check(rc, ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), "1.0.0");
    }

    #[test]
    fn test_abi_version() {
        assert_eq!(abi_version(), 1);
    }

    #[test]
    fn test_library_init_deinit() {
        library_init().unwrap();
        library_init().unwrap();
        library_deinit().unwrap();
    }

    #[test]
    fn test_attach_invalid_pid() {
        let err = Injector::attach(-1).unwrap_err();
        assert!(err.code != 0);
    }

    #[test]
    fn test_find_process_nonexistent() {
        assert!(find_process("__nonexistent_proc_xyz__").is_none());
    }
}
