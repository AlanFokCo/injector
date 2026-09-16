//! Rust bindings for `libinjector`: attach to a running Linux process over
//! ptrace, load a shared library into it, call a symbol there, and read or write
//! its memory.
//!
//! # Thread affinity: `Injector` is deliberately NOT `Send`/`Sync`
//!
//! `injector_attach` performs `PTRACE_ATTACH` from the calling OS thread and
//! every later ptrace operation on that handle - including the `PTRACE_DETACH`
//! in [`Drop`] - must come from the same thread. From any other thread the
//! library refuses the operation before sending anything to the target, with
//! [`error::ERR_OTHER`] and a message naming both tids; the kernel's own answer
//! to such a request would be `errno == ESRCH`.
//!
//! `Injector` is therefore not `Send`. An `unsafe impl Send` would make it
//! possible, from 100% safe Rust, to move a handle to another thread:
//!
//! ```compile_fail
//! use injector::Injector;
//! let inj = Injector::attach(std::process::id() as i32).unwrap();
//! std::thread::spawn(move || drop(inj)).join().unwrap();
//! ```
//!
//! The ptrace calls then fail with `EPERM` and the target process is left
//! stopped forever. The raw pointer field already makes the type
//! `!Send`/`!Sync`, so no impl is needed; use one [`Injector`] from one thread.
//!
//! [`Drop`] calls `injector_detach`, which frees the C handle whether or not the
//! detach succeeded. A drop that happens on a thread other than the one that
//! attached therefore leaves the target stopped and traced with no handle left
//! to detach it with.
//!
//! # Supported targets
//!
//! This build ships x86_64 (LP64) and i386 runtimes. x32 is not a supported
//! runtime: attaching to an x32-ABI target (`EM_X86_64` with `ELFCLASS32`)
//! fails with [`error::ERR_UNSUPPORTED_TARGET`].
//!
//! # Example
//!
//! These ask the library about itself, so they need no target process and no
//! privileges:
//!
//! ```
//! assert_eq!(injector::version(), "1.0.0");
//! assert_eq!(injector::abi_version(), 1);
//!
//! // A pid that does not exist is refused rather than attached to.
//! assert!(injector::Injector::attach(-1).is_err());
//!
//! // "No such process" is a normal answer from find_process, so it is None.
//! assert!(injector::find_process("__no_such_process_xyz__").is_none());
//! ```

/// The error type plus one `ERR_*` constant per `INJERR_*` code in the C
/// header.
pub mod error;
/// The value types this crate passes to and from the C API: [`Opts`],
/// [`DeliveryMode`], [`TimeoutAction`], [`TargetInfo`], [`Module`],
/// [`InvokeResult`] and the opaque [`Handle`].
pub mod types;

pub use error::InjectorError;
pub use types::*;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;

/// The largest number of arguments [`Injector::invoke`] and [`run`] accept;
/// this is `INJECTOR_MAX_INVOKE_ARGS` from the C header. Both reject a longer
/// slice with [`error::ERR_OTHER`] before calling into the library.
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

/// Convert a fixed-size C `char[N]` buffer to a String.
///
/// `_len` used to be ignored and `CStr::from_ptr` scanned until it happened to
/// find a NUL, which reads past the end of the array if the C side did not
/// terminate it. The scan is now bounded by `len`.
unsafe fn cstr_array_to_string(arr: *const c_char, len: usize) -> String {
    if arr.is_null() || len == 0 {
        return String::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(arr as *const u8, len) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(len);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// A ptrace attachment to one target process.
///
/// Create one with [`Injector::attach`] or [`Injector::attach_with_opts`] and
/// drive it from that thread only. The type is `!Send`/`!Sync` because the
/// attachment belongs to the OS thread that made it; see the crate-level docs.
/// [`Drop`] detaches.
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

impl Injector {
    /// Attaches to `pid` and returns a handle bound to this thread.
    ///
    /// The error carries the library's code: [`error::ERR_NO_PROCESS`] when
    /// `pid` is gone, [`error::ERR_PERMISSION`] when ptrace is refused,
    /// [`error::ERR_UNSUPPORTED_TARGET`] for an x32-ABI target.
    pub fn attach(pid: i32) -> Result<Self> {
        let mut raw: *mut injector_sys::injector_t = ptr::null_mut();
        let rc = unsafe { injector_sys::injector_attach(&mut raw, pid) };
        check(rc, ptr::null_mut())?;
        Ok(Self { raw })
    }

    /// Attaches to `pid` with explicit options: the delivery mode, a
    /// per-remote-call timeout in milliseconds (`call_timeout_ms == 0` means the
    /// library's 5000 ms default), the action to take when that timeout expires,
    /// and `enable_write_mem`, without which [`Injector::write_mem`] is refused
    /// with [`error::ERR_PERMISSION`].
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

    /// Loads the shared library at `path` into the target and returns an opaque
    /// [`Handle`] for [`Injector::uninject`] and
    /// [`Injector::remote_func_addr`].
    ///
    /// A `path` containing a NUL byte is rejected locally with
    /// [`error::ERR_OTHER`] instead of being truncated at it.
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

    /// Unloads (`dlclose`s) the library that [`Injector::inject`] returned
    /// `handle` for.
    pub fn uninject(&mut self, handle: Handle) -> Result<()> {
        let rc = unsafe { injector_sys::injector_uninject(self.raw, handle.0 as *mut c_void) };
        check(rc, self.raw)
    }

    /// Unloads every library this handle injected. The remaining ones are still
    /// attempted after a failure, and the error is the first non-zero code the
    /// library reported.
    pub fn uninject_all(&mut self) -> Result<()> {
        let rc = unsafe { injector_sys::injector_uninject_all(self.raw) };
        check(rc, self.raw)
    }

    /// Injects the library at `path`, resolves `symbol` in it, calls it with
    /// `args` and returns what it returned. `symbol` must name a function
    /// returning `intptr_t`.
    ///
    /// More than [`MAX_INVOKE_ARGS`] arguments is rejected locally, before any C
    /// call. On x86_64 the call runs in a cloned helper thread when the delivery
    /// mode is `NONSTOP` or `AUTO`, and over ptrace otherwise.
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
            let msg = unsafe { cstr_array_to_string(result.errmsg.as_ptr(), result.errmsg.len()) };
            let msg = if msg.is_empty() { unsafe { last_error(self.raw) } } else { msg };
            return Err(InjectorError { code: rc, message: msg });
        }
        Ok(InvokeResult {
            retval: result.retval as i64,
            errmsg: unsafe { cstr_array_to_string(result.errmsg.as_ptr(), result.errmsg.len()) },
        })
    }

    /// Lists the shared libraries loaded in the target. This reads
    /// `/proc/PID/maps` and neither ptraces the target nor executes code there.
    ///
    /// A library is listed once per contiguous group of mappings, so a
    /// non-contiguously mapped one can appear twice; anonymous mappings and
    /// bracketed pseudo-paths such as `[vdso]` are never listed. Names longer
    /// than 255 bytes are truncated, because the C field is a fixed 256 bytes
    /// and part of the stable ABI.
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
        // `Vec::with_capacity` + `set_len` would expose uninitialised
        // `injector_module_t` values (UB) if C wrote fewer than `cap` entries.
        // Zero-initialise instead: the struct is plain integers plus a char
        // array, so all-zero is a valid bit pattern.
        let mut buf: Vec<injector_sys::injector_module_t> = (0..cap)
            .map(|_| unsafe { std::mem::zeroed::<injector_sys::injector_module_t>() })
            .collect();
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
                name: unsafe { cstr_array_to_string(m.name.as_ptr(), m.name.len()) },
                base: m.base,
            })
            .collect())
    }

    /// Returns the address of `symbol` as loaded in the target, or
    /// [`error::ERR_FUNCTION_MISSING`] when it is not there.
    ///
    /// `libname` is accepted for API symmetry and does not scope the lookup:
    /// only the target executable's own dynamic symbol table is searched, parsed
    /// out of `/proc/PID/exe`. There is no remote `dlsym` and no other loaded
    /// library is consulted. For a symbol inside a library you injected, use
    /// [`Injector::remote_func_addr`] with the [`Handle`] from
    /// [`Injector::inject`].
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

    /// Copies `len` bytes of the target's memory at `addr`.
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

    /// Writes `data` to the target's memory at `addr`.
    ///
    /// Refused with [`error::ERR_PERMISSION`] unless the handle came from
    /// [`Injector::attach_with_opts`] with `enable_write_mem` set: writing into
    /// a target is destructive and is off by default.
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

    /// Returns the address of the function `name` inside the library that
    /// [`Injector::inject`] returned `handle` for, as loaded in the target.
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

    /// Returns the message the library recorded for this handle's most recent
    /// failed call. An empty string means no error was recorded for it.
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

/// Attaches to `pid`, injects `lib`, calls `symbol` with `args`, detaches again
/// and returns what `symbol` returned. `symbol` must name a function returning
/// `intptr_t`; `opts` falls back to [`Opts::default()`] when it is `None`.
///
/// The whole sequence happens inside one C call, so no handle outlives it and
/// there is nothing to keep on one thread across calls. More than
/// [`MAX_INVOKE_ARGS`] arguments is rejected locally.
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
        let msg = unsafe { cstr_array_to_string(result.errmsg.as_ptr(), result.errmsg.len()) };
        let msg = if msg.is_empty() { unsafe { last_error(ptr::null_mut()) } } else { msg };
        return Err(InjectorError { code: rc, message: msg });
    }
    Ok(InvokeResult {
        retval: result.retval as i64,
        errmsg: unsafe { cstr_array_to_string(result.errmsg.as_ptr(), result.errmsg.len()) },
    })
}

/// Reads `/proc/PID` for `pid` and reports its architecture, libc, executable,
/// cwd, root and comm. It does not ptrace-attach, so it is safe to call before
/// deciding whether to inject. A field that could not be read comes back empty.
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
        exe: unsafe { cstr_array_to_string(info.exe.as_ptr(), info.exe.len()) },
        cwd: unsafe { cstr_array_to_string(info.cwd.as_ptr(), info.cwd.len()) },
        root: unsafe { cstr_array_to_string(info.root.as_ptr(), info.root.len()) },
        comm: unsafe { cstr_array_to_string(info.comm.as_ptr(), info.comm.len()) },
    })
}

/// Reports whether [`Injector::attach`] would probably succeed. This is a
/// best-effort heuristic over `/proc/sys/kernel/yama/ptrace_scope` and the
/// caller's euid and does not attach; `attach` itself is the authoritative
/// check.
pub fn can_attach(pid: i32) -> bool {
    unsafe { injector_sys::injector_can_attach(pid) != 0 }
}

/// Returns the pid of a running process whose executable basename is `name`, by
/// scanning `/proc` and comparing each `/proc/PID/exe` link.
///
/// No such process is a normal outcome rather than a failure of the scan, so it
/// is reported as `None`. A `name` containing a NUL byte is `None` too, because
/// it cannot be passed to C at all.
pub fn find_process(name: &str) -> Option<i32> {
    let cname = CString::new(name).ok()?;
    let pid = unsafe { injector_sys::injector_find_process(cname.as_ptr()) };
    if pid < 0 { None } else { Some(pid) }
}

/// Returns the ABI version the loaded library was built with, to be compared
/// against the one your headers carry before a handle is trusted.
pub fn abi_version() -> u32 {
    unsafe { injector_sys::injector_abi_version() }
}

/// Returns the library's version string, for example `"1.0.0"`.
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

/// Runs the library's initialisation hook. It is idempotent, so calling it more
/// than once is supported, and it is currently a near-no-op that exists so a
/// program can initialise the library at a predictable point.
pub fn library_init() -> Result<()> {
    let rc = unsafe { injector_sys::injector_library_init() };
    check(rc, ptr::null_mut())
}

/// The idempotent counterpart of [`library_init`]. It does not detach live
/// handles; drop those first.
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
