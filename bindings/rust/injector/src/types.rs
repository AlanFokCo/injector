#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DeliveryMode {
    Auto = 0,
    Nonstop = 1,
    Ptrace = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TimeoutAction {
    Leave = 0,
    KillThread = 1,
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub delivery: DeliveryMode,
    pub call_timeout_ms: u32,
    pub timeout_action: TimeoutAction,
    pub enable_write_mem: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            delivery: DeliveryMode::Auto,
            call_timeout_ms: 0,
            timeout_action: TimeoutAction::Leave,
            enable_write_mem: false,
        }
    }
}

#[derive(Debug)]
pub struct TargetInfo {
    pub pid: i32,
    pub alive: bool,
    pub ptrace_allowed: bool,
    pub arch: String,
    pub libc: String,
    pub exe: String,
    pub cwd: String,
    pub root: String,
    pub comm: String,
}

#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub base: usize,
}

#[derive(Debug)]
pub struct InvokeResult {
    pub retval: i64,
    pub errmsg: String,
}

pub struct Handle(pub(crate) usize);
