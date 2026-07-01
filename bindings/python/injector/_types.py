DELIVERY_AUTO = 0
DELIVERY_NONSTOP = 1
DELIVERY_PTRACE = 2

TIMEOUT_LEAVE = 0
TIMEOUT_KILL_THREAD = 1

MAX_INVOKE_ARGS = 6


class Opts:
    __slots__ = ("delivery", "call_timeout_ms", "timeout_action", "enable_write_mem")

    def __init__(self, delivery=DELIVERY_AUTO, call_timeout_ms=0,
                 timeout_action=TIMEOUT_LEAVE, enable_write_mem=False):
        self.delivery = delivery
        self.call_timeout_ms = call_timeout_ms
        self.timeout_action = timeout_action
        self.enable_write_mem = enable_write_mem


class TargetInfo:
    __slots__ = ("pid", "alive", "ptrace_allowed", "arch", "libc",
                 "exe", "cwd", "root", "comm")

    def __init__(self, pid=0, alive=False, ptrace_allowed=False, arch="",
                 libc="", exe="", cwd="", root="", comm=""):
        self.pid = pid
        self.alive = alive
        self.ptrace_allowed = ptrace_allowed
        self.arch = arch
        self.libc = libc
        self.exe = exe
        self.cwd = cwd
        self.root = root
        self.comm = comm

    def __repr__(self):
        return ("TargetInfo(pid=%r, alive=%r, arch=%r, libc=%r, exe=%r, comm=%r)"
                % (self.pid, self.alive, self.arch, self.libc, self.exe, self.comm))


class Module:
    __slots__ = ("name", "base")

    def __init__(self, name="", base=0):
        self.name = name
        self.base = base

    def __repr__(self):
        return "Module(name=%r, base=0x%x)" % (self.name, self.base)


class InvokeResult:
    __slots__ = ("retval", "errmsg")

    def __init__(self, retval=0, errmsg=""):
        self.retval = retval
        self.errmsg = errmsg

    def __repr__(self):
        return "InvokeResult(retval=%r, errmsg=%r)" % (self.retval, self.errmsg)
