package injector

type DeliveryMode int

const (
	DeliveryAuto    DeliveryMode = 0
	DeliveryNonstop DeliveryMode = 1
	DeliveryPtrace  DeliveryMode = 2
)

type TimeoutAction int

const (
	TimeoutLeave      TimeoutAction = 0
	TimeoutKillThread TimeoutAction = 1
)

type Opts struct {
	Delivery       DeliveryMode
	CallTimeoutMs  uint
	TimeoutAction  TimeoutAction
	EnableWriteMem bool
}

type TargetInfo struct {
	PID            int
	Alive          bool
	PtraceAllowed  bool
	Arch           string
	Libc           string
	Exe            string
	Cwd            string
	Root           string
	Comm           string
}

type Module struct {
	Name string
	Base uintptr
}

type InvokeResult struct {
	RetVal int64
	ErrMsg string
}
