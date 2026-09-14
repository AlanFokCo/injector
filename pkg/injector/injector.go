package injector

// #cgo CFLAGS: -I./
// #cgo LDFLAGS: -L./ -linjector -ldl -lrt
// #include "injector.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"os"
	"runtime"
	"unsafe"
)

/*
Thread affinity: injector_attach performs PTRACE_ATTACH from the calling OS
thread, and every subsequent ptrace operation on that handle - including the
final PTRACE_DETACH - must come from the SAME OS thread. Go normally migrates a
goroutine between OS threads, so Attach/AttachWithOpts call runtime.LockOSThread
and Close calls runtime.UnlockOSThread.

Consequences you must respect:
  - Use one *Injector from a single goroutine only; do not share it across
    goroutines.
  - Always call Close. An *Injector that is dropped without Close leaves its
    goroutine pinned to an OS thread and, worse, leaves the target process
    ptrace-stopped. A finalizer makes a best-effort detach and warns on stderr,
    but because it runs on an arbitrary thread the detach may fail with EPERM.
*/

const MaxInvokeArgs = int(C.INJECTOR_MAX_INVOKE_ARGS)

type Injector struct {
	inj *C.injector_t
}

func Attach(pid int) (*Injector, error) {
	// Pin this goroutine to its OS thread for the lifetime of the handle; the
	// ptrace attachment is thread-affine.
	runtime.LockOSThread()
	var inj *C.injector_t
	rc := C.injector_attach(&inj, C.injector_pid_t(pid))
	if err := checkErr(rc, nil); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	return newInjector(inj), nil
}

func AttachWithOpts(pid int, opts *Opts) (*Injector, error) {
	copts := C.injector_opts_t{
		opts_size: C.size_t(unsafe.Sizeof(C.injector_opts_t{})),
	}
	if opts != nil {
		copts.delivery = C.injector_delivery_t(opts.Delivery)
		copts.call_timeout_ms = C.uint(opts.CallTimeoutMs)
		copts.timeout_action = C.injector_timeout_action_t(opts.TimeoutAction)
		if opts.EnableWriteMem {
			copts.enable_write_mem = 1
		}
	}
	runtime.LockOSThread()
	var inj *C.injector_t
	rc := C.injector_attach_with_opts(&inj, C.pid_t(pid), &copts)
	if err := checkErr(rc, nil); err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	return newInjector(inj), nil
}

// newInjector wraps a live C handle and installs a safety-net finalizer.
func newInjector(inj *C.injector_t) *Injector {
	i := &Injector{inj: inj}
	runtime.SetFinalizer(i, func(x *Injector) {
		if x.inj == nil {
			return
		}
		// Deliberately does NOT call injector_detach: the ptrace attachment is
		// bound to the OS thread that attached, and the finalizer runs on an
		// arbitrary thread, so PTRACE_DETACH there fails with ESRCH/EPERM. It
		// would also block the single finalizer goroutine for the length of a
		// remote-call timeout. Warn loudly instead of pretending to clean up.
		fmt.Fprintln(os.Stderr, "injector: an *Injector was garbage collected without Close(); "+
			"the target process is still ptrace-attached and may be left stopped")
	})
	return i
}

// Close detaches from the target and releases the OS-thread pin taken by
// Attach/AttachWithOpts. It is safe to call more than once.
func (i *Injector) Close() error {
	if i == nil || i.inj == nil {
		return nil
	}
	rc := C.injector_detach(i.inj)
	// BLOCKER: injector_detach() frees the handle before it returns, so handing
	// i.inj to checkErr() - which forwards it to injector_last_error(), and that
	// dereferences inj->errmsg - is a heap use-after-free. detach calls
	// injector__set_current(NULL) first, so the message it just recorded for a
	// failed detach lives in the library's thread-local buffer: pass nil to read
	// that instead of the freed handle. (cmd/main.c and the Python binding
	// already read the error this way.)
	err := checkErr(rc, nil)
	i.inj = nil
	runtime.SetFinalizer(i, nil)
	runtime.UnlockOSThread()
	return err
}

func (i *Injector) Inject(path string) (uintptr, error) {
	if i == nil || i.inj == nil {
		return 0, ErrClosed
	}
	cs := C.CString(path)
	defer C.free(unsafe.Pointer(cs))
	var handle unsafe.Pointer
	rc := C.injector_inject(i.inj, cs, &handle)
	if err := checkErr(rc, i.inj); err != nil {
		return 0, err
	}
	return uintptr(handle), nil
}

func (i *Injector) Uninject(handle uintptr) error {
	if i == nil || i.inj == nil {
		return ErrClosed
	}
	rc := C.injector_uninject(i.inj, unsafe.Pointer(handle))
	return checkErr(rc, i.inj)
}

func (i *Injector) UninjectAll() error {
	if i == nil || i.inj == nil {
		return ErrClosed
	}
	rc := C.injector_uninject_all(i.inj)
	return checkErr(rc, i.inj)
}

func (i *Injector) Invoke(path, symbol string, args ...int64) (*InvokeResult, error) {
	if i == nil || i.inj == nil {
		return nil, ErrClosed
	}
	if len(args) > MaxInvokeArgs {
		return nil, fmt.Errorf("too many args: %d (max %d)", len(args), MaxInvokeArgs)
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	var cargs *C.intptr_t
	if len(args) > 0 {
		var buf [MaxInvokeArgs]C.intptr_t
		for i, a := range args {
			buf[i] = C.intptr_t(a)
		}
		cargs = &buf[0]
	}

	var result C.injector_result_t
	rc := C.injector_invoke(i.inj, cpath, csym, cargs, C.int(len(args)), &result)
	if rc != 0 {
		msg := C.GoString(&result.errmsg[0])
		if msg == "" {
			msg = C.GoString(C.injector_last_error(i.inj))
		}
		return nil, &InjectorError{Code: int(rc), Msg: msg}
	}
	return &InvokeResult{
		RetVal: int64(result.retval),
		ErrMsg: C.GoString(&result.errmsg[0]),
	}, nil
}

func (i *Injector) ListModules() ([]Module, error) {
	if i == nil || i.inj == nil {
		return nil, ErrClosed
	}
	count := C.injector_list_modules(i.inj, nil, 0)
	if count < 0 {
		return nil, &InjectorError{Code: ErrOther, Msg: i.LastError()}
	}
	if count == 0 {
		return nil, nil
	}
	buf := make([]C.injector_module_t, int(count))
	n := C.injector_list_modules(i.inj, &buf[0], C.size_t(count))
	if n < 0 {
		return nil, &InjectorError{Code: ErrOther, Msg: i.LastError()}
	}
	// The second call can legitimately report more modules than the buffer
	// could hold (the target may have loaded more in between); only the first
	// `count` slots were actually written, so clamp to avoid phantom entries.
	if n > count {
		n = count
	}
	result := make([]Module, int(n))
	for idx := 0; idx < int(n); idx++ {
		result[idx] = Module{
			Name: C.GoString(&buf[idx].name[0]),
			Base: uintptr(buf[idx].base),
		}
	}
	return result, nil
}

func (i *Injector) ResolveSymbol(libname, symbol string) (uintptr, error) {
	if i == nil || i.inj == nil {
		return 0, ErrClosed
	}
	var clib *C.char
	if libname != "" {
		clib = C.CString(libname)
		defer C.free(unsafe.Pointer(clib))
	}
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))
	var addr C.uintptr_t
	rc := C.injector_resolve_symbol(i.inj, clib, csym, &addr)
	if err := checkErr(rc, i.inj); err != nil {
		return 0, err
	}
	return uintptr(addr), nil
}

func (i *Injector) ReadMem(addr uintptr, size int) ([]byte, error) {
	if i == nil || i.inj == nil {
		return nil, ErrClosed
	}
	if size < 0 {
		return nil, fmt.Errorf("injector: negative read size %d", size)
	}
	if size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, size)
	rc := C.injector_read_mem(i.inj, C.uintptr_t(addr), unsafe.Pointer(&buf[0]), C.size_t(size))
	if err := checkErr(rc, i.inj); err != nil {
		return nil, err
	}
	return buf, nil
}

func (i *Injector) WriteMem(addr uintptr, data []byte) error {
	if i == nil || i.inj == nil {
		return ErrClosed
	}
	if len(data) == 0 {
		return nil // &data[0] would panic on an empty slice
	}
	rc := C.injector_write_mem(i.inj, C.uintptr_t(addr), unsafe.Pointer(&data[0]), C.size_t(len(data)))
	return checkErr(rc, i.inj)
}

func (i *Injector) RemoteFuncAddr(handle uintptr, name string) (uintptr, error) {
	if i == nil || i.inj == nil {
		return 0, ErrClosed
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var addr C.size_t
	rc := C.injector_remote_func_addr(i.inj, unsafe.Pointer(handle), cname, &addr)
	if err := checkErr(rc, i.inj); err != nil {
		return 0, err
	}
	return uintptr(addr), nil
}

func (i *Injector) LastError() string {
	if i == nil || i.inj == nil {
		return "injector: handle is closed"
	}
	return C.GoString(C.injector_last_error(i.inj))
}

// --- Package-level functions ---

func Run(pid int, lib, symbol string, args []int64, opts *Opts) (*InvokeResult, error) {
	if len(args) > MaxInvokeArgs {
		return nil, fmt.Errorf("too many args: %d (max %d)", len(args), MaxInvokeArgs)
	}
	clib := C.CString(lib)
	defer C.free(unsafe.Pointer(clib))
	csym := C.CString(symbol)
	defer C.free(unsafe.Pointer(csym))

	var cargs *C.intptr_t
	if len(args) > 0 {
		var buf [MaxInvokeArgs]C.intptr_t
		for i, a := range args {
			buf[i] = C.intptr_t(a)
		}
		cargs = &buf[0]
	}

	copts := C.injector_opts_t{
		opts_size: C.size_t(unsafe.Sizeof(C.injector_opts_t{})),
	}
	if opts != nil {
		copts.delivery = C.injector_delivery_t(opts.Delivery)
		copts.call_timeout_ms = C.uint(opts.CallTimeoutMs)
		copts.timeout_action = C.injector_timeout_action_t(opts.TimeoutAction)
		if opts.EnableWriteMem {
			copts.enable_write_mem = 1
		}
	}

	var result C.injector_result_t
	rc := C.injector_run(C.pid_t(pid), clib, csym, cargs, C.int(len(args)), &copts, &result)
	if rc != 0 {
		msg := C.GoString(&result.errmsg[0])
		if msg == "" {
			msg = C.GoString(C.injector_last_error(nil))
		}
		return nil, &InjectorError{Code: int(rc), Msg: msg}
	}
	return &InvokeResult{
		RetVal: int64(result.retval),
		ErrMsg: C.GoString(&result.errmsg[0]),
	}, nil
}

func GetTargetInfo(pid int) (*TargetInfo, error) {
	var info C.injector_target_info_t
	rc := C.injector_target_info(C.pid_t(pid), &info)
	if err := checkErr(rc, nil); err != nil {
		return nil, err
	}
	return &TargetInfo{
		PID:           int(info.pid),
		Alive:         info.alive != 0,
		PtraceAllowed: info.ptrace_allowed != 0,
		Arch:          C.GoString(info.arch),
		Libc:          C.GoString(info.libc),
		Exe:           C.GoString(&info.exe[0]),
		Cwd:           C.GoString(&info.cwd[0]),
		Root:          C.GoString(&info.root[0]),
		Comm:          C.GoString(&info.comm[0]),
	}, nil
}

func CanAttach(pid int) bool {
	return C.injector_can_attach(C.pid_t(pid)) != 0
}

func FindProcess(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	pid := C.injector_find_process(cname)
	if pid < 0 {
		return -1, fmt.Errorf("process not found: %s", name)
	}
	return int(pid), nil
}

func ABIVersion() uint {
	return uint(C.injector_abi_version())
}

func Version() string {
	return C.GoString(C.injector_version_string())
}

func LibraryInit() error {
	rc := C.injector_library_init()
	return checkErr(rc, nil)
}

func LibraryDeinit() error {
	rc := C.injector_library_deinit()
	return checkErr(rc, nil)
}
