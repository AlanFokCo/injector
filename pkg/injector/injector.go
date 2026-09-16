// Package injector drives the libinjector C API from Go: attach to a running
// Linux process over ptrace, load a shared library into it, call a symbol
// there, and read or write its memory.
//
// # Thread affinity
//
// injector_attach performs PTRACE_ATTACH from the calling OS thread, and every
// later ptrace operation on that handle - injector_detach included - must come
// from that same OS thread. From any other thread the library refuses the
// operation before sending anything to the target, with ErrOther and a message
// naming both tids; the kernel's own answer to such a request would be
// errno == ESRCH. Go normally migrates a goroutine between OS threads, so Attach
// and AttachWithOpts call runtime.LockOSThread and Close calls
// runtime.UnlockOSThread.
//
// Consequences you must respect:
//
//   - Use one *Injector from a single goroutine only; do not share it across
//     goroutines.
//   - Always call Close. The finalizer that Attach installs cannot detach: it
//     runs on an arbitrary thread, where PTRACE_DETACH is refused, and it would
//     also block the runtime's single finalizer goroutine for the length of a
//     remote-call timeout. It only writes a warning to stderr. An *Injector
//     dropped without Close therefore leaves its goroutine pinned to an OS
//     thread and leaves the target process ptrace-stopped, and nothing cleans
//     that up for you.
//   - injector_detach frees the handle unconditionally, including when the
//     detach fails. A refused cross-thread Close still destroys the handle, so
//     the target stays stopped and traced with no handle left to detach it
//     with. Close clears its own pointer before returning, so calling it a
//     second time yields nil rather than handing a freed handle back to the C
//     API.
//
// # Supported targets
//
// This library ships x86_64 (LP64) and i386 runtimes. x32 is not a supported
// runtime: attaching to an x32-ABI target (EM_X86_64 with ELFCLASS32) is
// refused with ErrUnsupportedTarget.
package injector

// #cgo CFLAGS: -I./
// #cgo LDFLAGS: -L./ -linjector
// #include "injector.h"
// #include <stdlib.h>
// /* No -ldl and no -lrt: libinjector calls dlopen/dlsym only inside the target,
//  * through generated shellcode, never in its own code, so the archive has no
//  * undefined dl* symbols, and clock_gettime has been in libc since glibc 2.17.
//  * libinjector.pc.in links the same way for C consumers. */
import "C"
import (
	"fmt"
	"os"
	"runtime"
	"unsafe"
)

// MaxInvokeArgs is the largest number of arguments that Invoke and Run accept;
// it is INJECTOR_MAX_INVOKE_ARGS from the C header. Both reject a longer slice
// with a plain error before calling into the library.
const MaxInvokeArgs = int(C.INJECTOR_MAX_INVOKE_ARGS)

// Injector is a handle to one ptrace attachment to a target process. Attach and
// AttachWithOpts create one and Close destroys it; the zero value is not
// usable.
//
// A handle is thread-affine: drive it, Close included, only from the goroutine
// that created it. Every method answers ErrClosed once the handle is closed.
// LastError reports that same state as a string instead of an error.
type Injector struct {
	inj *C.injector_t
}

// Attach ptrace-attaches to pid and returns a handle to it.
//
// It pins the calling goroutine to its OS thread for the lifetime of the
// handle, because the attachment is thread-affine; Close releases the pin. On
// failure the goroutine is unpinned again and the returned error is an
// *InjectorError carrying the library's code - ErrNoProcess when pid is gone,
// ErrPermission when ptrace is refused, ErrUnsupportedTarget for an x32-ABI
// target.
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

// AttachWithOpts is Attach with explicit options: the delivery mode, a
// per-remote-call timeout in milliseconds (CallTimeoutMs 0 means the library's
// 5000 ms default) and the action to take when that timeout expires, plus
// EnableWriteMem, without which WriteMem is refused with ErrPermission. A nil
// opts asks for the library defaults.
//
// Like Attach it pins the calling goroutine to its OS thread until Close.
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
// Attach/AttachWithOpts. It is safe to call more than once: later calls return
// nil without reaching the C API.
//
// The C handle is freed by injector_detach whether or not the detach succeeded,
// so Close always invalidates the receiver. When the detach is refused - a call
// from a goroutine other than the one that attached, which answers ErrOther
// where the kernel would have said ESRCH - that error is returned and the target
// is left stopped and traced with no handle left to detach it with.
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

// Inject loads the shared library at path into the target and returns an opaque
// handle for Uninject and RemoteFuncAddr. The error is ErrClosed on a closed
// receiver, otherwise an *InjectorError carrying the library's code.
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

// Uninject unloads (dlcloses) the library that Inject returned handle for. The
// error is ErrClosed on a closed receiver, otherwise an *InjectorError from the
// library.
func (i *Injector) Uninject(handle uintptr) error {
	if i == nil || i.inj == nil {
		return ErrClosed
	}
	rc := C.injector_uninject(i.inj, unsafe.Pointer(handle))
	return checkErr(rc, i.inj)
}

// UninjectAll unloads every library this handle injected. The remaining
// libraries are still attempted after one fails, and the error is the first
// non-zero code the library reported - or ErrClosed on a closed receiver.
func (i *Injector) UninjectAll() error {
	if i == nil || i.inj == nil {
		return ErrClosed
	}
	rc := C.injector_uninject_all(i.inj)
	return checkErr(rc, i.inj)
}

// Invoke injects the library at path, resolves symbol in it, calls it and
// returns what it returned. symbol must name a function returning intptr_t. On
// x86_64 the call runs in a cloned helper thread when the delivery mode is
// NONSTOP or AUTO, and over ptrace otherwise.
//
// More than MaxInvokeArgs arguments is rejected locally, before any C call. A
// failure comes back as an *InjectorError whose Msg is the library's own errmsg,
// falling back to LastError when that is empty.
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

// ListModules returns the shared libraries loaded in the target. It reads
// /proc/PID/maps and neither ptraces the target nor executes code there, so it
// is safe on an attached handle. A library appears once per contiguous group of
// mappings, so a non-contiguously mapped one can appear twice; anonymous
// mappings and bracketed pseudo-paths such as [vdso] are never listed. Module
// names longer than 255 bytes are truncated, because the C field is a fixed 256
// bytes and part of the stable ABI.
//
// No libraries loaded is reported as (nil, nil), not as an error.
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

// ResolveSymbol returns the address of symbol as loaded in the target, or
// ErrFunctionMissing when it is not there.
//
// libname is accepted for API symmetry and does not scope the lookup: only the
// target executable's own dynamic symbol table is searched, parsed out of
// /proc/PID/exe. There is no remote dlsym and no other loaded library is
// consulted. For a symbol inside a library you injected, use RemoteFuncAddr
// with the handle Inject returned.
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

// ReadMem copies size bytes of the target's memory at addr. A negative size is
// rejected locally and size 0 returns an empty slice without touching the
// target, so no zero-length read ever reaches the library.
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

// WriteMem writes data to the target's memory at addr. It is refused with
// ErrPermission unless the handle was created through AttachWithOpts with
// Opts.EnableWriteMem set: writing into a target is destructive and is off by
// default. Empty data is a no-op, so no zero-length write reaches the library.
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

// RemoteFuncAddr returns the address of the function name inside the library
// that Inject returned handle for, as loaded in the target. handle may also be
// a special value such as RTLD_DEFAULT. The error is ErrClosed on a closed
// receiver, otherwise an *InjectorError from the library.
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

// LastError returns the message the library recorded for this handle's most
// recent failed call. It cannot fail: on a closed receiver it returns a fixed
// string saying so, and an empty result means no error was recorded for this
// handle.
func (i *Injector) LastError() string {
	if i == nil || i.inj == nil {
		return "injector: handle is closed"
	}
	return C.GoString(C.injector_last_error(i.inj))
}

// --- Package-level functions ---

// Run attaches to pid, injects lib, calls symbol with args and detaches again,
// and returns what symbol returned. symbol must name a function returning
// intptr_t; a nil opts asks for the library defaults.
//
// The whole sequence happens inside one C call, which cgo runs start to finish
// on a single OS thread, so Run takes no OS-thread pin and leaves no handle
// behind to Close. More than MaxInvokeArgs arguments is rejected locally. On
// failure the error carries the library's own errmsg when it set one.
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

// GetTargetInfo reads /proc/PID for pid and reports its architecture, libc,
// executable, cwd, root and comm. It does not ptrace-attach, so it is safe to
// call before deciding whether to inject. The error is ErrNoProcess when pid
// does not exist and ErrOther on a read error; a field that could not be read
// comes back empty.
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

// CanAttach reports whether Attach would probably succeed. It is a best-effort
// heuristic over /proc/sys/kernel/yama/ptrace_scope and the caller's euid and
// does not attach; Attach itself is the authoritative check.
func CanAttach(pid int) bool {
	return C.injector_can_attach(C.pid_t(pid)) != 0
}

// FindProcess returns the pid of a running process whose executable basename is
// name, by scanning /proc and comparing each /proc/PID/exe link. No such process
// is a normal outcome rather than a failure of the scan, and is reported as
// (-1, error).
func FindProcess(name string) (int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	pid := C.injector_find_process(cname)
	if pid < 0 {
		return -1, fmt.Errorf("process not found: %s", name)
	}
	return int(pid), nil
}

// ABIVersion returns the ABI version the loaded library was built with, to be
// compared against the one your headers carry before a handle is trusted.
func ABIVersion() uint {
	return uint(C.injector_abi_version())
}

// Version returns the library's version as a string, for example "1.0.0".
func Version() string {
	return C.GoString(C.injector_version_string())
}

// LibraryInit runs the library's initialisation hook. It is idempotent, so
// calling it more than once is supported, and it is currently a near-no-op that
// exists so a program can initialise the library at a predictable point.
func LibraryInit() error {
	rc := C.injector_library_init()
	return checkErr(rc, nil)
}

// LibraryDeinit is the idempotent counterpart of LibraryInit. It does not
// detach live handles; Close those first.
func LibraryDeinit() error {
	rc := C.injector_library_deinit()
	return checkErr(rc, nil)
}
