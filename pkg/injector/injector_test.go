package injector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	v := Version()
	if v != "1.0.0" {
		t.Fatalf("expected 1.0.0, got %s", v)
	}
}

func TestABIVersion(t *testing.T) {
	if ABIVersion() != 1 {
		t.Fatalf("expected ABI version 1, got %d", ABIVersion())
	}
}

func TestLibraryInitDeinit(t *testing.T) {
	if err := LibraryInit(); err != nil {
		t.Fatal(err)
	}
	if err := LibraryInit(); err != nil {
		t.Fatal("second init should be idempotent:", err)
	}
	if err := LibraryDeinit(); err != nil {
		t.Fatal(err)
	}
}

func TestAttachInvalidPid(t *testing.T) {
	_, err := Attach(-1)
	if err == nil {
		t.Fatal("expected error for invalid pid")
	}
	ie, ok := err.(*InjectorError)
	if !ok {
		t.Fatalf("expected *InjectorError, got %T", err)
	}
	if ie.Code != ErrNoProcess {
		// Hard assertion, not a t.Logf: Attach(-1) is deterministic. injector.c
		// rejects pid <= 1 before it ever touches /proc or ptrace, mapping that
		// straight to INJERR_NO_PROCESS, so any other code means the validation
		// path changed and must fail the test rather than be logged away.
		t.Errorf("Attach(-1): got code %d, want %d (INJERR_NO_PROCESS), msg: %s",
			ie.Code, ErrNoProcess, ie.Msg)
	}
}

func TestFindProcessNonexistent(t *testing.T) {
	_, err := FindProcess("__nonexistent_proc_xyz__")
	if err == nil {
		t.Fatal("expected error for nonexistent process")
	}
}

// TestClosedHandleIsSafe is a regression test for a segfault: every method used
// to forward a NULL injector_t* straight into the C API, which dereferences it
// unconditionally and killed the whole Go process (uncatchable).
func TestClosedHandleIsSafe(t *testing.T) {
	i := &Injector{} // nil C handle, i.e. "already closed"
	if _, err := i.Inject("/tmp/whatever.so"); !errors.Is(err, ErrClosed) {
		t.Errorf("Inject: got %v, want ErrClosed", err)
	}
	if err := i.Uninject(0); !errors.Is(err, ErrClosed) {
		t.Errorf("Uninject: got %v, want ErrClosed", err)
	}
	if err := i.UninjectAll(); !errors.Is(err, ErrClosed) {
		t.Errorf("UninjectAll: got %v, want ErrClosed", err)
	}
	if _, err := i.Invoke("/tmp/x.so", "f"); !errors.Is(err, ErrClosed) {
		t.Errorf("Invoke: got %v, want ErrClosed", err)
	}
	if _, err := i.ListModules(); !errors.Is(err, ErrClosed) {
		t.Errorf("ListModules: got %v, want ErrClosed", err)
	}
	if _, err := i.ResolveSymbol("", "malloc"); !errors.Is(err, ErrClosed) {
		t.Errorf("ResolveSymbol: got %v, want ErrClosed", err)
	}
	if _, err := i.ReadMem(0x1000, 16); !errors.Is(err, ErrClosed) {
		t.Errorf("ReadMem: got %v, want ErrClosed", err)
	}
	if err := i.WriteMem(0x1000, []byte{1, 2, 3}); !errors.Is(err, ErrClosed) {
		t.Errorf("WriteMem: got %v, want ErrClosed", err)
	}
	if _, err := i.RemoteFuncAddr(0, "f"); !errors.Is(err, ErrClosed) {
		t.Errorf("RemoteFuncAddr: got %v, want ErrClosed", err)
	}
	if err := i.Close(); err != nil { // double Close must stay a no-op
		t.Errorf("Close on closed handle: got %v, want nil", err)
	}
	var nilInj *Injector
	if err := nilInj.Close(); err != nil {
		t.Errorf("Close on nil receiver: got %v, want nil", err)
	}
}

// TestAttachUnderSchedulingPressure is a regression test for the missing
// runtime.LockOSThread: PTRACE_ATTACH binds the tracee to the attaching OS
// thread, so if Go migrates the goroutine the later ptrace calls and the final
// PTRACE_DETACH fail with EPERM and the target is left stopped forever.
func TestAttachUnderSchedulingPressure(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a target process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	// Wait until the target has finished execve and has libc mapped. Attaching
	// inside the execve window sees a transitional /proc/<pid>/maps and fails
	// with INJERR_NO_LIBRARY ("Could not find libc"), which would make this
	// test flaky for reasons unrelated to thread affinity.
	waitForLibc(t, cmd.Process.Pid)

	stop := make(chan struct{})
	for k := 0; k < 4; k++ {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					runtime.Gosched()
				}
			}
		}()
	}
	defer close(stop)

	done := make(chan error, 1)
	go func() {
		inj, err := Attach(cmd.Process.Pid)
		if err != nil {
			done <- fmt.Errorf("Attach: %w", err)
			return
		}
		if _, err := inj.ListModules(); err != nil {
			_ = inj.Close()
			done <- fmt.Errorf("ListModules: %w", err)
			return
		}
		done <- inj.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ptrace session failed under scheduling pressure: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("timed out: target may have been left ptrace-stopped")
	}
}

// waitForLibc blocks until /proc/<pid>/maps shows a libc mapping, so tests do
// not race with the target's execve.
func waitForLibc(t *testing.T, pid int) {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/maps", pid)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && bytes.Contains(b, []byte("libc")) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("target %d never mapped libc (execve race or unexpected environment)", pid)
}

// TestCloseAfterTargetDied is a regression test for a heap use-after-free in
// Close(): injector_detach() frees the C handle, and Close() then passed that
// same handle to checkErr(), which forwards it to injector_last_error() - a
// function that dereferences inj->errmsg. The read only happens when the detach
// *fails*, so this test forces that: it attaches to a target it started itself,
// SIGKILLs and reaps that target while the handle is still attached, and then
// calls Close(). PTRACE_DETACH on a pid that is gone fails with ESRCH, which
// injector_detach() reports as a non-zero rc. Under a sanitizer (or with the old
// code on a recycled heap block) the stale read crashes or reports; either way
// Close() must come back with a non-nil error carrying a non-empty message.
func TestCloseAfterTargetDied(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start a target process: %v", err)
	}
	reaped := false
	defer func() {
		// Never signal a pid we already reaped: it may have been recycled, and
		// the one thing this test must not do is touch a process it did not
		// start itself.
		if reaped {
			return
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	// Do not attach inside the target's execve window (see waitForLibc).
	waitForLibc(t, cmd.Process.Pid)

	inj, err := Attach(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("Attach(%d) failed: %v - this test needs ptrace permission "+
			"(CAP_SYS_PTRACE, or /proc/sys/kernel/yama/ptrace_scope <= 1 for a "+
			"child of this process)", cmd.Process.Pid, err)
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("Kill(%d): %v", cmd.Process.Pid, err)
	}
	reapUntilDead(t, cmd.Process.Pid)
	reaped = true

	err = inj.Close() // the call under test: must return, not crash
	if err == nil {
		t.Fatal("Close() after the target died returned nil: injector_detach " +
			"should have failed with ESRCH, so the error path was never reached")
	}
	ie, ok := err.(*InjectorError)
	if !ok {
		t.Fatalf("Close() returned %T (%v), want *InjectorError", err, err)
	}
	if ie.Code != ErrNoProcess {
		// Hard assertion, deliberately not a Fatalf: the second-Close and
		// ListModules checks below must still run. This is deterministic, not
		// flaky - the target was reaped by reapUntilDead, so the remote munmap
		// that injector_detach performs first hits PTRACE_SETREGS on a tracee
		// that no longer exists and the kernel answers ESRCH, i.e.
		// INJERR_NO_PROCESS. Any other code (INJERR_WAIT_TRACEE, ...) means the
		// detach error path changed and must fail the test instead of being
		// logged away.
		t.Errorf("Close() after the target died: got code %d, want %d "+
			"(INJERR_NO_PROCESS), msg: %s", ie.Code, ErrNoProcess, ie.Msg)
	}
	if ie.Msg == "" {
		t.Error("detach error carries an empty message: the thread-local error " +
			"buffer was not read back (checkErr must be called with a nil handle)")
	}

	// The handle must be released exactly once: a second Close is a no-op and
	// every method now answers ErrClosed instead of touching freed memory.
	if err := inj.Close(); err != nil {
		t.Errorf("second Close(): got %v, want nil", err)
	}
	if _, err := inj.ListModules(); !errors.Is(err, ErrClosed) {
		t.Errorf("ListModules after Close(): got %v, want ErrClosed", err)
	}
}

// reapUntilDead drains wait4(pid) until the kernel reports the child as exited.
// Draining matters rather than a single cmd.Process.Wait(): a ptrace-stop
// notification can still be queued in front of the death, and Process.Wait()
// returns that stop status without reaping, which would leave the pid alive and
// make the PTRACE_DETACH below succeed instead of failing with ESRCH. WNOHANG
// keeps the deadline enforceable.
func reapUntilDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var ws syscall.WaitStatus
		got, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
		if err != nil {
			switch {
			case errors.Is(err, syscall.EINTR):
				continue
			case errors.Is(err, syscall.ECHILD):
				return // already reaped; the pid is gone either way
			default:
				t.Fatalf("wait4(%d): %v", pid, err)
			}
		}
		if got == 0 {
			time.Sleep(5 * time.Millisecond) // still alive / still a stop status
			continue
		}
		if ws.Exited() || ws.Signaled() {
			return // dead and reaped
		}
	}
	t.Fatalf("target %d was not reaped within 10s after SIGKILL", pid)
}
