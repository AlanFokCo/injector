package injector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
		t.Logf("error code %d (expected %d), msg: %s", ie.Code, ErrNoProcess, ie.Msg)
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
