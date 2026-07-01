package injector

import "testing"

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
