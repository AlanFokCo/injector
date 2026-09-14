"""End-to-end test of the Python binding against a live target process.

Beyond exercising attach/list/detach through ctypes, this is what actually
validates the hardcoded Structure layouts in _types.py/_ffi.py against the real
C ABI: a field-offset or field-type mismatch shows up here as garbage data or a
crash, not as a clean unit-test failure.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import injector


# --- skip policy -------------------------------------------------------------
# This file is the only end-to-end coverage of the hardcoded ctypes layouts
# against the real C ABI, so "the tests/ artefacts are not built" must not be
# allowed to look like success: the two places that used to `print("SKIP: ...")`
# and `return` left CI green with zero coverage. Failing loudly is now the
# default; INJECTOR_ALLOW_SKIP=1 opts back into skipping, and the runner at the
# bottom counts and prints the skips either way.
_ALLOW_SKIP_ENV = "INJECTOR_ALLOW_SKIP"


def _under_pytest():
    """pytest exports PYTEST_CURRENT_TEST only *while* a test is running, not
    during import, so this has to be asked at call time."""
    return "PYTEST_CURRENT_TEST" in os.environ


class Skipped(Exception):
    """Raised by _require_built() when INJECTOR_ALLOW_SKIP=1 lets a test bail
    out. The runner below catches it and counts it; pytest is handled with
    pytest.skip() instead, so the run reports a skip rather than an error."""


def _require_built(*paths):
    """Assert every build artefact exists, or skip - never silently return."""
    missing = [p for p in paths if not os.path.isfile(p)]
    if not missing:
        return
    reason = ("missing build artefact(s): %s - run `cd tests && make build` "
              "first (or set %s=1 to allow this test to be skipped)"
              % (", ".join(missing), _ALLOW_SKIP_ENV))
    if os.environ.get(_ALLOW_SKIP_ENV) == "1":
        if _under_pytest():
            try:
                import pytest
            except ImportError:
                pass
            else:
                pytest.skip(reason)   # reported as a skip, not an error
        raise Skipped(reason)         # counted by the runner at the bottom
    raise RuntimeError(reason)


def _wait_for_libc(pid, timeout=10.0):
    """Do not attach inside the target's execve window: /proc/<pid>/maps is
    transitional there and libc is not visible yet."""
    deadline = time.time() + timeout
    path = "/proc/%d/maps" % pid
    while time.time() < deadline:
        try:
            with open(path, "rb") as f:
                if b"libc" in f.read():
                    return
        except OSError:
            pass
        time.sleep(0.005)
    raise AssertionError("target %d never mapped libc" % pid)


def test_attach_list_detach():
    proc = subprocess.Popen(["sleep", "30"])
    try:
        _wait_for_libc(proc.pid)

        info = injector.target_info(proc.pid)
        assert info.pid == proc.pid, info
        assert info.alive, "target should be alive"
        assert info.arch, "arch should be reported"

        with injector.Injector(proc.pid) as inj:
            mods = inj.list_modules()
            assert len(mods) > 0, "expected at least one module"
            names = [m.name for m in mods]
            assert any("libc" in n for n in names), names[:8]
            for m in mods:
                assert isinstance(m.base, int) and m.base > 0, m
                assert m.name and "\x00" not in m.name, repr(m.name)

            # Documented behaviour (include/injector.h): resolve_symbol
            # searches ONLY the target executable's .dynsym and libname is
            # reserved/ignored. /usr/bin/sleep exports nothing, so the correct
            # result here is INJERR_FUNCTION_MISSING - assert that, and cover a
            # successful resolve in test_resolve_symbol_in_executable below.
            try:
                inj.resolve_symbol(None, "malloc")
            except injector.FunctionMissingError:
                pass
            else:
                raise AssertionError("expected FunctionMissingError for sleep")

            base = mods[0].base
            data = inj.read_mem(base, 16)
            assert len(data) == 16, len(data)
            assert data[:4] == b"\x7fELF", "mapping does not start with an ELF magic"
            assert inj.read_mem(base, 0) == b""
        # context manager closed it; the target must still be alive and running
        assert proc.poll() is None, "target died (exit=%s)" % proc.poll()
    finally:
        proc.kill()
        proc.wait()


def test_close_releases_the_target():
    """A closed handle must leave the target running, not ptrace-stopped."""
    proc = subprocess.Popen(["sleep", "30"])
    try:
        _wait_for_libc(proc.pid)
        inj = injector.Injector(proc.pid)
        inj.list_modules()
        inj.close()
        inj.close()          # idempotent
        time.sleep(0.3)
        assert proc.poll() is None, "target died after close"
        with open("/proc/%d/status" % proc.pid) as f:
            state = [l for l in f if l.startswith("State:")][0].split()[1]
        assert state in ("S", "R"), "target left in state %s (still stopped?)" % state
        with open("/proc/%d/status" % proc.pid) as f:
            tracer = [l for l in f if l.startswith("TracerPid:")]
        # Not `if tracer:` - /proc/<pid>/status always carries TracerPid, so an
        # empty list means the assertion below was silently skipped, not passed.
        assert len(tracer) == 1, "no TracerPid line in /proc/%d/status" % proc.pid
        assert tracer[0].split()[1] == "0", "target is still being traced"
    finally:
        proc.kill()
        proc.wait()


def test_run_one_shot():
    """injector.run() is the one-shot path (attach, inject, call, detach).

    Uses the repository's own test-target/test-library pair, because
    test-library.so references `exit_value`, which only test-target exports.
    """
    tests_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             "..", "..", "..", "tests"))
    target = os.path.join(tests_dir, "test-target")
    lib = os.path.join(tests_dir, "test-library.so")
    _require_built(target, lib)
    proc = subprocess.Popen([target])
    try:
        _wait_for_libc(proc.pid)
        res = injector.run(proc.pid, lib, "entry_noarg")
        assert res.retval == 42, res
        res = injector.run(proc.pid, lib, "entry_threeargs", args=[1, 2, 3])
        assert res.retval == 6, res
        # the one-shot path must not leave the target stopped or dead
        assert proc.poll() is None, "target died after run()"
        with open("/proc/%d/status" % proc.pid) as f:
            st = dict(l.split(":\t")[:2] for l in f.read().splitlines() if ":\t" in l)
        assert st.get("TracerPid", "0").strip() == "0", "target left traced"
    finally:
        proc.kill()
        proc.wait()





def test_resolve_symbol_in_executable():
    """A successful resolve_symbol + read/write_mem round trip.

    Needs a target whose executable exports symbols, i.e. the repository's own
    test-target (built with -rdynamic, exporting exit_value and probe_val).
    """
    tests_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             "..", "..", "..", "tests"))
    target = os.path.join(tests_dir, "test-target")
    _require_built(target)
    proc = subprocess.Popen([target])
    try:
        _wait_for_libc(proc.pid)

        # write_mem is opt-in: without enable_write_mem it must be refused, and
        # (regression) the resulting error must be catchable as the builtin
        # PermissionError/OSError, which it was not when the classes merely
        # shadowed those names.
        with injector.Injector(proc.pid) as inj:
            addr = inj.resolve_symbol(None, "probe_val")
            assert addr > 0, "could not resolve probe_val"
            value = int.from_bytes(inj.read_mem(addr, 4), sys.byteorder, signed=True)
            assert value == 7, "expected probe_val == 7, read %d" % value
            try:
                inj.write_mem(addr, (99).to_bytes(4, sys.byteorder, signed=True))
            except OSError as e:
                assert isinstance(e, injector.PermissionError), type(e)
            else:
                raise AssertionError("write_mem succeeded without enable_write_mem")

        opts = injector.Opts(enable_write_mem=True)
        with injector.Injector(proc.pid, opts) as inj:
            addr = inj.resolve_symbol(None, "probe_val")
            inj.write_mem(addr, (99).to_bytes(4, sys.byteorder, signed=True))
            got = int.from_bytes(inj.read_mem(addr, 4), sys.byteorder, signed=True)
            assert got == 99, "write_mem round trip failed: %d" % got
    finally:
        proc.kill()
        proc.wait()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, skipped = 0, []
    for fn in fns:
        try:
            fn()
        except Skipped as exc:
            skipped.append(fn.__name__)
            print("SKIP:", fn.__name__, "-", exc)
            continue
        passed += 1
        print("PASS:", fn.__name__)
    print("skips: %d" % len(skipped))
    if passed == 0:
        # All-skipped is a failure, not a green run: this file is the only
        # end-to-end check of the hardcoded ctypes layouts against the real C
        # ABI, so %s=1 turning every test into a skip must not exit 0.
        print("no integration test actually ran (%d skipped) - refusing to "
              "report success: build the tests/ artefacts and drop %s=1"
              % (len(skipped), _ALLOW_SKIP_ENV))
        sys.exit(1)
    print("ALL PASSED (%d tests)" % passed)
