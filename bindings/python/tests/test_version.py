import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import injector


def test_version():
    assert injector.version() == "1.0.0"


def test_abi_version():
    assert injector.abi_version() == 1


def test_library_init_deinit():
    injector.library_init()
    injector.library_init()
    injector.library_deinit()


if __name__ == "__main__":
    test_version()
    print("PASS: test_version")
    test_abi_version()
    print("PASS: test_abi_version")
    test_library_init_deinit()
    print("PASS: test_library_init_deinit")
    print("ALL PASSED")
