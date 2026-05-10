"""Shared test utilities for Pycryptox test suite."""


class Counter:
    """Lightweight test counter with pass/fail tracking."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self._idx = 0

    def _step(self) -> int:
        self._idx += 1
        return self._idx

    def ok(self, label: str) -> None:
        i = self._step()
        self.passed += 1
        print(f"  Test {i} OK -- {label}")

    def fail(self, label: str, err: str) -> None:
        i = self._step()
        self.failed += 1
        print(f"  Test {i} FAIL -- {label}: {err}")

    def assert_ok(self, label: str, fn) -> None:
        try:
            fn()
            self.ok(label)
        except Exception as e:
            self.fail(label, f"{type(e).__name__}: {e}")

    def assert_true(self, label: str, fn) -> None:
        try:
            if fn():
                self.ok(label)
            else:
                self.fail(label, "got falsy")
        except Exception as e:
            self.fail(label, f"{type(e).__name__}: {e}")

    def assert_eq(self, label: str, fn, expected) -> None:
        try:
            v = fn()
            if v == expected:
                self.ok(label)
            else:
                self.fail(label, f"got {v!r}, expected {expected!r}")
        except Exception as e:
            self.fail(label, f"{type(e).__name__}: {e}")

    def assert_raise(self, label: str, exc_type, fn) -> None:
        try:
            fn()
            self.fail(label, f"expected {exc_type.__name__}, no raise")
        except exc_type:
            self.ok(label)
        except Exception as e:
            self.fail(label, f"expected {exc_type.__name__}, got {type(e).__name__}: {e}")

    def summary(self) -> tuple[int, int]:
        return self.passed, self.failed
