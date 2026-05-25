"""Meta tests: package version and surface."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pycryptox as crx
from _helpers import Counter


def test_meta() -> tuple[int, int]:
    print("=" * 60)
    print("meta")
    print("=" * 60)
    c = Counter()

    c.assert_true("__version__ is exposed",
                  lambda: hasattr(crx, "__version__"))
    c.assert_true("__version__ is a str",
                  lambda: isinstance(crx.__version__, str))
    c.assert_eq("__version__ matches the expected release",
                lambda: crx.__version__, "3.0.0")

    p, f = c.summary()
    print(f"\n  meta: {p} passed, {f} failed")
    print("=" * 60)
    return p, f


if __name__ == "__main__":
    p, f = test_meta()
    sys.exit(0 if f == 0 else 1)
