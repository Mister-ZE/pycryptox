"""Run the complete Pycryptox test suite."""

import sys
import time

from test_purple import test_purple
from test_blue import test_blue
from test_red import test_red
from test_yellow import test_yellow
from test_purplekeys import test_purplekeys
from test_bluekeys import test_bluekeys


def main() -> None:
    start = time.time()

    results = []
    for name, fn in [
        ("PURPLE", test_purple),
        ("BLUE", test_blue),
        ("RED", test_red),
        ("YELLOW", test_yellow),
        ("purplekeys", test_purplekeys),
        ("bluekeys", test_bluekeys),
    ]:
        print()
        p, f = fn()
        results.append((name, p, f))
        print()

    total_p = sum(r[1] for r in results)
    total_f = sum(r[2] for r in results)

    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    for name, p, f in results:
        status = "PASS" if f == 0 else "FAIL"
        print(f"  {name:20s} {p:3d} passed, {f:3d} failed  [{status}]")
    print("-" * 60)
    print(f"  {'TOTAL':20s} {total_p:3d} passed, {total_f:3d} failed")
    print(f"  duration: {time.time() - start:.2f}s")
    print("=" * 60)
    
    input("ENTER TO QUIT...")


if __name__ == "__main__":
    main()
