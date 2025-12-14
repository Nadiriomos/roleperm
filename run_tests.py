import time
import unittest

def main() -> int:
    start = time.perf_counter()
    suite = unittest.defaultTestLoader.discover("tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    elapsed = time.perf_counter() - start
    print(f"\nTook: {elapsed:.3f}s")
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    raise SystemExit(main())
