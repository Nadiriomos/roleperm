import time, unittest
def main():
    t0=time.perf_counter()
    suite=unittest.defaultTestLoader.discover("tests")
    res=unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"\nTook: {time.perf_counter()-t0:.3f}s")
    return 0 if res.wasSuccessful() else 1
if __name__=="__main__":
    raise SystemExit(main())
