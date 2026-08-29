import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from tests import test_engine, test_scanners
except ImportError as e:
    print(f"Import error: {str(e)}")
    sys.exit(1)


def run_tests():
    test_modules = [test_engine, test_scanners]
    passed = 0
    failed = 0

    print("==================================================")
    print("           DSPM SCANNER TEST SUITE                ")
    print("==================================================")

    for module in test_modules:
        print(f"\nRunning tests in {module.__name__}...")
        for attr_name in dir(module):
            if attr_name.startswith("test_"):
                test_fn = getattr(module, attr_name)
                if callable(test_fn):
                    try:
                        test_fn()
                        print(f"  [PASS] {attr_name}")
                        passed += 1
                    except Exception as err:
                        print(f"  [FAIL] {attr_name}")
                        print(f"         Error: {type(err).__name__}: {str(err)}")
                        import traceback

                        traceback.print_exc()
                        failed += 1

    print("\n==================================================")
    print(f"Summary: {passed} passed, {failed} failed.")
    print("==================================================")

    if failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    run_tests()
