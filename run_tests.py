import importlib
import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def discover_test_modules():
    """Every tests/test_*.py module, in name order."""
    modules = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        name = f"tests.{path.stem}"
        try:
            modules.append(importlib.import_module(name))
        except Exception as e:  # import failure is a test failure, not a crash
            print(f"Import error in {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
            modules.append(None)
    return modules


def run_tests():
    passed = 0
    failed = 0

    print("==================================================")
    print("           DSPM SCANNER TEST SUITE                ")
    print("==================================================")

    only = sys.argv[1:]  # optional substrings to select modules/tests
    for module in discover_test_modules():
        if module is None:
            failed += 1
            continue
        if only and not any(o in module.__name__ for o in only):
            continue
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
                        traceback.print_exc()
                        failed += 1

    print("\n==================================================")
    print(f"Summary: {passed} passed, {failed} failed.")
    print("==================================================")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    os.chdir(ROOT)
    run_tests()
