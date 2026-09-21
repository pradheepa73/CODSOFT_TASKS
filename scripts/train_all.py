"""Run every trainer in sequence, skipping missing datasets."""
import importlib
import sys

TRAINERS = [
    "scripts.train_packet",
    "scripts.train_phish",
    "scripts.train_net",
    "scripts.train_access",
]


def main() -> int:
    failures = []
    for name in TRAINERS:
        try:
            mod = importlib.import_module(name)
            print(f"\n=== {name} ===")
            mod.main()
        except FileNotFoundError as e:
            print(f"[skip] {name}: {e}")
        except Exception as e:
            print(f"[fail] {name}: {e}")
            failures.append(name)
    if failures:
        print(f"\nFailures: {failures}")
        return 1
    print("\nAll trainers complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())