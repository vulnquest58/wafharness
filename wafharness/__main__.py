"""``python -m wafharness`` — the same entry point as the console script."""

from wafharness.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
