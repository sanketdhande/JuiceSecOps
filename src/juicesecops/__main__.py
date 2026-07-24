# Lets `python -m juicesecops ...` work; this is the command CI and the
# scripts/run_juice_shop_pipeline*.sh scripts invoke after the scanners run.
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
