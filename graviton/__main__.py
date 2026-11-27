"""Package entrypoint for `python -m graviton`."""
from __future__ import annotations

from graviton.cli.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
