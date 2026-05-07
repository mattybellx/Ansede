"""Developer utility wrapper for the community rule registry."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ansede_static.registry import handle_registry_command  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(handle_registry_command(sys.argv[1:], workspace_root=ROOT))
