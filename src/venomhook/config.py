from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def load_profile(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)
