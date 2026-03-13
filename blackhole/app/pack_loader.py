from __future__ import annotations

import json
from pathlib import Path

import yaml

from .models import ReplayPack, ReplayProfile


def _load_obj(path: Path):
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(path.read_text())
    return json.loads(path.read_text())


def load_pack(path: str | Path) -> ReplayPack:
    path = Path(path)
    obj = _load_obj(path)
    if isinstance(obj, dict) and "profiles" in obj:
        return ReplayPack.model_validate(obj)
    if isinstance(obj, list):
        return ReplayPack(name=path.stem, profiles=[ReplayProfile.model_validate(item) for item in obj])
    raise ValueError(f"Unsupported pack format for {path}")
