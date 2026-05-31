"""Dataset manifest + curated-subset integrity verification (R12)."""

from __future__ import annotations

import hashlib
import json
import pathlib

from sentinel.config import settings


def data_root() -> pathlib.Path:
    return pathlib.Path(settings.replay_data_dir)


def manifest_path() -> pathlib.Path:
    return data_root() / "manifest.json"


def load_manifest() -> dict:
    return json.loads(manifest_path().read_text())


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def verify_curated() -> list[dict]:
    """Check every bundled file against its pinned sha256."""
    out: list[dict] = []
    for e in load_manifest().get("curated", []):
        p = data_root() / e["path"]
        if not p.exists():
            out.append({"name": e["name"], "ok": False, "reason": "missing"})
            continue
        actual = sha256_bytes(p.read_bytes())
        ok = actual == e["sha256"]
        out.append({"name": e["name"], "ok": ok, "bytes": p.stat().st_size,
                    "reason": None if ok else "sha256 mismatch"})
    return out
