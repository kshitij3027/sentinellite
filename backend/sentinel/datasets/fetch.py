"""`sentinel datasets fetch` (R12): verify the curated subset and download the
public source datasets to datasets/raw/ with checksum verification. AIRGAP_MODE
blocks all network calls (MT2) and only verifies the bundled subset."""

from __future__ import annotations

import hashlib

import httpx

from sentinel.config import settings
from sentinel.datasets.manifest import data_root, load_manifest, verify_curated


def raw_dir():
    d = data_root() / "raw"
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_fetch(full: bool = False) -> dict:
    results: dict = {"airgap": settings.airgap_mode, "curated": verify_curated(), "downloaded": []}
    if settings.airgap_mode:
        return results  # MT2: no external network calls

    manifest = load_manifest()
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        for src in manifest.get("sources", []):
            name, url = src["name"], src["url"]
            if name == "flaws_cloudtrail_logs.tar" and not full:
                results["downloaded"].append({"name": name, "skipped": "use --full (~240MB)"})
                continue
            if not url.endswith((".yaml", ".yml", ".json", ".tar")):
                results["downloaded"].append({"name": name, "skipped": "repo/index (not a single file)"})
                continue
            try:
                if url.endswith(".tar"):
                    dest = raw_dir() / name
                    h = hashlib.sha256()
                    with client.stream("GET", url) as r, open(dest, "wb") as f:
                        r.raise_for_status()
                        for chunk in r.iter_bytes(1 << 16):
                            f.write(chunk)
                            h.update(chunk)
                    results["downloaded"].append({"name": name, "bytes": dest.stat().st_size, "sha256": h.hexdigest()})
                else:
                    r = client.get(url)
                    r.raise_for_status()
                    (raw_dir() / name).write_bytes(r.content)
                    actual = hashlib.sha256(r.content).hexdigest()
                    exp = src.get("sha256")
                    results["downloaded"].append({
                        "name": name, "bytes": len(r.content), "sha256": actual,
                        "ok": (exp is None or exp == actual),
                    })
            except Exception as exc:
                results["downloaded"].append({"name": name, "error": str(exc)[:120]})
    return results
