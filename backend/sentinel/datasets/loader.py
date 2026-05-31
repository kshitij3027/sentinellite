"""Load records from the curated real-attack datasets. Handles both NDJSON
(Splunk attack_data) and {"Records":[...]} (CloudTrail S3 delivery) layouts."""

from __future__ import annotations

import json
import pathlib

from sentinel.datasets.manifest import data_root


def _curated(name: str) -> pathlib.Path:
    return data_root() / "curated" / name


def load_cloudtrail(name: str) -> list[dict]:
    txt = _curated(name).read_text().strip()
    if not txt:
        return []
    try:
        d = json.loads(txt)
        if isinstance(d, dict) and isinstance(d.get("Records"), list):
            return d["Records"]
        if isinstance(d, list):
            return d
        return [d]
    except json.JSONDecodeError:
        return [json.loads(line) for line in txt.splitlines() if line.strip()]


def benign_reads(limit: int = 60) -> list[dict]:
    """Real, benign read/list CloudTrail events from invictus-ir for noise."""
    recs = load_cloudtrail("invictus_aws_bulk.json")
    reads = [
        r for r in recs
        if r.get("readOnly") is True or str(r.get("eventName", "")).startswith(("Describe", "List", "Get"))
    ]
    return reads[:limit]


def createaccesskey_events() -> list[dict]:
    return load_cloudtrail("splunk_createaccesskey.json")


def s3_exfil_events() -> list[dict]:
    return load_cloudtrail("splunk_s3_exfil.json")


def console_login_events() -> list[dict]:
    return load_cloudtrail("splunk_login_sfa.json")


def lodash_advisory() -> dict:
    return json.loads(_curated("ghsa_lodash.json").read_text())
