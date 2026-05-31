"""R11/R12: curated dataset integrity, loaders, and the teampcp scenario shape.
Reads the bundled curated files (mounted in the container); no network/DB/LLM."""

from __future__ import annotations

from sentinel.datasets import loader
from sentinel.datasets.manifest import verify_curated
from sentinel.mitre import classify
from sentinel.replay.scenario import build_teampcp, scenario_stats


def test_curated_integrity():
    results = verify_curated()
    assert results, "manifest curated list should be non-empty"
    assert all(r["ok"] for r in results), [r for r in results if not r["ok"]]


def test_loaders_parse_real_data():
    cak = loader.createaccesskey_events()
    assert cak and cak[0].get("eventName") == "CreateAccessKey"  # NDJSON parsed
    exfil = loader.s3_exfil_events()
    assert exfil and exfil[0].get("eventName") == "GetObject"
    reads = loader.benign_reads(limit=30)
    assert reads and all(
        r.get("readOnly") is True or str(r.get("eventName", "")).startswith(("Describe", "List", "Get"))
        for r in reads
    )
    adv = loader.lodash_advisory()
    assert "CVE-2021-23337" in (adv.get("aliases") or [])


def test_teampcp_scenario_shape():
    events = build_teampcp(noise_count=42)
    stats = scenario_stats(events)
    assert stats["malicious"] == 8
    assert stats["benign_pct"] >= 80  # SC3: bulk is auto-closable noise
    # events are time-ordered
    assert [e["t"] for e in events] == sorted(e["t"] for e in events)


def test_teampcp_chain_covers_required_mitre():
    events = build_teampcp(noise_count=10)
    mal = [e for e in events if e["verdict"] == "MALICIOUS"]
    # normalize each malicious payload and confirm MITRE classification
    from sentinel.schemas import normalize

    techniques: set[str] = set()
    for e in mal:
        a = normalize(e["source"], e["payload"], event_name=e.get("event_name"))
        techniques.update(classify(a))
    for required in ("T1195.002", "T1059.004", "T1552.001", "T1078.004", "T1098.001", "T1530"):
        assert required in techniques, f"{required} missing from {techniques}"


def test_real_attack_events_are_used():
    events = build_teampcp(noise_count=5)
    datasets = {e["payload"].get("_dataset", "") for e in events if e["verdict"] == "MALICIOUS"}
    assert any("Splunk attack_data" in d for d in datasets)
    assert any("GitHub Advisory DB" in d for d in datasets)
