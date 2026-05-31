"""B4: the PDF incident report builder produces a valid PDF."""

from __future__ import annotations

from sentinel.report.pdf import build_report

_INV = {
    "id": "inv_test01", "tenant_id": "default", "status": "awaiting_approval",
    "trigger_alert_id": "alt_1", "summary": "Supply-chain compromise -> AWS credential theft -> PII exfil.",
    "scores": {"severity": 100, "confidence": 92, "priority": 100},
    "kill_chain": [
        {"t_offset_s": 28, "stage": "Initial Access", "mitre": "T1195.002", "summary": "Compromised lodash dependency."},
        {"t_offset_s": 128, "stage": "Exfiltration", "mitre": "T1530", "summary": "Mass GetObject on customer-PII bucket."},
    ],
    "actions": [
        {"type": "block_ip", "params": {"cidr": "185.220.101.0/24"}, "requires_second_confirm": False},
        {"type": "revoke_aws_keys", "params": {"user": "svc-legacy"}, "requires_second_confirm": True},
    ],
    "findings": [{"iocs": [{"type": "cve", "value": "CVE-2021-23337"}, {"type": "ip", "value": "185.220.101.45"}]}],
    "data_provenance": {"sources": ["github", "aws_cloudtrail"], "datasets": ["Splunk attack_data", "GitHub Advisory DB"]},
}


def test_build_report_is_valid_pdf():
    pdf = build_report(_INV, audit_ok=True)
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 1500


def test_build_report_handles_empty_investigation():
    pdf = build_report({"id": "inv_empty"}, audit_ok=None)
    assert pdf[:5] == b"%PDF-"
