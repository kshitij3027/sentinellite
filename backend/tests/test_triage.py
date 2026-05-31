"""R3/R4 deterministic core: indicator detection, MITRE classification, scoring,
and the auto-close/escalate decision (no LLM, no DB)."""

from __future__ import annotations

import copy

from sentinel.agents.triage import _decision, deterministic_scores
from sentinel.detection.indicators import evaluate
from sentinel.mitre import CATALOG, classify
from sentinel.schemas import normalize
from tests import samples


def _tor_assumerole():
    p = copy.deepcopy(samples.CLOUDTRAIL_ASSUMEROLE)
    p["sourceIPAddress"] = "185.220.101.45"
    p["userIdentity"]["sessionContext"] = {"attributes": {"mfaAuthenticated": "false"}}
    return normalize("aws_cloudtrail", p)


def _find_aws_creds():
    return normalize("falco", {
        "rule": "Find AWS Credentials", "priority": "Warning", "source": "syscall",
        "time": "2026-05-30T13:44:38Z",
        "output_fields": {"proc.cmdline": "grep -r AKIA /root/.aws/credentials",
                          "proc.name": "grep", "container.id": "ci-runner-12", "user.name": "root"},
        "tags": ["mitre_credential_access", "T1552"],
    })


def _supply_chain_push():
    return normalize("github", {
        "ref": "refs/heads/main",
        "head_commit": {"message": "bump deps", "added": [], "modified": ["package.json", "package-lock.json"]},
        "commits": [{"message": "postinstall hook added via lodash GHSA-35jh-r3h4-6jhm"}],
        "repository": {"full_name": "teampcp/api"}, "sender": {"login": "ci-bot"},
    }, event_name="push")


# ---------------- MITRE classification ----------------

def test_mitre_ids_are_valid():
    assert classify(normalize("aws_cloudtrail", samples.CLOUDTRAIL_CREATEACCESSKEY)) == ["T1098.001"]
    assert classify(_tor_assumerole()) == ["T1078.004"]
    assert "T1552.001" in classify(_find_aws_creds())
    assert "T1059.004" in classify(normalize("falco", samples.FALCO_SHELL))
    assert classify(_supply_chain_push()) == ["T1195.002"]
    g = normalize("aws_cloudtrail", samples.CLOUDTRAIL_GETOBJECT)  # bucket acme-secrets
    assert classify(g) == ["T1530"]
    for tid in ("T1195.002", "T1059.004", "T1552.001", "T1078.004", "T1098.001", "T1530"):
        assert tid in CATALOG


# ---------------- indicators ----------------

def test_threat_indicators_detected():
    assert "persistence_key" in evaluate(normalize("aws_cloudtrail", samples.CLOUDTRAIL_CREATEACCESSKEY)).matched
    tor = evaluate(_tor_assumerole())
    assert tor.threat and "tor_exit_ip" in tor.matched and "role_assumption" in tor.matched
    assert "credential_theft" in evaluate(_find_aws_creds()).matched
    sc = evaluate(_supply_chain_push())
    assert sc.threat and "supply_chain_compromise" in sc.matched
    assert "sensitive_bucket_exfil" in evaluate(normalize("aws_cloudtrail", samples.CLOUDTRAIL_GETOBJECT)).matched


def test_obvious_noise_detected():
    okta = evaluate(normalize("okta_system_log", samples.OKTA_LOGIN_SUCCESS))
    assert okta.obvious_noise and not okta.threat
    gh = evaluate(normalize("github", samples.GITHUB_PUSH, event_name="push"))
    assert gh.obvious_noise


def test_benign_cloudtrail_read_is_noise():
    a = normalize("aws_cloudtrail", {
        "eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com",
        "eventTime": "2026-05-30T14:00:00Z", "sourceIPAddress": "34.201.5.9", "readOnly": True,
        "userIdentity": {"arn": "arn:aws:iam::1:role/monitor"},
    })
    assert evaluate(a).obvious_noise


# ---------------- scoring + decision ----------------

def test_noise_autocloses():
    a = normalize("okta_system_log", samples.OKTA_LOGIN_SUCCESS)
    sig = evaluate(a)
    sc = deterministic_scores(a, sig)
    assert sc["severity_label"] in ("info", "low")
    assert sc["confidence"] >= 90
    assert _decision(sc["severity_label"], sc["confidence"], sig) == "auto_close"


def test_threats_escalate():
    for builder in (
        lambda: normalize("aws_cloudtrail", samples.CLOUDTRAIL_CREATEACCESSKEY),
        _tor_assumerole, _find_aws_creds, _supply_chain_push,
        lambda: normalize("falco", samples.FALCO_SHELL),
        lambda: normalize("aws_cloudtrail", samples.CLOUDTRAIL_GETOBJECT),
    ):
        a = builder()
        sig = evaluate(a)
        sc = deterministic_scores(a, sig)
        assert sc["severity_label"] in ("medium", "high", "critical"), a.source_event_type
        assert _decision(sc["severity_label"], sc["confidence"], sig) == "escalate", a.source_event_type


def test_ambiguous_escalates():
    a = normalize("okta_system_log", samples.OKTA_LOGIN_FAILURE)  # medium, proxy, not noise/threat
    sig = evaluate(a)
    sc = deterministic_scores(a, sig)
    assert _decision(sc["severity_label"], sc["confidence"], sig) == "escalate"
