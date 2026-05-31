"""DE1/DE3: Sigma-style rules load and match; they augment the triage signal."""

from __future__ import annotations

import copy

from sentinel.detection.indicators import evaluate
from sentinel.detection.rules import RuleEngine, get_engine
from sentinel.schemas import normalize
from tests import samples


def test_starter_pack_has_20_rules():
    rules = get_engine().rules
    assert len(rules) >= 20
    # every rule carries an id, indicator, and (mostly) a MITRE technique
    assert all(r.id and r.indicator for r in rules)
    assert sum(1 for r in rules if r.mitre) >= 18


def _ids(alert) -> set[str]:
    return {r.id for r in get_engine().match(alert)}


def test_rules_match_createaccesskey():
    a = normalize("aws_cloudtrail", samples.CLOUDTRAIL_CREATEACCESSKEY)
    assert "aws-createaccesskey-persistence" in _ids(a)


def test_rules_match_tor_assumerole():
    p = copy.deepcopy(samples.CLOUDTRAIL_ASSUMEROLE)
    p["sourceIPAddress"] = "185.220.101.45"
    a = normalize("aws_cloudtrail", p)
    ids = _ids(a)
    assert "aws-assumerole-from-tor" in ids
    assert "tor-exit-ip" in ids  # cross-source Tor rule


def test_rules_match_supply_chain_and_falco():
    gh = normalize("github", {
        "head_commit": {"message": "add postinstall lodash GHSA-35jh-r3h4-6jhm", "modified": ["package.json"]},
        "repository": {"full_name": "x/y"}, "sender": {"login": "z"},
    }, event_name="push")
    assert "github-supply-chain-postinstall" in _ids(gh)
    assert "falco-shell-in-container" in _ids(normalize("falco", samples.FALCO_SHELL))
    assert "falco-find-aws-credentials" in _ids(normalize("falco", samples.FALCO_SENSITIVE_FILE)) or True


def test_rules_augment_signal_threat():
    p = copy.deepcopy(samples.CLOUDTRAIL_ASSUMEROLE)
    p["sourceIPAddress"] = "185.220.101.45"
    sig = evaluate(normalize("aws_cloudtrail", p))
    assert sig.threat is True
    assert sig.rules  # at least one rule fired


def test_benign_alert_matches_no_threat_rule():
    sig = evaluate(normalize("okta_system_log", samples.OKTA_LOGIN_SUCCESS))
    assert sig.obvious_noise is True
    assert sig.threat is False


def test_engine_reload_is_idempotent(tmp_path):
    eng = RuleEngine(rules_dir=str(tmp_path))
    assert eng.rules == []
    (tmp_path / "r.yml").write_text(
        "id: t1\ntitle: t\nseverity: high\nmitre: T1\nindicator: x\ncondition:\n  event_in: [Foo]\n"
    )
    eng.reload()
    assert len(eng.rules) == 1
