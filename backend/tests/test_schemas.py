"""R1: each source validates against its native schema and normalizes correctly."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel.schemas import SOURCES, normalize
from sentinel.schemas.common import Source
from tests import samples


def test_registry_has_four_sources():
    assert set(SOURCES) == {
        "github",
        "aws_cloudtrail",
        "okta_system_log",
        "falco",
    }


def test_unknown_source_raises():
    with pytest.raises(KeyError):
        normalize("splunk", {})


# ---------------- GitHub ----------------

def test_github_push():
    a = normalize("github", samples.GITHUB_PUSH, event_name="push")
    assert a.source == Source.github.value
    assert a.source_event_type == "push"
    assert a.actor_identity == "alice-dev"
    assert a.repository == "octo-org/sentinel"
    assert a.severity_hint == "info"
    assert a.raw  # original preserved


def test_github_member_added_admin_is_high():
    a = normalize("github", samples.GITHUB_MEMBER_ADDED, event_name="member")
    assert a.source_event_type == "member.added"
    assert a.actor_identity == "alice-admin"
    assert a.severity_hint == "high"  # granted admin


def test_github_type_error_is_rejected():
    with pytest.raises(ValidationError):
        normalize("github", {"commits": "not-a-list"}, event_name="push")


# ---------------- CloudTrail ----------------

def test_cloudtrail_assumerole():
    a = normalize("aws_cloudtrail", samples.CLOUDTRAIL_ASSUMEROLE)
    assert a.source_event_type == "sts:AssumeRole"
    assert a.actor_identity == "arn:aws:iam::123456789012:user/Alice"
    assert a.source_ip == "203.0.113.64"
    assert a.cloud_resource == "arn:aws:iam::123456789012:role/AdminRole"
    assert a.severity_hint == "low"  # MFA was true


def test_cloudtrail_createaccesskey_is_high():
    a = normalize("aws_cloudtrail", samples.CLOUDTRAIL_CREATEACCESSKEY)
    assert a.source_event_type == "iam:CreateAccessKey"
    assert a.severity_hint == "high"


def test_cloudtrail_getobject_no_mfa_is_medium():
    a = normalize("aws_cloudtrail", samples.CLOUDTRAIL_GETOBJECT)
    assert a.source_event_type == "s3:GetObject"
    assert a.source_ip == "198.51.100.22"
    assert a.cloud_resource == "arn:aws:s3:::acme-secrets/prod/db-credentials.json"
    assert a.severity_hint == "medium"  # mfaAuthenticated == "false"


def test_cloudtrail_internal_dns_ip_becomes_none():
    payload = dict(samples.CLOUDTRAIL_ASSUMEROLE)
    payload["sourceIPAddress"] = "cloudformation.amazonaws.com"
    a = normalize("aws_cloudtrail", payload)
    assert a.source_ip is None


# ---------------- Okta ----------------

def test_okta_login_success():
    a = normalize("okta_system_log", samples.OKTA_LOGIN_SUCCESS)
    assert a.source_event_type == "user.session.start"
    assert a.actor_identity == "alice@acme.com"
    assert a.source_ip == "203.0.113.64"
    assert a.severity_hint == "info"


def test_okta_login_failure_from_proxy_is_medium():
    a = normalize("okta_system_log", samples.OKTA_LOGIN_FAILURE)
    assert a.severity_hint == "medium"  # WARN + FAILURE + isProxy
    assert a.source_ip == "198.51.100.200"


def test_okta_sso_captures_app():
    a = normalize("okta_system_log", samples.OKTA_SSO)
    assert a.source_event_type == "user.authentication.sso"
    assert a.cloud_resource == "AWS Account Federation"


# ---------------- Falco ----------------

def test_falco_shell_is_critical():
    a = normalize("falco", samples.FALCO_SHELL)
    assert a.source_event_type == "Terminal shell in container"
    assert a.severity_hint == "critical"
    assert a.process == "sh -c clear; (bash || ash || sh)"
    assert a.asset == "kubecon"
    assert a.actor_identity == "root"


def test_falco_sensitive_file_is_medium():
    a = normalize("falco", samples.FALCO_SENSITIVE_FILE)
    assert a.severity_hint == "medium"
    assert a.process == "cat /etc/shadow"
    assert a.cloud_resource == "docker.io/library/nginx@ee97d9c4186f"


def test_normalized_entities_helper():
    a = normalize("falco", samples.FALCO_SHELL)
    ents = a.entities()
    assert ents["process"] == "sh -c clear; (bash || ash || sh)"
    assert "source_ip" not in ents  # falco has none
