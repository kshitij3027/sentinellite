"""AWS CloudTrail event validator + normalizer."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinel.schemas.common import NormalizedAlert, Source, utcnow
from sentinel.types import Severity

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6 = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")

# eventNames a SOC treats as elevated by default (heuristic hint only).
_HIGH_RISK = {
    "CreateAccessKey", "CreateUser", "AttachUserPolicy", "PutUserPolicy",
    "AttachRolePolicy", "PutRolePolicy", "CreateLoginProfile", "UpdateLoginProfile",
    "DeleteTrail", "StopLogging", "PutBucketPolicy", "DeleteBucketPolicy",
    "DisableKey", "ConsoleLogin",
}
_MEDIUM_RISK = {"AssumeRole", "GetSessionToken", "ListAccessKeys", "GetObject", "ListBuckets"}


class CloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    eventVersion: str | None = None
    eventTime: str | None = None
    eventSource: str | None = None
    eventName: str | None = None
    awsRegion: str | None = None
    sourceIPAddress: str | None = None
    userAgent: str | None = None
    userIdentity: dict[str, Any] | None = None
    requestParameters: dict[str, Any] | None = None
    responseElements: dict[str, Any] | None = None
    errorCode: str | None = None
    errorMessage: str | None = None
    eventID: str | None = None
    eventType: str | None = None
    readOnly: bool | None = None
    managementEvent: bool | None = None
    eventCategory: str | None = None
    recipientAccountId: str | None = None
    resources: list[dict[str, Any]] | None = None


def _looks_like_ip(value: str | None) -> bool:
    return bool(value and (_IPV4.match(value) or _IPV6.match(value)))


def _parse_ts(value: str | None) -> datetime:
    if value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return utcnow()


def _actor(ui: dict[str, Any]) -> str | None:
    if not ui:
        return None
    if ui.get("arn"):
        return ui["arn"]
    if ui.get("userName"):
        return ui["userName"]
    issuer = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
    return issuer.get("arn") or issuer.get("userName")


def _mfa(ui: dict[str, Any]) -> str | None:
    return ((ui.get("sessionContext") or {}).get("attributes") or {}).get("mfaAuthenticated")


def _cloud_resource(ev: CloudTrailEvent) -> str | None:
    if ev.resources:
        for r in ev.resources:
            if r.get("ARN"):
                return r["ARN"]
    rp = ev.requestParameters or {}
    for key in ("roleArn", "bucketName", "userName", "policyArn"):
        if rp.get(key):
            return str(rp[key])
    return _actor(ev.userIdentity or {})


def _severity(ev: CloudTrailEvent) -> Severity:
    name = ev.eventName or ""
    if ev.errorCode:
        return "medium"
    if name in _HIGH_RISK:
        # AssumeRole/CreateAccessKey from non-MFA temp creds is the classic theft signal.
        return "high"
    if name == "AssumeRole" or name in _MEDIUM_RISK:
        if _mfa(ev.userIdentity or {}) == "false":
            return "medium"
        return "low"
    return "info"


def to_normalized(payload: dict[str, Any], event_name: str | None = None) -> NormalizedAlert:
    ev = CloudTrailEvent.model_validate(payload)
    ui = ev.userIdentity or {}
    src = (ev.eventSource or "").split(".")[0]  # sts.amazonaws.com -> sts
    set_type = f"{src}:{ev.eventName}" if src and ev.eventName else (ev.eventName or "AwsApiCall")

    ip = ev.sourceIPAddress if _looks_like_ip(ev.sourceIPAddress) else None
    actor = _actor(ui)

    title = f"CloudTrail {ev.eventName or 'event'}"
    if actor:
        title += f" by {actor.split('/')[-1]}"
    if ev.errorCode:
        title += f" (denied: {ev.errorCode})"

    return NormalizedAlert(
        tenant_id="default",
        source=Source.aws_cloudtrail,
        source_event_type=set_type,
        ts=_parse_ts(ev.eventTime),
        severity_hint=_severity(ev),
        title=title,
        actor_identity=actor,
        source_ip=ip,
        asset=ev.recipientAccountId or ev.awsRegion,
        cloud_resource=_cloud_resource(ev),
        raw=payload,
    )
