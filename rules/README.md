# Detection rules

Sigma-style YAML detection rules (DE1). Files here are **hot-reloaded** by the
worker on change. Each rule maps a normalized-alert condition to a severity and a
MITRE ATT&CK technique. The starter pack of 20 detections lands in Milestone 7 (DE3).

Example shape (final schema defined in `sentinel/detection/`):

```yaml
id: leaked-aws-key-in-ci
title: Leaked AWS access key in CI logs
severity: high
source: github
mitre: T1552.001
condition:
  source_event_type: workflow_run
  match:
    output: "AKIA"
```
