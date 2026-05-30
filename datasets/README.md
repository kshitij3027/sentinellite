# Datasets

SentinelLite is demoed against **real public attack data**, not fabricated logs.

- `curated/` — a small (~50 MB) hand-picked subset committed to the repo so the
  demo works **offline immediately after clone**. Populated in Milestone 4.
- `raw/` — full datasets downloaded on demand by `sentinel datasets fetch`
  (gitignored; checksum-verified). Canonical sources only, zero signup.
- `manifest.json` — source URLs, licenses, and checksums (Milestone 4).

| Dataset | Source | License |
|---|---|---|
| flaws.cloud CloudTrail dump | Summit Route (Scott Piper) | Public research release |
| invictus-ir/aws_dataset | GitHub | MIT |
| Splunk Attack Data | research.splunk.com | Apache-2.0 / MIT |
| GitHub Advisory Database | github/advisory-database | CC BY 4.0 |
| Falco fixtures | falcosecurity/falco | Apache-2.0 |

> The kill chain reconstructed in the demo is built from real attacker activity
> captured on flaws.cloud and Splunk Attack Data — not data I made up.
