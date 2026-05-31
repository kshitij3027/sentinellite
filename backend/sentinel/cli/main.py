"""The `sentinel` CLI: public-dataset fetching (R12) + attack replay (R11)."""

from __future__ import annotations

import httpx
import typer
from rich.console import Console
from rich.table import Table

from sentinel import __version__
from sentinel.config import settings

app = typer.Typer(name="sentinel", help="SentinelLite CLI — attack replay & dataset fetching.",
                  no_args_is_help=True, add_completion=False)
datasets_app = typer.Typer(help="Manage public attack datasets.", no_args_is_help=True)
attack_app = typer.Typer(help="Replay scripted attack scenarios.", no_args_is_help=True)
rules_app = typer.Typer(help="Detection rules (Sigma-style).", no_args_is_help=True)
app.add_typer(datasets_app, name="datasets")
app.add_typer(attack_app, name="attack")
app.add_typer(rules_app, name="rules")
console = Console()


@rules_app.command("list")
def rules_list() -> None:
    """List loaded detection rules (DE1/DE3)."""
    from sentinel.detection.rules import get_engine

    eng = get_engine()
    t = Table(title=f"Detection rules ({len(eng.rules)})")
    t.add_column("id"); t.add_column("sev"); t.add_column("source"); t.add_column("mitre"); t.add_column("title")
    for r in eng.rules:
        t.add_row(r.id, r.severity, r.source or "any", r.mitre or "-", r.title)
    console.print(t)


@rules_app.command("tune")
def rules_tune(
    tenant: str = typer.Option("default"),
    write: bool = typer.Option(True, help="write candidates to rules/candidates/"),
) -> None:
    """DetectionTunerAgent (DE2): propose rules for escalations not yet covered."""
    import asyncio

    from sentinel.detection.tuner import propose_rules, write_candidates

    proposals = asyncio.run(propose_rules(tenant))
    if not proposals:
        console.print("[green]No detection gaps[/] — existing rules cover all escalated true-positives.")
        raise typer.Exit(0)
    t = Table(title="Proposed detection rules")
    t.add_column("id"); t.add_column("source"); t.add_column("mitre"); t.add_column("title")
    for p in proposals:
        t.add_row(p["id"], p.get("source") or "any", p.get("mitre") or "-", p["title"])
    console.print(t)
    if write:
        dest = write_candidates(proposals)
        console.print(f"[green]Wrote candidates -> {dest}[/] (review the diff, then merge into rules/).")
    if settings.github_pat:
        console.print("[dim]GITHUB_PAT set — a real deployment would open a PR against the rules repo.[/]")
    else:
        console.print("[dim]Set GITHUB_PAT to have the tuner open a PR against the rules repo.[/]")


@app.command()
def version() -> None:
    """Print the SentinelLite version."""
    console.print(f"SentinelLite [bold cyan]v{__version__}[/]")


@datasets_app.command("verify")
def datasets_verify() -> None:
    """Verify the bundled curated subset against its pinned sha256."""
    from sentinel.datasets.manifest import verify_curated

    t = Table(title="Curated dataset integrity")
    t.add_column("file"); t.add_column("status"); t.add_column("bytes", justify="right")
    ok_all = True
    for r in verify_curated():
        ok = r["ok"]; ok_all = ok_all and ok
        t.add_row(r["name"], "[green]ok[/]" if ok else f"[red]{r.get('reason')}[/]", str(r.get("bytes", "-")))
    console.print(t)
    raise typer.Exit(code=0 if ok_all else 1)


@datasets_app.command("fetch")
def datasets_fetch(full: bool = typer.Option(False, "--full", help="also download the ~240MB flaws.cloud tar")) -> None:
    """Verify the curated subset and download public source datasets (R12)."""
    from sentinel.datasets.fetch import run_fetch

    if settings.airgap_mode:
        console.print("[yellow]AIRGAP_MODE=true[/] — skipping all network downloads; verifying curated only.")
    res = run_fetch(full=full)

    ct = Table(title="Curated (bundled, offline)")
    ct.add_column("file"); ct.add_column("status")
    for r in res["curated"]:
        ct.add_row(r["name"], "[green]ok[/]" if r["ok"] else f"[red]{r.get('reason')}[/]")
    console.print(ct)

    if res["downloaded"]:
        dt = Table(title="Downloaded sources -> datasets/raw/")
        dt.add_column("source"); dt.add_column("result")
        for d in res["downloaded"]:
            if "error" in d:
                dt.add_row(d["name"], f"[red]{d['error']}[/]")
            elif "skipped" in d:
                dt.add_row(d["name"], f"[dim]skipped: {d['skipped']}[/]")
            else:
                dt.add_row(d["name"], f"[green]{d['bytes']} B[/] sha256={d['sha256'][:12]}")
        console.print(dt)
    console.print("[bold green]datasets ready.[/]")


@attack_app.command("replay")
def attack_replay(
    scenario: str = typer.Argument(..., help="e.g. teampcp"),
    api: str = typer.Option(None, help="control-plane base URL"),
    tenant: str = typer.Option("default", help="tenant id"),
    speed: float = typer.Option(1.0, help="time compression (1.0 = real-time ~3min)"),
    noise: int = typer.Option(42, help="number of benign noise alerts"),
    wait: bool = typer.Option(True, help="wait for and print the resulting investigation"),
) -> None:
    """Emit a public-dataset-backed attack sequence and watch the SOC respond."""
    from sentinel.replay.runner import run_replay, wait_for_investigation

    api_base = api or settings.api_base_url
    console.rule(f"[bold red]SentinelLite — attack replay: {scenario}[/]")

    def on_event(e: dict, code: int) -> None:
        color = "red" if e["verdict"] == "MALICIOUS" else "dim"
        ok = "[green]→[/]" if code == 200 else f"[red]({code})[/]"
        console.print(f"  t+{e['t']:>3}s {ok} [{color}]{e['verdict']:<9}[/] {e['source']:<16} {e['label']}")

    res = run_replay(scenario, api_base=api_base, tenant=tenant, speed=speed, noise=noise, on_event=on_event)
    s = res["stats"]
    console.print(f"\n[bold]Emitted {res['emitted']} alerts[/] — {s['malicious']} malicious / "
                  f"{s['benign']} benign ({s['benign_pct']}% noise).")

    if not wait:
        return
    console.print("\n[dim]Waiting for triage + investigation to settle...[/]")
    inv = wait_for_investigation(api_base, tenant, expected_escalations=s["malicious"])
    if not inv:
        console.print("[yellow]No investigation surfaced yet — check `make logs`.[/]")
        raise typer.Exit(code=0)

    console.rule("[bold]Reconstructed incident[/]")
    console.print(f"[bold]{inv.get('summary', '')}[/]")
    console.print(f"id={inv['id']}  status=[yellow]{inv['status']}[/]  scores={inv.get('scores')}")

    kc = Table(title="Kill chain (MITRE ATT&CK)")
    kc.add_column("t"); kc.add_column("stage"); kc.add_column("technique"); kc.add_column("summary")
    for step in inv.get("kill_chain", []):
        kc.add_row(f"+{step['t_offset_s']}s", step["stage"], step["mitre"], step["summary"][:60])
    console.print(kc)

    acts = inv.get("actions", [])
    if acts:
        at = Table(title="Recommended actions (awaiting approval)")
        at.add_column("type"); at.add_column("params"); at.add_column("confirm?")
        for a in acts:
            at.add_row(a["type"], str(a["params"]), "[red]2-tier[/]" if a["requires_second_confirm"] else "single")
        console.print(at)

    prov = inv.get("data_provenance", {})
    console.print(f"\n[dim]data provenance:[/] sources={prov.get('sources')} datasets={prov.get('datasets')}")
    try:
        v = httpx.get(f"{api_base}/audit/verify", headers={"X-Tenant-Id": tenant}, timeout=10).json()
        badge = "[green]ok[/]" if v.get("ok") else "[red]BROKEN[/]"
        console.print(f"[dim]audit hash-chain:[/] {badge} (length {v.get('length')})")
    except Exception:
        pass


def main() -> None:
    app()


if __name__ == "__main__":
    main()
