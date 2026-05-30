"""The `sentinel` CLI: attack replay + dataset fetching.

Milestone 0 wires the command tree; `datasets fetch` and `attack replay` get
their real implementations in Milestone 4."""

from __future__ import annotations

import typer
from rich.console import Console

from sentinel import __version__

app = typer.Typer(
    name="sentinel",
    help="SentinelLite CLI — attack replay & dataset fetching.",
    no_args_is_help=True,
    add_completion=False,
)
datasets_app = typer.Typer(help="Manage public attack datasets.", no_args_is_help=True)
attack_app = typer.Typer(help="Replay scripted attack scenarios.", no_args_is_help=True)
app.add_typer(datasets_app, name="datasets")
app.add_typer(attack_app, name="attack")

console = Console()


@app.command()
def version() -> None:
    """Print the SentinelLite version."""
    console.print(f"SentinelLite [bold cyan]v{__version__}[/]")


@datasets_app.command("fetch")
def datasets_fetch() -> None:
    """Download all public attack datasets (checksum-verified)."""
    console.print("[yellow]datasets fetch[/] — implemented in Milestone 4.")
    raise typer.Exit(code=0)


@attack_app.command("replay")
def attack_replay(scenario: str = typer.Argument(..., help="e.g. teampcp")) -> None:
    """Emit a scripted attack alert sequence drawn from public datasets."""
    console.print(f"[yellow]attack replay {scenario}[/] — implemented in Milestone 4.")
    raise typer.Exit(code=0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
