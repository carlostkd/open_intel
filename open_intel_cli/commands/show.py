"""
cli/commands/show.py — Launch the Textual entity browser.

Argument can be:
    a path to a saved .json investigation file
    an investigation id (UUID stored in SQLite)
    omitted → interactive picker over recent runs
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

console = Console()


def run(
    target: Optional[str] = typer.Argument(
        None, help="Investigation id or path to a .json export"
    ),
    no_tui: bool = typer.Option(False, "--no-tui", help="Print summary table without launching TUI (for scripted use)."),
) -> None:
    """Open the entity browser TUI."""
    from open_intel_cli import config as cli_config
    cli_config.apply_env()

    data: Optional[dict] = None

    if target is None:
        if no_tui:
            console.print("[yellow]No target specified.[/yellow]")
            raise typer.Exit(code=1)
        target = _pick_recent()
        if target is None:
            console.print("[yellow]No investigations found. Run `open_intel investigate` first.[/yellow]")
            raise typer.Exit(code=1)

    candidate_path = Path(target).expanduser()
    if candidate_path.exists() and candidate_path.suffix == ".json":
        data = json.loads(candidate_path.read_text(encoding="utf-8"))
    else:
        from open_intel_cli.adapters import sqlite as sqlite_adapter
        sqlite_adapter.init_db()
        resolved = sqlite_adapter.resolve_investigation_id(target) or target
        data = sqlite_adapter.investigation_to_export_dict(resolved)
        if not data or not data.get("investigation"):
            console.print(f"[red]Unknown investigation:[/red] {target}")
            raise typer.Exit(code=1)

    if no_tui:
        _print_summary(data)
        return

    from open_intel_cli.browser import EntityBrowserApp
    app = EntityBrowserApp(data=data)
    app.run()


def _print_summary(data: dict) -> None:
    inv = data.get("investigation") or data
    entities = data.get("entities", [])
    table = Table(title="Investigation summary")
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Query", str(inv.get("query") or ""))
    table.add_row("Status", str(inv.get("status") or ""))
    table.add_row("Entities", str(len(entities)))
    table.add_row("Created", str(inv.get("created_at") or "")[:19])
    table.add_row("Summary", (str(inv.get("summary") or "—"))[:120])
    console.print(table)


def _pick_recent() -> Optional[str]:
    from open_intel_cli.adapters import sqlite as sqlite_adapter
    sqlite_adapter.init_db()
    rows = sqlite_adapter.list_investigations(limit=20)
    if not rows:
        return None

    table = Table(title="Recent investigations")
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Query")
    table.add_column("Status")
    table.add_column("Entities", justify="right")
    table.add_column("Date")
    for idx, r in enumerate(rows, 1):
        table.add_row(
            str(idx),
            (r["query"] or "")[:50],
            r["status"] or "",
            str(r["entity_count"]),
            (r["created_at"] or "")[:19],
        )
    console.print(table)
    from rich.prompt import Prompt
    choice = Prompt.ask("Pick #", default="1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(rows):
            return rows[idx]["id"]
    except ValueError:
        pass
    return None
