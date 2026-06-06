"""
cli/commands/export.py — convert a saved investigation to a sharable format.

    open_intel export <id_or_json_file> --format stix|misp|sigma|csv|md|json
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

console = Console()


def run(
    target: str = typer.Argument(..., help="Investigation id or .json file"),
    fmt: str = typer.Option("json", "--format", help="stix|misp|sigma|csv|md|json"),
    output: Optional[Path] = typer.Option(None, "--output", help="Output file"),
) -> None:
    """Export an investigation."""
    from open_intel_cli import config as cli_config
    cli_config.apply_env()

    fmt = fmt.lower()
    if fmt not in ("stix", "misp", "sigma", "csv", "md", "json"):
        console.print(f"[red]Unsupported format:[/red] {fmt}")
        raise typer.Exit(code=2)

    inv_id, data = _load_target(target)
    if not data:
        console.print(f"[red]Could not load investigation:[/red] {target}")
        raise typer.Exit(code=1)

    payload, suffix = _render(fmt, inv_id, data)
    out_path = output or _default_out_path(target, suffix, fmt=fmt)
    out_path = Path(out_path).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, bytes):
        out_path.write_bytes(payload)
    else:
        out_path.write_text(payload, encoding="utf-8")
    console.print(f"[green]Wrote[/green] {out_path}")


def _load_target(target: str) -> tuple[Optional[str], Optional[dict]]:
    p = Path(target).expanduser()
    if p.exists() and p.suffix == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None, None
        inv_id = data.get("investigation", {}).get("id") or data.get("id")
        return inv_id, data
    from open_intel_cli.adapters import sqlite as sqlite_adapter
    sqlite_adapter.init_db()
    resolved = sqlite_adapter.resolve_investigation_id(target) or target
    data = sqlite_adapter.investigation_to_export_dict(resolved)
    if not data or not data.get("investigation"):
        return None, None
    return resolved, data


def _render(fmt: str, inv_id: Optional[str], data: dict) -> tuple[str | bytes, str]:
    if fmt == "json":
        return json.dumps(data, indent=2, default=str), ".json"

    if fmt == "csv":
        return _csv_from_data(data), ".csv"

    if fmt == "md":
        from open_intel_cli.commands.investigate import _render_markdown  # reuse renderer
        # Adapt shape: _render_markdown expects flat payload
        flat = _flatten_for_md(data)
        return _render_markdown(flat), ".md"

    # STIX/MISP/Sigma need investigation_id (UUID) and load from DB
    if inv_id is None:
        raise typer.BadParameter(
            "STIX, MISP, and Sigma export require an investigation id in the database "
            "(not a bare JSON file)."
        )
    try:
        inv_uuid = uuid.UUID(inv_id)
    except (ValueError, TypeError) as exc:
        raise typer.BadParameter(f"Invalid investigation id: {inv_id} ({exc})") from exc

    if fmt == "stix":
        from export import investigation_to_stix_bundle, bundle_to_json
        bundle = investigation_to_stix_bundle(inv_uuid)
        return bundle_to_json(bundle), ".json"

    if fmt == "misp":
        from export import investigation_to_misp_event, misp_event_to_json
        event = investigation_to_misp_event(inv_uuid)
        return misp_event_to_json(event), ".json"

    if fmt == "sigma":
        from export import export_sigma_rules
        rules_yaml = export_sigma_rules(inv_uuid)
        return rules_yaml if isinstance(rules_yaml, str) else "\n---\n".join(rules_yaml), ".yml"

    raise typer.BadParameter(f"Unknown format: {fmt}")


def _csv_from_data(data: dict) -> str:
    entities = data.get("entities", [])
    if not entities and isinstance(data.get("investigation"), dict):
        entities = data.get("entities", [])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["entity_type", "value", "canonical_value", "confidence",
         "extraction_method", "corroborating_sources", "context_snippet"]
    )
    for e in entities:
        writer.writerow(
            [
                e.get("entity_type", ""),
                e.get("value", ""),
                e.get("canonical_value", ""),
                e.get("confidence", ""),
                e.get("extraction_method", ""),
                e.get("corroborating_sources", ""),
                (e.get("context_snippet") or "").replace("\n", " ")[:500],
            ]
        )
    return buf.getvalue()


def _flatten_for_md(data: dict) -> dict:
    if "investigation" in data:
        inv = data["investigation"]
        return {
            "query": inv.get("query", ""),
            "refined_query": inv.get("refined_query"),
            "model_used": inv.get("model_used"),
            "created_at": inv.get("created_at", ""),
            "summary": inv.get("summary"),
            "entities": data.get("entities", []),
            "relationships": data.get("relationships", []),
            "sources_used": data.get("sources_used", {}),
        }
    return data


def _default_out_path(target: str, suffix: str, fmt: str = "") -> Path:
    p = Path(target).expanduser()
    if p.exists():
        candidate = p.with_suffix(suffix)
        # Avoid overwriting input when suffix is the same (e.g. stix/misp .json)
        if candidate == p and fmt and fmt not in ("json",):
            return p.parent / f"{p.stem}-{fmt}{suffix}"
        return candidate
    from open_intel_cli import config as cli_config
    return cli_config.get_output_dir() / f"{target}{suffix}"
