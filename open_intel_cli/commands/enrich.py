"""
cli/commands/enrich.py — re-run enrichment over a stored investigation.

Useful after weeks/months: IP feeds shift, emails appear in new breaches,
domains move. This refreshes:
    - IP reputation (Feodo, AbuseIPDB, GreyNoise)
    - Domain reputation (URLScan, SecurityTrails — when keys present)
    - Hash reputation (VirusTotal, Hybrid Analysis)
    - Email reputation (HIBP, EmailRep)
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

console = Console()


def run(
    target: str = typer.Argument(..., help="Investigation id or .json file"),
    skip_ips: bool = typer.Option(False, "--skip-ips"),
    skip_domains: bool = typer.Option(False, "--skip-domains"),
    skip_hashes: bool = typer.Option(False, "--skip-hashes"),
    skip_emails: bool = typer.Option(False, "--skip-emails"),
) -> None:
    """Re-enrich entities for an existing investigation."""
    from open_intel_cli import config as cli_config
    cli_config.apply_env()

    inv_id = _resolve_investigation_id(target)
    if inv_id is None:
        console.print(f"[red]Cannot resolve investigation:[/red] {target}")
        raise typer.Exit(code=1)

    asyncio.run(_run(inv_id, skip_ips, skip_domains, skip_hashes, skip_emails))


def _resolve_investigation_id(target: str) -> Optional[str]:
    import json as _json
    p = Path(target).expanduser()
    if p.exists() and p.suffix == ".json":
        try:
            data = _json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        return data.get("investigation", {}).get("id") or data.get("id")
    from open_intel_cli.adapters import sqlite as sqlite_adapter
    sqlite_adapter.init_db()
    resolved = sqlite_adapter.resolve_investigation_id(target) or target
    row = sqlite_adapter.get_investigation(resolved)
    return row["id"] if row else None


class _FakeEntity:
    """Minimal stand-in shaped like extractor.normalizer.NormalizedEntity."""
    __slots__ = ("entity_type", "value", "confidence", "canonical_value")

    def __init__(self, entity_type: str, value: str, confidence: float,
                 canonical_value: str | None = None):
        self.entity_type = entity_type
        self.value = value
        self.confidence = confidence
        self.canonical_value = canonical_value or value


class _FakeResult:
    """Shape: ExtractionResult — only .entities is used by reputation enrichers."""
    __slots__ = ("entities",)

    def __init__(self, entities: list):
        self.entities = entities


_TYPE_MAP = {
    "ip_address":       "IP_ADDRESS",
    "domain":           "DOMAIN",
    "email":            "EMAIL_ADDRESS",
    "file_hash_md5":    "FILE_HASH_MD5",
    "file_hash_sha1":   "FILE_HASH_SHA1",
    "file_hash_sha256": "FILE_HASH_SHA256",
}


def _load_extraction_results(investigation_id: str) -> list:
    """Reconstruct ExtractionResult-shaped objects from the DB."""
    from open_intel_cli.adapters import sqlite as sqlite_adapter
    rows = sqlite_adapter.get_entities(investigation_id)
    fakes = []
    for r in rows:
        canonical = _TYPE_MAP.get(r["entity_type"], r["entity_type"].upper())
        fakes.append(
            _FakeEntity(
                entity_type=canonical,
                value=r["value"],
                confidence=r.get("confidence") or 1.0,
                canonical_value=r.get("canonical_value"),
            )
        )
    return [_FakeResult(fakes)]


async def _run(
    investigation_id: str,
    skip_ips: bool,
    skip_domains: bool,
    skip_hashes: bool,
    skip_emails: bool,
) -> None:
    inv_uuid = uuid.UUID(investigation_id)
    extraction_results = _load_extraction_results(investigation_id)

    if not skip_ips:
        try:
            from sources.ip_reputation import enrich_ip_entities
            console.print("• IP reputation…")
            await enrich_ip_entities(extraction_results, inv_uuid)
            console.print("  [green]done[/green]")
        except Exception as exc:
            console.print(f"  [red]failed:[/red] {exc}")

    if not skip_domains:
        try:
            from sources.domain_reputation import enrich_domain_entities
            console.print("• Domain reputation…")
            await enrich_domain_entities(extraction_results, inv_uuid)
            console.print("  [green]done[/green]")
        except Exception as exc:
            console.print(f"  [red]failed:[/red] {exc}")

    if not skip_hashes:
        try:
            from sources.hash_reputation import enrich_hash_entities
            console.print("• Hash reputation…")
            await enrich_hash_entities(extraction_results, inv_uuid)
            console.print("  [green]done[/green]")
        except Exception as exc:
            console.print(f"  [red]failed:[/red] {exc}")

    if not skip_emails:
        try:
            from sources.email_reputation import enrich_email_entities
            console.print("• Email reputation…")
            await enrich_email_entities(extraction_results, inv_uuid)
            console.print("  [green]done[/green]")
        except Exception as exc:
            console.print(f"  [red]failed:[/red] {exc}")

    console.print("\n[green]Re-enrichment complete.[/green]")
