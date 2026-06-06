"""
cli/display.py — Rich live display for investigations.

Three-zone layout:
    title bar     — query + elapsed timer
    step table    — pipeline stages with status icons
    activity line — current URL / sub-task detail

Status icons:
    pending  · gray dot
    active   ⠹ spinner (cycles in tick())
    ok       ✓ green
    fail     ✗ red
    skip     ↷ yellow
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

STATUS_GLYPH = {
    "pending": ("·", "grey50"),
    "active":  ("⠹", "cyan"),
    "ok":      ("✓", "green"),
    "fail":    ("✗", "red"),
    "skip":    ("↷", "yellow"),
}


@dataclass
class StepRow:
    name: str
    status: str = "pending"
    detail: str = ""
    substeps: list[tuple[str, str]] = field(default_factory=list)  # (label, status)


class InvestigationDisplay:
    """Live terminal display driven by .update_step() and .update_current_url()."""

    def __init__(self, console: Optional[Console] = None, quiet: bool = False):
        self.console = console or Console()
        self.quiet = quiet
        self._live: Optional[Live] = None
        self._query: str = ""
        self._start_ts: float = time.monotonic()
        self._steps: list[StepRow] = []
        self._current_url: str = ""
        self._spinner_index = 0
        self._final_summary: Optional[dict] = None
        self._error: Optional[str] = None

    # -- lifecycle ----------------------------------------------------------

    def start(self, query: str, steps: Optional[list[str]] = None) -> None:
        self._query = query
        self._start_ts = time.monotonic()
        names = steps or [
            "Refining query",
            "Searching dark web",
            "Filtering results",
            "Scraping pages",
            "Extracting entities",
            "Enriching intelligence",
            "Building graph",
            "Generating summary",
            "Finalizing results",
        ]
        self._steps = [StepRow(name=n) for n in names]
        if self.quiet:
            self.console.print(f"[bold]Open_Intel[/bold] — {query}")
            return
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=8,
            transient=False,
        )
        self._live.start()

    def stop(self) -> None:
        if self._live is not None:
            self._live.update(self._render(), refresh=True)
            self._live.stop()
            self._live = None

    # -- updates ------------------------------------------------------------

    def update_step(self, step_name: str, status: str, detail: str = "") -> None:
        row = self._find_step(step_name)
        if row is None:
            row = StepRow(name=step_name)
            self._steps.append(row)
        row.status = status
        if detail:
            row.detail = detail
        self._refresh()
        if self.quiet:
            icon = STATUS_GLYPH.get(status, ("·", "grey50"))[0]
            d = f" — {detail}" if detail else ""
            self.console.print(f"  {icon} {step_name}{d}")

    def update_substep(self, step_name: str, label: str, status: str) -> None:
        row = self._find_step(step_name)
        if row is None:
            return
        for idx, (existing, _) in enumerate(row.substeps):
            if existing == label:
                row.substeps[idx] = (label, status)
                self._refresh()
                return
        row.substeps.append((label, status))
        self._refresh()

    def update_current_url(self, url: str) -> None:
        self._current_url = url
        self._refresh()

    def complete(self, summary: dict) -> None:
        self._final_summary = summary
        self.stop()
        self._print_completion(summary)

    def error(self, msg: str) -> None:
        self._error = msg
        self.stop()
        self.console.print(f"[bold red]Investigation failed:[/bold red] {msg}")

    # -- render -------------------------------------------------------------

    def _refresh(self) -> None:
        self._spinner_index = (self._spinner_index + 1) % len(SPINNER_FRAMES)
        if self._live is not None:
            self._live.update(self._render(), refresh=True)

    def _find_step(self, name: str) -> Optional[StepRow]:
        for row in self._steps:
            if row.name == name:
                return row
        return None

    def _render(self) -> Panel:
        elapsed = time.monotonic() - self._start_ts
        title = Text()
        title.append("Open_Intel", style="bold magenta")
        title.append(f" — \"{self._query}\"", style="bold white")
        title.append(f"   Elapsed: {self._fmt_elapsed(elapsed)}", style="grey50")

        table = Table.grid(padding=(0, 1))
        table.add_column(width=2)
        table.add_column(no_wrap=False)
        for row in self._steps:
            glyph, colour = STATUS_GLYPH.get(row.status, ("·", "grey50"))
            if row.status == "active":
                glyph = SPINNER_FRAMES[self._spinner_index]
            line = Text()
            line.append(f"{glyph} ", style=colour)
            line.append(row.name, style="white" if row.status != "pending" else "grey50")
            if row.detail:
                line.append(f"  ({row.detail})", style="grey62")
            table.add_row("", line)
            for sub_label, sub_status in row.substeps:
                sg, sc = STATUS_GLYPH.get(sub_status, ("·", "grey50"))
                sub = Text(f"   {sg} {sub_label}", style=sc)
                table.add_row("", sub)

        activity = Text()
        if self._current_url:
            activity.append("Fetching: ", style="bold")
            activity.append(self._current_url, style="cyan")
        else:
            activity.append("", style="grey50")

        body = Group(title, Text(""), table, Text(""), activity)
        return Panel(body, border_style="magenta", padding=(1, 2))

    @staticmethod
    def _fmt_elapsed(secs: float) -> str:
        m, s = divmod(int(secs), 60)
        return f"{m}m {s:02d}s"

    def _print_completion(self, summary: dict) -> None:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="bold")
        table.add_column()
        table.add_row("Entities", str(summary.get("entity_count", "—")))
        table.add_row("Pages", str(summary.get("page_count", "—")))
        if "c2_ips" in summary:
            table.add_row("C2 IPs", f"{summary['c2_ips']} confirmed")
        table.add_row("Sources", str(summary.get("sources_used", "—")))
        if summary.get("report_path"):
            table.add_row("Report", str(summary["report_path"]))
        if summary.get("data_path"):
            table.add_row("Data", str(summary["data_path"]))

        panel = Panel(
            Group(Text("✓ Investigation complete", style="bold green"), Text(""), table),
            border_style="green",
            padding=(1, 2),
        )
        self.console.print(panel)
