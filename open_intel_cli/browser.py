"""
cli/browser.py — Textual TUI for browsing an investigation's entities.

Two-pane layout:
    Left  (30%)  — entity list, type-filter, badges
    Right (70%)  — entity detail + top connections

Keys:
    /  search                f  filter by type
    p  shortest path         c  clusters view
    e  export selected       q  quit
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)


TYPE_SHORT = {
    "ip_address":       ("I", "cyan"),
    "domain":           ("D", "green"),
    "onion_url":        ("O", "magenta"),
    "email":            ("E", "yellow"),
    "file_hash_md5":    ("H", "blue"),
    "file_hash_sha1":   ("H", "blue"),
    "file_hash_sha256": ("H", "blue"),
    "crypto_wallet":    ("W", "yellow"),
    "ransomware_group": ("R", "red"),
    "malware":          ("M", "red"),
    "cve":              ("C", "red"),
    "phone":            ("P", "grey50"),
    "handle":           ("@", "yellow"),
    "pgp_key":          ("K", "grey50"),
}


def _badges_for_entity(entity: dict) -> list[str]:
    tags = (entity.get("corroborating_sources") or "").lower()
    badges: list[str] = []
    if "c2" in tags:
        badges.append("[C2]")
    if "breached" in tags or "hibp" in tags:
        badges.append("[Breached]")
    if "malicious" in tags or "abuseipdb" in tags:
        badges.append("[Malicious]")
    if "fresh" in tags:
        badges.append("[Fresh]")
    return badges


class EntityBrowserApp(App):
    """Textual app over an investigation export dict."""

    CSS = """
    Screen { layout: horizontal; }
    #left  { width: 35%; border-right: solid $accent; }
    #right { width: 65%; padding: 1 2; }
    #detail { height: 100%; }
    DataTable { height: 1fr; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "focus_search", "Search"),
        Binding("f", "cycle_filter", "Filter"),
        Binding("c", "clusters_view", "Clusters"),
        Binding("p", "path_view", "Path"),
        Binding("e", "export_selected", "Export"),
        Binding("r", "refresh_table", "Refresh"),
    ]

    search_query: reactive[str] = reactive("")
    type_filter: reactive[Optional[str]] = reactive(None)

    def __init__(self, data: dict[str, Any]):
        super().__init__()
        self.data = data
        inv = data.get("investigation") or {}
        self._title_text = inv.get("query") or data.get("query") or "investigation"
        self.entities: list[dict] = list(data.get("entities", []))
        self.relationships: list[dict] = list(data.get("relationships", []))
        # Connection counts
        counts: Counter[str] = Counter()
        for r in self.relationships:
            counts[r["entity_a_id"]] += 1
            counts[r["entity_b_id"]] += 1
        self.connection_count = counts
        self.entities.sort(
            key=lambda e: (-counts.get(e["id"], 0), -(e.get("confidence") or 0))
        )

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal():
            with Vertical(id="left"):
                yield Input(placeholder="search… (press / to focus)", id="search")
                yield Label(f"[{self._title_text}]", id="title")
                yield DataTable(id="entity_table", zebra_stripes=True, cursor_type="row")
            with Vertical(id="right"):
                yield Static("Select an entity on the left.", id="detail")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"Open_Intel — {self._title_text}"
        table: DataTable = self.query_one("#entity_table", DataTable)
        table.add_columns("T", "Value", "Conn", "Badges")
        self._populate_table()

    # -- helpers -----------------------------------------------------------

    def _filtered(self) -> list[dict]:
        out = self.entities
        if self.type_filter:
            out = [e for e in out if e["entity_type"] == self.type_filter]
        if self.search_query:
            q = self.search_query.lower()
            out = [
                e for e in out
                if q in (e.get("value") or "").lower()
                or q in (e.get("canonical_value") or "").lower()
                or q in (e.get("corroborating_sources") or "").lower()
            ]
        return out

    def _populate_table(self) -> None:
        table: DataTable = self.query_one("#entity_table", DataTable)
        table.clear()
        for e in self._filtered():
            glyph, _colour = TYPE_SHORT.get(e["entity_type"], ("?", "white"))
            val = (e.get("canonical_value") or e.get("value") or "")[:42]
            conn = self.connection_count.get(e["id"], 0)
            badges = " ".join(_badges_for_entity(e))
            table.add_row(glyph, val, str(conn), badges, key=e["id"])

    # -- input handlers ----------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            self.search_query = event.value
            self._populate_table()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        eid = str(event.row_key.value) if hasattr(event.row_key, "value") else str(event.row_key)
        entity = next((e for e in self.entities if e["id"] == eid), None)
        if entity:
            self._render_detail(entity)

    # -- actions -----------------------------------------------------------

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_cycle_filter(self) -> None:
        types = sorted({e["entity_type"] for e in self.entities})
        if not types:
            return
        if self.type_filter is None:
            self.type_filter = types[0]
        else:
            try:
                idx = types.index(self.type_filter)
                self.type_filter = types[idx + 1] if idx + 1 < len(types) else None
            except ValueError:
                self.type_filter = None
        self._populate_table()

    def action_refresh_table(self) -> None:
        self._populate_table()

    def action_clusters_view(self) -> None:
        self.push_screen(ClustersScreen(self))

    def action_path_view(self) -> None:
        self.push_screen(PathScreen(self))

    def action_export_selected(self) -> None:
        table: DataTable = self.query_one("#entity_table", DataTable)
        row = table.cursor_row
        rows = list(self._filtered())
        if row < 0 or row >= len(rows):
            return
        entity = rows[row]
        from pathlib import Path
        out = Path.home() / ".open_intel" / "results" / f"entity-{entity['id']}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        import json
        out.write_text(json.dumps(entity, indent=2, default=str), encoding="utf-8")
        self.notify(f"Exported to {out}")

    # -- detail pane -------------------------------------------------------

    def _render_detail(self, entity: dict) -> None:
        lines: list[str] = []
        val = entity.get("canonical_value") or entity.get("value") or ""
        lines.append(f"[b]Entity:[/b] {val}")
        lines.append(
            f"Type: {entity['entity_type']}  |  Confidence: "
            f"{(entity.get('confidence') or 0):.2f}"
        )
        tags = entity.get("corroborating_sources") or ""
        if tags:
            lines.append(f"Tags: {tags}")
        lines.append("")
        if entity.get("first_seen") or entity.get("last_seen"):
            lines.append(
                f"First seen: {entity.get('first_seen') or '—'}   "
                f"Last seen: {entity.get('last_seen') or '—'}"
            )
        if entity.get("extraction_method"):
            lines.append(f"Extraction: {entity['extraction_method']}")
        lines.append("")
        ctx = (entity.get("context_snippet") or "").strip()
        if ctx:
            lines.append("[b]Context:[/b]")
            lines.append(ctx[:1500])
            lines.append("")

        neighbours = self._neighbours_of(entity["id"])
        if neighbours:
            lines.append("[b]Connected to (top 10):[/b]")
            for other_id, edge_type, conf in neighbours[:10]:
                other = next((e for e in self.entities if e["id"] == other_id), None)
                if other:
                    other_val = (other.get("canonical_value") or other.get("value") or "")[:48]
                    lines.append(f"  → {other_val:50} {edge_type:18} {conf:.2f}")
        detail: Static = self.query_one("#detail", Static)
        detail.update("\n".join(lines))

    def _neighbours_of(self, entity_id: str) -> list[tuple[str, str, float]]:
        out: list[tuple[str, str, float]] = []
        for r in self.relationships:
            if r["entity_a_id"] == entity_id:
                out.append((r["entity_b_id"], r["relationship_type"], r.get("confidence") or 0.0))
            elif r["entity_b_id"] == entity_id:
                out.append((r["entity_a_id"], r["relationship_type"], r.get("confidence") or 0.0))
        out.sort(key=lambda t: -t[2])
        return out


# ---------------------------------------------------------------------------
# Cluster overlay
# ---------------------------------------------------------------------------


class ClustersScreen(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close"), Binding("q", "dismiss", "Close")]

    def __init__(self, parent_app: EntityBrowserApp):
        super().__init__()
        self._parent_app = parent_app

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("[b]Infrastructure clusters[/b]   (esc to close)"),
            Static(self._render_clusters(), id="clusters_body"),
        )

    def _render_clusters(self) -> str:
        # Greedy connected-component clustering via the parent's edges
        adj: dict[str, set[str]] = defaultdict(set)
        for r in self._parent_app.relationships:
            adj[r["entity_a_id"]].add(r["entity_b_id"])
            adj[r["entity_b_id"]].add(r["entity_a_id"])

        seen: set[str] = set()
        clusters: list[list[str]] = []
        for eid in adj:
            if eid in seen:
                continue
            stack = [eid]
            comp: list[str] = []
            while stack:
                node = stack.pop()
                if node in seen:
                    continue
                seen.add(node)
                comp.append(node)
                stack.extend(adj.get(node, ()))
            clusters.append(comp)

        clusters.sort(key=len, reverse=True)
        entity_by_id = {e["id"]: e for e in self._parent_app.entities}

        lines = []
        for idx, comp in enumerate(clusters[:10], start=1):
            hub_id = max(comp, key=lambda x: len(adj.get(x, ())))
            hub = entity_by_id.get(hub_id, {})
            hub_val = hub.get("canonical_value") or hub.get("value") or hub_id[:8]
            type_counts: Counter[str] = Counter()
            for nid in comp:
                ent = entity_by_id.get(nid)
                if ent:
                    type_counts[ent["entity_type"]] += 1
            lines.append(
                f"Cluster {chr(64 + idx)}: {hub_val}  (hub, {len(adj.get(hub_id, ()))} conn)"
            )
            for etype, count in type_counts.most_common():
                lines.append(f"  └── {count} {etype}")
            lines.append("")
        return "\n".join(lines) or "No clusters detected."


# ---------------------------------------------------------------------------
# Path finder overlay
# ---------------------------------------------------------------------------


class PathScreen(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, parent_app: EntityBrowserApp):
        super().__init__()
        self._parent_app = parent_app

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("[b]Shortest path between two entities[/b]"),
            Input(placeholder="first entity value", id="path_a"),
            Input(placeholder="second entity value", id="path_b"),
            Static("", id="path_result"),
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        a = self.query_one("#path_a", Input).value.strip().lower()
        b = self.query_one("#path_b", Input).value.strip().lower()
        if not a or not b:
            return
        result = self._find_path(a, b)
        self.query_one("#path_result", Static).update(result)

    def _find_path(self, a_val: str, b_val: str) -> str:
        ents = self._parent_app.entities
        a_ent = next((e for e in ents if (e.get("canonical_value") or e.get("value") or "").lower() == a_val), None)
        b_ent = next((e for e in ents if (e.get("canonical_value") or e.get("value") or "").lower() == b_val), None)
        if a_ent is None or b_ent is None:
            return "One or both entities not found in this investigation."

        adj: dict[str, set[str]] = defaultdict(set)
        for r in self._parent_app.relationships:
            adj[r["entity_a_id"]].add(r["entity_b_id"])
            adj[r["entity_b_id"]].add(r["entity_a_id"])

        # BFS
        queue = [(a_ent["id"], [a_ent["id"]])]
        visited = {a_ent["id"]}
        while queue:
            node, path = queue.pop(0)
            if node == b_ent["id"]:
                ents_by_id = {e["id"]: e for e in ents}
                arrow = " → ".join(
                    (ents_by_id[n].get("canonical_value") or ents_by_id[n].get("value") or n)
                    for n in path
                )
                return f"{arrow}\n({len(path) - 1} hops)"
            for nxt in adj.get(node, ()):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt]))
        return "No path between these entities."
