"""
graph/export.py — Export the relationship graph to external formats.

All functions accept an nx.MultiDiGraph as their first argument.
to_graphml and to_gephi_csv write files; to_json and summary_stats return data.

Public interface
----------------
to_graphml(graph, filepath)                          → None
to_json(graph)                                       → dict
to_gephi_csv(graph, nodes_path, edges_path)          → None
summary_stats(graph)                                 → dict
"""

from __future__ import annotations

import csv
import json
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

import networkx as nx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _serialize_value(v: Any) -> Any:
    """Convert a value to a JSON-serializable form."""
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, (list, dict)):
        return v  # already JSON-native (contents may recurse in to_json)
    return v


def _node_to_dict(node_id: str, data: dict) -> dict:
    raw_label = data.get("label") or node_id.split("@")[0]
    label = raw_label[:50] if len(raw_label) > 50 else raw_label
    return {
        "id": node_id,
        "label": label,
        "type": data.get("node_type", ""),
        "confidence": data.get("confidence", 0.0),
        "first_seen": _serialize_value(data.get("first_seen")),
        "last_seen": _serialize_value(data.get("last_seen")),
        "source_urls": data.get("source_urls", []),
        "metadata": data.get("metadata", {}),
    }


def _edge_to_dict(source: str, target: str, data: dict) -> dict:
    return {
        "source": source,
        "target": target,
        "type": data.get("edge_type", ""),
        "confidence": data.get("confidence", 0.0),
        "source_url": data.get("source_url", ""),
        "timestamp": _serialize_value(data.get("timestamp")),
        "metadata": data.get("metadata", {}),
    }


# ---------------------------------------------------------------------------
# Helpers for GraphML (NetworkX only supports basic scalar types)
# ---------------------------------------------------------------------------


def _flatten_for_graphml(data: dict) -> dict:
    """
    Convert node/edge attributes to GraphML-compatible scalars.

    NetworkX's GraphML writer supports str, int, float, bool — not datetime,
    list, or dict.  This function converts everything else to its JSON or
    ISO-8601 string representation.
    """
    flat: dict = {}
    for key, value in data.items():
        if isinstance(value, datetime):
            flat[key] = value.isoformat()
        elif isinstance(value, (list, dict)):
            flat[key] = json.dumps(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            flat[key] = value if value is not None else ""
        else:
            flat[key] = str(value)
    return flat


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def to_graphml(graph: nx.MultiDiGraph, filepath: str) -> None:
    """
    Export *graph* to GraphML format (opens in Gephi, yEd, Cytoscape).

    All node/edge attributes are serialised to GraphML-compatible scalar types
    before writing.
    """
    serialised = nx.MultiDiGraph()

    for node_id, data in graph.nodes(data=True):
        serialised.add_node(node_id, **_flatten_for_graphml(data))

    for src, tgt, key, data in graph.edges(data=True, keys=True):
        serialised.add_edge(src, tgt, key=key, **_flatten_for_graphml(data))

    nx.write_graphml(serialised, filepath)


def to_json(graph: nx.MultiDiGraph) -> dict:
    """
    Return a JSON-serialisable dict representing the graph.

    Schema:
        {
            "nodes": [{"id": ..., "type": ..., "first_seen": <ISO-8601>, ...}],
            "edges": [{"source": ..., "target": ..., "type": ..., ...}],
        }

    All datetime values are serialised as ISO 8601 strings.
    """
    nodes = [
        _node_to_dict(nid, data)
        for nid, data in graph.nodes(data=True)
    ]
    edges = [
        _edge_to_dict(src, tgt, data)
        for src, tgt, data in graph.edges(data=True)
    ]
    return {"nodes": nodes, "edges": edges}


def to_gephi_csv(
    graph: nx.MultiDiGraph,
    nodes_path: str,
    edges_path: str,
) -> None:
    """
    Export the graph to two CSV files in Gephi node/edge table format.

    nodes.csv columns: Id, Label, Type, FirstSeen, LastSeen
    edges.csv columns: Source, Target, Type, Confidence, SourceUrl
    """
    with open(nodes_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Id", "Label", "Type", "FirstSeen", "LastSeen"]
        )
        writer.writeheader()
        for node_id, data in graph.nodes(data=True):
            first_seen = data.get("first_seen")
            last_seen = data.get("last_seen")
            writer.writerow({
                "Id": node_id,
                "Label": node_id,
                "Type": data.get("node_type", ""),
                "FirstSeen": first_seen.isoformat() if isinstance(first_seen, datetime) else str(first_seen or ""),
                "LastSeen": last_seen.isoformat() if isinstance(last_seen, datetime) else str(last_seen or ""),
            })

    with open(edges_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Source", "Target", "Type", "Confidence", "SourceUrl"]
        )
        writer.writeheader()
        for src, tgt, data in graph.edges(data=True):
            writer.writerow({
                "Source": src,
                "Target": tgt,
                "Type": data.get("edge_type", ""),
                "Confidence": data.get("confidence", ""),
                "SourceUrl": data.get("source_url", ""),
            })


def summary_stats(graph: nx.MultiDiGraph) -> dict:
    """
    Return aggregate statistics about the graph.

    Schema:
        {
            "total_nodes": int,
            "total_edges": int,
            "nodes_by_type": {"ThreatActor": N, ...},
            "edges_by_type": {"CO_APPEARED_ON": N, ...},
            "most_connected": [{"node_id": ..., "degree": N}],  # top 5
        }
    """
    nodes_by_type: dict[str, int] = defaultdict(int)
    for _, data in graph.nodes(data=True):
        ntype = data.get("node_type", "")
        if ntype:
            nodes_by_type[ntype] += 1

    edges_by_type: dict[str, int] = defaultdict(int)
    for _, _, data in graph.edges(data=True):
        etype = data.get("edge_type", "")
        if etype:
            edges_by_type[etype] += 1

    degree_list = sorted(
        ((nid, graph.degree(nid)) for nid in graph.nodes()),
        key=lambda t: t[1],
        reverse=True,
    )
    most_connected = [
        {"node_id": nid, "degree": deg}
        for nid, deg in degree_list[:5]
    ]

    return {
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "nodes_by_type": dict(nodes_by_type),
        "edges_by_type": dict(edges_by_type),
        "most_connected": most_connected,
    }
