"""
graph/queries.py — Named query functions that operate on a NetworkX graph.

All functions are pure (no side effects, no DB calls).
All accept a graph as their first argument and return data.
None of these functions modify the graph.

Public interface
----------------
get_neighbors(graph, node_id, hops, edge_types)  → dict[str, list[GraphNode]]
find_nodes_by_type(graph, node_type)             → list[GraphNode]
find_co_occurring_entities(graph, node_id)       → list[tuple[GraphNode, int]]
get_new_nodes_since(graph, since)                → list[GraphNode]
find_high_degree_nodes(graph, top_n, node_type)  → list[tuple[GraphNode, int]]
get_shortest_path(graph, source_id, target_id)   → list[GraphNode] | None
get_actor_profile(graph, actor_node_id)          → dict
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

import networkx as nx

from graph.model import EDGE_TYPES, NODE_TYPES, GraphNode


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_graphnode(node_id: str, data: dict) -> GraphNode:
    """Reconstruct a GraphNode from raw NetworkX node attribute dict."""
    return GraphNode(
        node_id=node_id,
        node_type=data.get("node_type", ""),
        first_seen=data.get("first_seen", datetime.utcnow()),
        last_seen=data.get("last_seen", datetime.utcnow()),
        source_urls=list(data.get("source_urls", [])),
        metadata=dict(data.get("metadata", {})),
    )


def _has_node(graph: nx.MultiDiGraph, node_id: str) -> bool:
    return graph.has_node(node_id)


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def get_neighbors(
    graph: nx.MultiDiGraph,
    node_id: str,
    hops: int = 2,
    edge_types: Optional[list[str]] = None,
) -> dict[str, list[GraphNode]]:
    """
    Return all nodes reachable within *hops* steps from *node_id*.

    Traversal is bidirectional (follows both outgoing and incoming edges) so
    that CO_APPEARED_ON and similar undirected-semantics edges are fully
    explored regardless of which direction they were stored.

    If *edge_types* is provided, only edges whose ``edge_type`` attribute
    matches one of the listed types are traversed.

    Returns a dict keyed by hop distance (as a string):
        {"1": [GraphNode, ...], "2": [GraphNode, ...], ...}
    """
    if not _has_node(graph, node_id):
        return {}

    visited: dict[str, int] = {node_id: 0}  # node_id → hop at which it was reached
    queue: deque[tuple[str, int]] = deque([(node_id, 0)])
    result: dict[str, list[GraphNode]] = {}

    while queue:
        current, depth = queue.popleft()
        if depth >= hops:
            continue

        # Collect adjacent nodes (both directions)
        neighbors: set[str] = set()

        for _, nbr, edge_data in graph.out_edges(current, data=True):
            if edge_types is None or edge_data.get("edge_type") in edge_types:
                neighbors.add(nbr)

        for pred, _, edge_data in graph.in_edges(current, data=True):
            if edge_types is None or edge_data.get("edge_type") in edge_types:
                neighbors.add(pred)

        for nbr in neighbors:
            if nbr == node_id:
                continue
            if nbr not in visited:
                hop = depth + 1
                visited[nbr] = hop
                key = str(hop)
                result.setdefault(key, [])
                result[key].append(_make_graphnode(nbr, graph.nodes[nbr]))
                queue.append((nbr, hop))

    return result


def find_nodes_by_type(
    graph: nx.MultiDiGraph,
    node_type: str,
) -> list[GraphNode]:
    """Return all nodes in *graph* whose node_type equals *node_type*."""
    return [
        _make_graphnode(nid, data)
        for nid, data in graph.nodes(data=True)
        if data.get("node_type") == node_type
    ]


def find_co_occurring_entities(
    graph: nx.MultiDiGraph,
    node_id: str,
) -> list[tuple[GraphNode, int]]:
    """
    Return a list of (GraphNode, co_occurrence_count) for every node that
    co-occurs with *node_id* via CO_APPEARED_ON edges.

    Co-occurrence count = number of CO_APPEARED_ON edges connecting the pair
    (in either direction).  Results are sorted by count descending.
    """
    if not _has_node(graph, node_id):
        return []

    counts: dict[str, int] = defaultdict(int)

    for _, nbr, data in graph.out_edges(node_id, data=True):
        if data.get("edge_type") == EDGE_TYPES.CO_APPEARED_ON:
            counts[nbr] += 1

    for pred, _, data in graph.in_edges(node_id, data=True):
        if data.get("edge_type") == EDGE_TYPES.CO_APPEARED_ON:
            counts[pred] += 1

    result = [
        (_make_graphnode(nid, graph.nodes[nid]), count)
        for nid, count in counts.items()
    ]
    result.sort(key=lambda t: t[1], reverse=True)
    return result


def get_new_nodes_since(
    graph: nx.MultiDiGraph,
    since: datetime,
) -> list[GraphNode]:
    """Return all nodes where first_seen >= *since*."""
    nodes = []
    for nid, data in graph.nodes(data=True):
        first_seen = data.get("first_seen")
        if first_seen is not None and first_seen >= since:
            nodes.append(_make_graphnode(nid, data))
    return nodes


def find_high_degree_nodes(
    graph: nx.MultiDiGraph,
    top_n: int = 10,
    node_type: Optional[str] = None,
) -> list[tuple[GraphNode, int]]:
    """
    Return the *top_n* most-connected nodes by total degree (in + out).

    If *node_type* is provided, only consider nodes of that type.
    Results are sorted by degree descending.
    """
    candidates = [
        (nid, data)
        for nid, data in graph.nodes(data=True)
        if node_type is None or data.get("node_type") == node_type
    ]

    scored = [
        (_make_graphnode(nid, data), graph.degree(nid))
        for nid, data in candidates
    ]
    scored.sort(key=lambda t: t[1], reverse=True)
    return scored[:top_n]


def get_shortest_path(
    graph: nx.MultiDiGraph,
    source_id: str,
    target_id: str,
) -> Optional[list[GraphNode]]:
    """
    Return the shortest path between *source_id* and *target_id*.

    Uses an undirected view of the graph so paths are found regardless of
    edge direction.  Returns None if no path exists or either node is absent.
    """
    if not _has_node(graph, source_id) or not _has_node(graph, target_id):
        return None

    try:
        undirected = graph.to_undirected()
        path_ids: list[str] = nx.shortest_path(undirected, source_id, target_id)
        return [_make_graphnode(nid, graph.nodes[nid]) for nid in path_ids]
    except nx.NetworkXNoPath:
        return None
    except nx.NodeNotFound:
        return None
    except Exception:
        return None


def get_actor_profile(
    graph: nx.MultiDiGraph,
    actor_node_id: str,
) -> dict:
    """
    Return a structured profile dict for a ThreatActor node.

    Keys:
        node               — GraphNode for the actor
        connected_wallets  — list[GraphNode] of CryptoWallet neighbours
        connected_malware  — list[GraphNode] of MalwareFamily/RansomwareGroup
        connected_forums   — list[GraphNode] of Forum/OnionURL neighbours
        co_actors          — list[GraphNode] connected via LIKELY/CONFIRMED_SAME_ACTOR
        total_pages_appeared — number of unique source_urls on the node
        first_seen         — datetime
        last_seen          — datetime
    """
    if not _has_node(graph, actor_node_id):
        return {}

    node_data = graph.nodes[actor_node_id]
    actor_node = _make_graphnode(actor_node_id, node_data)

    _same_actor_types = {EDGE_TYPES.LIKELY_SAME_ACTOR, EDGE_TYPES.CONFIRMED_SAME_ACTOR}

    connected_wallets: list[GraphNode] = []
    connected_malware: list[GraphNode] = []
    connected_forums: list[GraphNode] = []
    co_actors: list[GraphNode] = []

    # Collect all adjacent nodes across all edges
    all_adjacent: set[str] = set()
    for _, nbr in graph.out_edges(actor_node_id):
        all_adjacent.add(nbr)
    for pred, _ in graph.in_edges(actor_node_id):
        all_adjacent.add(pred)

    for nbr_id in all_adjacent:
        if nbr_id == actor_node_id:
            continue
        nbr_data = graph.nodes.get(nbr_id, {})
        nbr_type = nbr_data.get("node_type", "")
        nbr_node = _make_graphnode(nbr_id, nbr_data)

        if nbr_type == NODE_TYPES.CRYPTO_WALLET:
            connected_wallets.append(nbr_node)
        elif nbr_type in (NODE_TYPES.MALWARE_FAMILY, NODE_TYPES.RANSOMWARE_GROUP):
            connected_malware.append(nbr_node)
        elif nbr_type in (NODE_TYPES.FORUM, NODE_TYPES.ONION_URL):
            connected_forums.append(nbr_node)

    # Co-actors: nodes connected specifically via same-actor edge types
    for _, nbr, data in graph.out_edges(actor_node_id, data=True):
        if data.get("edge_type") in _same_actor_types:
            co_actors.append(_make_graphnode(nbr, graph.nodes[nbr]))

    for pred, _, data in graph.in_edges(actor_node_id, data=True):
        if data.get("edge_type") in _same_actor_types:
            co_actors.append(_make_graphnode(pred, graph.nodes[pred]))

    # Deduplicate co_actors by node_id
    seen_co: set[str] = set()
    deduped_co: list[GraphNode] = []
    for n in co_actors:
        if n.node_id not in seen_co:
            seen_co.add(n.node_id)
            deduped_co.append(n)

    return {
        "node": actor_node,
        "connected_wallets": connected_wallets,
        "connected_malware": connected_malware,
        "connected_forums": connected_forums,
        "co_actors": deduped_co,
        "total_pages_appeared": len(node_data.get("source_urls", [])),
        "first_seen": node_data.get("first_seen"),
        "last_seen": node_data.get("last_seen"),
    }
