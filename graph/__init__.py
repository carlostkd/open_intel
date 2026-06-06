"""
graph — Phase 3 graph relationship mapping module.

Exports all public symbols from the five sub-modules:
    model      — data definitions (node/edge types, dataclasses)
    builder    — graph construction from DB + manual mutation helpers
    queries    — pure query functions over a NetworkX graph
    export     — serialisation to GraphML, JSON, Gephi CSV
    visualize  — interactive HTML visualisation via pyvis
"""

from graph.model import (
    GraphEdge,
    GraphNode,
    EDGE_TYPES,
    NODE_TYPES,
)

from graph.builder import (
    add_entity_to_graph,
    add_relationship,
    build_graph_from_db,
    infer_relationships,
)

from graph.queries import (
    find_co_occurring_entities,
    find_high_degree_nodes,
    find_nodes_by_type,
    get_actor_profile,
    get_neighbors,
    get_new_nodes_since,
    get_shortest_path,
)

from graph.export import (
    summary_stats,
    to_graphml,
    to_json,
)

from graph.visualize import (
    build_pyvis_network,
    get_html_string,
)

__all__ = [
    # model
    "GraphNode",
    "GraphEdge",
    "NODE_TYPES",
    "EDGE_TYPES",
    # builder
    "build_graph_from_db",
    "add_entity_to_graph",
    "add_relationship",
    "infer_relationships",
    # queries
    "get_neighbors",
    "find_nodes_by_type",
    "find_co_occurring_entities",
    "get_new_nodes_since",
    "find_high_degree_nodes",
    "get_shortest_path",
    "get_actor_profile",
    # export
    "to_json",
    "to_graphml",
    "summary_stats",
    # visualize
    "build_pyvis_network",
    "get_html_string",
]
