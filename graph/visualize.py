"""
graph/visualize.py — Interactive graph visualisation using pyvis.

Converts a NetworkX MultiDiGraph to a pyvis Network and exports it as a
self-contained HTML file suitable for embedding in Streamlit via st.components.

If pyvis is not installed, all functions log a warning and return None / empty
string.  They never raise on a missing dependency.

Public interface
----------------
build_pyvis_network(graph, max_nodes, highlight_node_id)  → Network | None
export_html(network, filepath)                            → None
get_html_string(network)                                  → str
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

import networkx as nx

from graph.model import NODE_TYPES

if TYPE_CHECKING:
    pass  # pyvis.network.Network imported conditionally at runtime

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Node colour palette (hex strings)
# ---------------------------------------------------------------------------

_NODE_COLORS: dict[str, str] = {
    NODE_TYPES.THREAT_ACTOR:      "#e74c3c",  # red
    NODE_TYPES.CRYPTO_WALLET:     "#f39c12",  # gold
    NODE_TYPES.MALWARE_FAMILY:    "#9b59b6",  # purple
    NODE_TYPES.RANSOMWARE_GROUP:  "#9b59b6",  # purple
    NODE_TYPES.ONION_URL:         "#3498db",  # blue
    NODE_TYPES.FORUM:             "#3498db",  # blue
    NODE_TYPES.CVE:               "#e67e22",  # orange
    NODE_TYPES.EMAIL_ADDRESS:     "#2ecc71",  # green
    NODE_TYPES.PGP_KEY:           "#2ecc71",  # green
    NODE_TYPES.PASTE:             "#95a5a6",  # grey
}

_DEFAULT_COLOR = "#bdc3c7"  # light grey fallback
_HIGHLIGHT_BORDER = "#f1c40f"  # yellow

# Edge width thresholds mapped to pyvis ``width`` values
_EDGE_WIDTH_THIN   = 1.0   # confidence < 0.4
_EDGE_WIDTH_MEDIUM = 3.0   # 0.4 <= confidence < 0.7
_EDGE_WIDTH_THICK  = 5.0   # confidence >= 0.7


def _confidence_to_width(confidence: float) -> float:
    if confidence < 0.4:
        return _EDGE_WIDTH_THIN
    if confidence < 0.7:
        return _EDGE_WIDTH_MEDIUM
    return _EDGE_WIDTH_THICK


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def build_pyvis_network(
    graph: nx.MultiDiGraph,
    max_nodes: int = 200,
    highlight_node_id: Optional[str] = None,
) -> "Optional[object]":
    """
    Convert *graph* into a pyvis Network.

    If the graph has more than *max_nodes* nodes, only the highest-degree
    nodes are retained.

    If *highlight_node_id* is given, that node receives a yellow border.

    Returns the pyvis Network, or None if pyvis is not installed.
    """
    try:
        from pyvis.network import Network  # noqa: PLC0415
    except ImportError:
        logger.warning(
            "pyvis is not installed — graph visualisation is unavailable. "
            "Install it with: pip install pyvis"
        )
        return None

    # Trim graph to max_nodes highest-degree nodes if necessary
    if graph.number_of_nodes() > max_nodes:
        top_nodes = sorted(
            graph.nodes(), key=lambda n: graph.degree(n), reverse=True
        )[:max_nodes]
        subgraph = graph.subgraph(top_nodes)
    else:
        subgraph = graph

    net = Network(
        height="750px",
        width="100%",
        directed=True,
        notebook=False,
    )
    net.force_atlas_2based()

    for node_id, data in subgraph.nodes(data=True):
        node_type = data.get("node_type", "")
        color = _NODE_COLORS.get(node_type, _DEFAULT_COLOR)

        node_kwargs: dict = {
            "label": node_id,
            "color": color,
            "title": f"Type: {node_type}\nID: {node_id}",
        }

        if node_id == highlight_node_id:
            node_kwargs["color"] = {
                "background": color,
                "border": _HIGHLIGHT_BORDER,
            }
            node_kwargs["borderWidth"] = 3

        net.add_node(node_id, **node_kwargs)

    for src, tgt, data in subgraph.edges(data=True):
        confidence = data.get("confidence", 0.5)
        edge_type = data.get("edge_type", "")
        net.add_edge(
            src,
            tgt,
            title=f"{edge_type} (confidence={confidence:.2f})",
            width=_confidence_to_width(confidence),
        )

    return net


def export_html(network: "object", filepath: str) -> None:
    """
    Save the pyvis Network as a self-contained HTML file.

    Does nothing if *network* is None (pyvis not installed).
    """
    if network is None:
        logger.warning("export_html called with None network — skipping.")
        return
    try:
        network.save_graph(filepath)  # type: ignore[attr-defined]
    except Exception as exc:
        logger.warning("export_html failed: %s", exc)


def get_html_string(network: "object") -> str:
    """
    Return the full interactive HTML as a string.

    Used for embedding in Streamlit via ``st.components.v1.html()``.
    Returns an empty string if *network* is None or pyvis is not installed.
    """
    if network is None:
        return ""
    try:
        return network.generate_html()  # type: ignore[attr-defined]
    except AttributeError:
        # Older pyvis versions use get_network_html
        try:
            return network.get_network_html()  # type: ignore[attr-defined]
        except Exception as exc:
            logger.warning("get_html_string failed: %s", exc)
            return ""
    except Exception as exc:
        logger.warning("get_html_string failed: %s", exc)
        return ""
