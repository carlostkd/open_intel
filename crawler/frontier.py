"""
crawler/frontier.py — Priority-queue crawl frontier with relevance scoring.

Each URL is scored by cosine similarity between "<url> <snippet>" and the
investigation query using the sentence-transformers all-MiniLM-L6-v2 model.
Higher score → popped sooner (max-priority implemented via negated scores on
a min-heap).

Uses vector.model_singleton for the shared SentenceTransformer instance.
"""

from __future__ import annotations

import heapq
import logging
from typing import Optional, Tuple

import numpy as np

from vector.model_singleton import get_embedding_model

_logger = logging.getLogger(__name__)


def _get_model():
    """Return the SentenceTransformer singleton."""
    return get_embedding_model()


# ---------------------------------------------------------------------------
# Cosine similarity
# ---------------------------------------------------------------------------

def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity clipped to [0.0, 1.0]."""
    denom = float(np.linalg.norm(a) * np.linalg.norm(b)) + 1e-10
    return float(np.clip(np.dot(a, b) / denom, 0.0, 1.0))


# ---------------------------------------------------------------------------
# Frontier
# ---------------------------------------------------------------------------

class Frontier:
    """
    Min-heap priority queue where URLs with *higher* relevance scores are
    popped first (achieved by storing negated scores as heap keys).

    Not thread-safe — designed for a single asyncio event loop.
    """

    def __init__(self, query: str) -> None:
        self._query = query
        self._heap: list = []
        self._counter = 0  # monotone tie-breaker so URLs are never compared
        self._query_embedding: Optional[np.ndarray] = None

    # ------------------------------------------------------------------
    # Embedding helpers
    # ------------------------------------------------------------------

    def _query_emb(self) -> np.ndarray:
        """Return (cached) embedding for the investigation query."""
        if self._query_embedding is None:
            self._query_embedding = _get_model().encode(
                self._query, convert_to_numpy=True
            )
        return self._query_embedding

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, url: str, snippet: str = "") -> float:
        """
        Compute relevance score (0.0–1.0) for *url* + optional *snippet*.

        The input text is "<url> <snippet>" embedded and compared to the
        investigation query via cosine similarity.  Returns 0.5 on any
        embedding failure so the crawler degrades gracefully.
        """
        text = f"{url} {snippet}".strip()
        try:
            model = _get_model()
            if model is None:
                return 0.5
            emb = model.encode(text, convert_to_numpy=True)
            return _cosine(emb, self._query_emb())
        except Exception as exc:
            _logger.debug("Frontier.score error: %s", exc)
            return 0.5

    def push(self, url: str, depth: int, score: float) -> None:
        """
        Add *url* at the given *depth* with pre-computed *score*.

        Call Frontier.score() first to obtain the score; separating scoring
        from pushing lets callers filter by min_relevance before enqueueing.
        """
        heapq.heappush(self._heap, (-score, self._counter, url, depth))
        self._counter += 1

    def pop(self) -> Tuple[str, int]:
        """
        Return (url, depth) for the highest-relevance item.
        Raises IndexError if the frontier is empty.
        """
        _, _, url, depth = heapq.heappop(self._heap)
        return url, depth

    def empty(self) -> bool:
        return not self._heap

    def __len__(self) -> int:
        return len(self._heap)
