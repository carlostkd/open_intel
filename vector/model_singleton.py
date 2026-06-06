"""
Thread-safe singleton for the SentenceTransformer embedding model.

Loads all-MiniLM-L6-v2 lazily on first use, then reuses the same instance
across all consumers. This eliminates the ~80 MB duplicate model weight
problem when multiple modules each instantiate their own model at load time.

Import torch and SentenceTransformer INSIDE the getter function to avoid
the 2-5 second startup delay from torch enumerating CUDA devices.
"""

from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

_model: "SentenceTransformer | None" = None
_lock = threading.Lock()


def get_embedding_model() -> "SentenceTransformer | None":
    """
    Return the shared SentenceTransformer instance.

    Lazy-loads the model on first call, then caches it for all subsequent calls.
    Thread-safe: uses a lock to prevent race conditions during init.
    """
    global _model

    if _model is not None:
        return _model

    with _lock:
        if _model is not None:
            return _model

        import torch  # noqa: PLC0415 - imported inside function per M-6
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        try:
            _model = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("Loaded embedding model all-MiniLM-L6-v2 (singleton)")
        except Exception as exc:
            logger.warning("Failed to load embedding model: %s", exc)
            _model = None

    return _model