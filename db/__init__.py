"""
db — persistent storage layer (Phase 1A).

Public surface:
    Base                  — SQLAlchemy declarative base; import to create schema
    Investigation         — investigation run record
    Source                — every .onion domain ever seen
    Page                  — every scraped page
    Entity                — structured intelligence artifact extracted from a page
    EntityRelationship    — link between two entities
    investigation_sources — many-to-many junction table (Investigation <-> Source)
    get_engine            — create / retrieve a SQLAlchemy Engine
    get_session_factory   — return a sessionmaker bound to an engine
    get_session           — context-manager that yields a committed/rolled-back Session
"""

from db.models import (
    Base,
    Investigation,
    Source,
    Page,
    Entity,
    EntityRelationship,
    investigation_sources,
    SourceStatus,
    SourceType,
    EntityType,
    RelationshipType,
)
from db.session import get_engine, get_session_factory, get_session

__all__ = [
    "Base",
    "Investigation",
    "Source",
    "Page",
    "Entity",
    "EntityRelationship",
    "investigation_sources",
    "SourceStatus",
    "SourceType",
    "EntityType",
    "RelationshipType",
    "get_engine",
    "get_session_factory",
    "get_session",
]
