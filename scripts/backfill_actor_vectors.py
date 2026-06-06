"""
Backfill script: sync existing ActorStyleProfile rows to ChromaDB.

Safe to run multiple times - uses upsert (not insert).
"""

import logging

from db.session import get_session
from db.models import ActorStyleProfile
from vector import store as vector_store

logger = logging.getLogger(__name__)


def backfill_actor_vectors() -> int:
    """
    Load all ActorStyleProfile rows from DB and upsert their vectors to ChromaDB.
    Returns the number of profiles processed.
    """
    count = 0
    with get_session() as session:
        profiles = session.query(ActorStyleProfile).all()
        logger.info(f"Found {len(profiles)} actor style profiles to backfill")

        for profile in profiles:
            try:
                if not profile.style_vector:
                    logger.warning(f"Skipping profile {profile.id} - empty style_vector")
                    continue

                success = vector_store.upsert_actor_profile(
                    actor_id=profile.id,
                    style_vector=profile.style_vector,
                    username=profile.canonical_value,
                    platform=profile.entity_type,
                )
                if success:
                    count += 1
                else:
                    logger.warning(f"Failed to upsert profile {profile.id}")
            except Exception as exc:
                logger.error(f"Error backfilling profile {profile.id}: {exc}")

    logger.info(f"Backfill complete: {count}/{len(profiles)} profiles synced to ChromaDB")
    return count


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    backfill_actor_vectors()


if __name__ == "__main__":
    main()