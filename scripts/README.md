# Scripts

Utility scripts for managing the Open_Intel stack. These are not required for normal operation — they handle one-off admin tasks and setup.

## Scripts

### `import_seed.py`
Populates the database with seed threat intelligence data on first run. Called automatically by `docker-entrypoint.sh` when the database is empty. Run manually inside the container if you need to re-seed:
```bash
docker compose -f infra/docker-compose.yml exec fastapi python scripts/import_seed.py
```

### `download_seed.py`
Downloads the seed dataset from the configured source before importing. Run this if `import_seed.py` reports missing data files.

### `reset_password.py`
Admin CLI to reset a user's password directly in the database. Run inside the container:
```bash
docker compose -f infra/docker-compose.yml exec fastapi python scripts/reset_password.py <email> <new_password>
```

### `health_check.py`
Checks connectivity to Tor, the database, and the API. Useful for diagnosing startup issues. The `check_health.sh` wrapper at the root calls this script.

### `backfill_actor_vectors.py`
Regenerates embedding vectors for all existing actor profiles in the database. Run this after upgrading the sentence-transformer model or if vector search results look incorrect.

### `start-tor.ps1`
PowerShell script that starts Tor on Windows outside of Docker. Not needed when using Docker Compose — Tor runs as a container service. Useful only for bare-metal Windows development setups.

### `crop_logo.py`
One-time image processing utility used to generate `public/logo_circle.png` from the source logo. Not needed unless the logo is being updated.
