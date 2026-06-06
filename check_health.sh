#!/usr/bin/env bash
# Step 3.1 — Wait for all services healthy
echo "=== Waiting for health ==="
READY=false
for i in $(seq 1 60); do
  STATUS=$(curl -s http://localhost:8000/healthz/ready 2>/dev/null | python3 -c \
    "import sys,json
try:
    print(json.load(sys.stdin).get('status','?'))
except:
    print('not_ready')" 2>/dev/null)
  
  if [ "$STATUS" = "ready" ]; then
    echo "✓ Backend ready after $((i*5))s"
    READY=true
    break
  fi
  
  [ $((i % 6)) -eq 0 ] && echo "  [$((i*5))s] waiting... ($STATUS)"
  sleep 5
done

[ "$READY" = "false" ] && echo "✗ Not ready after 5min" && docker compose -f infra/docker-compose.yml --project-directory . logs fastapi --tail=30

# Step 3.2 — Check all 4 services
docker compose -f infra/docker-compose.yml --project-directory . ps --format "table {{.Name}}\t{{.State}}\t{{.Health}}"

# Step 3.3 — Check migrations applied
docker compose -f infra/docker-compose.yml --project-directory . exec -T fastapi alembic upgrade head 2>&1 | tail -5
echo ""
docker compose -f infra/docker-compose.yml --project-directory . exec -T postgres psql -U voidaccess -d voidaccess -c "SELECT version_num FROM alembic_version;" 2>/dev/null

# Step 3.4 — Check for import errors in logs
echo "=== Import/startup errors ==="
docker compose -f infra/docker-compose.yml --project-directory . logs fastapi --tail=50 | \
  grep -E "ImportError|ModuleNotFoundError|AttributeError|ERROR|CRITICAL" | \
  grep -v "^#" | head -20
