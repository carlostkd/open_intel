#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

# Docker permission check
if ! docker info > /dev/null 2>&1; then
    if sudo docker info > /dev/null 2>&1; then
        printf "\n  ${YELLOW}⚠${NC}  Docker needs sudo.\n"
        printf "  ${DIM}→${NC}  Run: ${BOLD}sudo bash start.sh${NC}\n\n"
        exit 1
    else
        printf "\n  ${RED}✗${NC}  Docker not running.\n"
        exit 1
    fi
fi

# .env check
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    printf "\n  ${RED}✗${NC}  No .env found.\n"
    printf "  ${DIM}→${NC}  Run setup first: "
    printf "${BOLD}bash setup.sh${NC}\n\n"
    exit 1
fi

# Auto-detect compose file (absolute path so docker compose finds it
# regardless of where the user invoked the script from)
if [ -f "$SCRIPT_DIR/infra/docker-compose.yml" ]; then
    COMPOSE_FILE="$SCRIPT_DIR/infra/docker-compose.yml"
elif [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
    COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
else
    printf "\n  ${RED}✗${NC}  docker-compose.yml not found\n\n"
    exit 1
fi

# Use absolute paths for --project-directory and --env-file. Compose resolves
# --env-file relative to the current working directory; an absolute path means
# the variables (POSTGRES_PASSWORD, JWT_SECRET, etc.) always reach containers
# even if the user invokes start.sh from outside the repo root.
COMPOSE_CMD="docker compose -f $COMPOSE_FILE \
    --project-directory $SCRIPT_DIR \
    --env-file $SCRIPT_DIR/.env"

# Banner
printf "\n"
printf "  ${CYAN}╔═══════════════════════════════════╗${NC}\n"
printf "  ${CYAN}║${NC}  ${BOLD}Open_Intel${NC}  ·  Starting up       "
printf "${CYAN}║${NC}\n"
printf "  ${CYAN}╚═══════════════════════════════════╝${NC}\n\n"

printf "  ${DIM}→${NC}  Building and starting containers...\n"
printf "  ${DIM}→${NC}  First run takes 3-5 min. "
printf "Cached after that.\n\n"

# Run with output visible
$COMPOSE_CMD up --build -d
BUILD_EXIT=$?

if [ $BUILD_EXIT -ne 0 ]; then
    printf "\n  ${RED}✗${NC}  Failed to start.\n"
    printf "  ${DIM}→${NC}  Run for full output:\n"
    printf "  ${DIM}   $COMPOSE_CMD up --build${NC}\n\n"
    exit 1
fi

printf "\n  ${DIM}→${NC}  Checking services...\n\n"

ALL_OK=true
for SVC in postgres tor fastapi nextjs; do
    LABEL="$SVC"
    case $SVC in
        postgres) LABEL="PostgreSQL" ;;
        tor)      LABEL="Tor" ;;
        fastapi)  LABEL="FastAPI" ;;
        nextjs)   LABEL="Next.js" ;;
    esac
    
    HEALTHY=false
    for attempt in $(seq 1 40); do
        STATE=$(docker inspect \
            --format='{{.State.Status}}' \
            "voidaccess-${SVC}" 2>/dev/null \
            || echo "missing")
        HEALTH=$(docker inspect \
            --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
            "voidaccess-${SVC}" 2>/dev/null \
            || echo "none")
        
        if [ "$HEALTH" = "healthy" ] || \
           { [ "$STATE" = "running" ] && \
             [ "$HEALTH" = "none" ]; }; then
            printf "  ${GREEN}✓${NC}  $LABEL\n"
            HEALTHY=true
            break
        fi
        
        printf "\r  ${CYAN}·${NC}  $LABEL (${attempt}/40)...   "
        sleep 3
    done
    
    printf "\r%-60s\r" " "
    
    if [ "$HEALTHY" = "false" ]; then
        printf "  ${YELLOW}⚠${NC}  $LABEL — not healthy\n"
        ALL_OK=false
    fi
done

printf "\n"

if [ "$ALL_OK" = "true" ]; then
    printf "  ${GREEN}╔═══════════════════════════════════╗${NC}\n"
    printf "  ${GREEN}║${NC}  ${BOLD}✓  Open_Intel is ready!${NC}           "
    printf "${GREEN}║${NC}\n"
    printf "  ${GREEN}╠═══════════════════════════════════╣${NC}\n"
    printf "  ${GREEN}║${NC}  UI   →  http://localhost:3001   "
    printf "${GREEN}║${NC}\n"
    printf "  ${GREEN}║${NC}  API  →  http://localhost:8000   "
    printf "${GREEN}║${NC}\n"
    printf "  ${GREEN}╚═══════════════════════════════════╝${NC}\n\n"
else
    printf "  ${YELLOW}⚠${NC}  Some services slow — check:\n"
    printf "  ${DIM}  $COMPOSE_CMD logs -f${NC}\n\n"
fi