#!/usr/bin/env bash
# Open_Intel — stop the full stack.
# Usage: ./stop.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

printf "\n"
printf "${CYAN}"
printf "  ╔═══════════════════════════════════╗\n"
printf "  ║  Open_Intel  ·  Shutting down     ║\n"
printf "  ╚═══════════════════════════════════╝\n"
printf "${NC}\n"

if ! docker info > /dev/null 2>&1; then
    if sudo docker info > /dev/null 2>&1; then
        printf "\n  ${YELLOW}⚠${NC}  Docker requires sudo on this system.\n"
        printf "  ${DIM}→${NC}  Re-run with: ${BOLD}sudo bash stop.sh${NC}\n\n"
        exit 1
    else
        printf "\n  ${RED}✗${NC}  Docker not found or not running.\n"
        printf "  ${DIM}→${NC}  Install: ${DIM}https://docs.docker.com/get-docker/${NC}\n\n"
        exit 1
    fi
fi

printf "  ${DIM}→${NC}  Stopping containers...\n"
ENV_ARG=""
if [ -f "$SCRIPT_DIR/.env" ]; then
    ENV_ARG="--env-file $SCRIPT_DIR/.env"
fi
docker compose -f "$SCRIPT_DIR/infra/docker-compose.yml" \
    --project-directory "$SCRIPT_DIR" \
    $ENV_ARG \
    down > /dev/null 2>&1
printf "  ${GREEN}✓${NC}  All services stopped\n"
printf "\n"
