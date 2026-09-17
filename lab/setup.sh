#!/usr/bin/env bash
# language: bash, file: setup.sh, target: Red Sky lab launcher
# Brings up the vulnerable target range. Requires docker + docker compose.

set -e

cd "$(dirname "$0")"

RED="\033[38;2;255;36;0m"
BLOOD="\033[38;2;120;0;0m"
BONE="\033[38;2;230;220;210m"
ASH="\033[38;2;120;120;120m"
OK="\033[38;2;80;200;80m"
RESET="\033[0m"

banner() {
    printf "%s" "$BLOOD"
    cat << 'BANNER'
    ██▀███  ▓█████ ▓█████▄      ██████  ██ ▄█▀▓██   ██▓
    ▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌   ▒██    ▒  ██▄█▒  ▒██  ██▒
    ▓██ ░▄█ ▒▒███   ░██   █▌   ░ ▓██▄   ▓███▄░   ▒██ ██░
    ▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌     ▒   ██▒▓██ █▄   ░ ▐██▓░
    ░██▓ ▒██▒░▒████▒░▒████▓    ▒██████▒▒▒██▒ █▄  ░ ██▒▓░
BANNER
    printf "%s\n" "$RESET"
}

case "${1:-up}" in
    up)
        banner
        echo -e "${ASH}starting red sky lab...${RESET}"
        docker compose up -d
        echo
        echo -e "${OK}▓ lab up.${RESET}"
        echo
        echo -e "  ${BONE}DVWA           ${ASH}http://127.0.0.1:8081${RESET}"
        echo -e "  ${BONE}Juice Shop     ${ASH}http://127.0.0.1:8082${RESET}"
        echo -e "  ${BONE}WebGoat        ${ASH}http://127.0.0.1:8083${RESET}"
        echo -e "  ${BONE}Mutillidae     ${ASH}http://127.0.0.1:8084${RESET}"
        echo -e "  ${BONE}vuln-node      ${ASH}http://127.0.0.1:8085${RESET}"
        echo -e "  ${BONE}redis (unauth) ${ASH}127.0.0.1:6379${RESET}"
        echo -e "  ${BONE}mysql (weak)   ${ASH}127.0.0.1:3307 (root:root)${RESET}"
        echo
        ;;
    down)
        docker compose down -v
        echo -e "${OK}▓ lab down.${RESET}"
        ;;
    status)
        docker compose ps
        ;;
    *)
        echo "usage: $0 {up|down|status}"
        exit 1
        ;;
esac
