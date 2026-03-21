#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Secara — Installer Script
# Installs secara and ensures the `secara` command is available in your shell.
# Supports: Linux, macOS
# Usage:   bash install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

echo -e "${CYAN}"
echo " ____                           "
echo "/ ___|  ___  ___ __ _ _ __ __ _ "
echo "\\___ \\ / _ \\/ __/ _\` | '__/ _\` |"
echo " ___) |  __/ (_| (_| | | | (_| |"
echo "|____/ \\___|\\___\\__,_|_|  \\__,_|"
echo -e "${RESET}"
echo -e "${BOLD}Secara Installer${RESET}"
echo "────────────────────────────────"

# ── 1. Check Python ───────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}✗ Python 3 is required but not found.${RESET}"
    echo "  Install it with: sudo apt install python3 python3-pip"
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}✓ Python ${PY_VERSION} found${RESET}"

# ── 2. Install secara ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Installing secara...${RESET}"

if pip3 install -e . --quiet 2>&1; then
    echo -e "${GREEN}✓ secara installed successfully${RESET}"
else
    echo -e "${YELLOW}  Trying with --user flag...${RESET}"
    pip3 install -e . --user --quiet
    echo -e "${GREEN}✓ secara installed (user mode)${RESET}"
fi

# ── 3. Find the installed binary and link it ────────────────────────────────────
echo ""
echo -e "${BOLD}Configuring command line access...${RESET}"

# Find where pip installed the binary
SECARA_BIN=""
if command -v secara &>/dev/null; then
    SECARA_BIN=$(command -v secara)
elif [ -f "$HOME/.local/bin/secara" ]; then
    SECARA_BIN="$HOME/.local/bin/secara"
elif [ -f "/usr/local/bin/secara" ]; then
    SECARA_BIN="/usr/local/bin/secara"
fi

if [ -z "$SECARA_BIN" ]; then
    echo -e "${RED}✗ Could not locate the installed 'secara' binary.${RESET}"
    echo "  Try running: python3 -m secara.cli"
    exit 1
fi

# Check if it's already in the system PATH
if command -v secara &>/dev/null && [ "$(command -v secara)" = "/usr/local/bin/secara" ]; then
    echo -e "${GREEN}✓ 'secara' is already globally available.${RESET}"
else
    echo -e "${YELLOW}  To make the 'secara' command available everywhere without restarting"
    echo -e "  your terminal, we will create a symlink in /usr/local/bin.${RESET}"
    echo -e "  ${CYAN}(This requires sudo privileges)${RESET}"
    
    if sudo ln -sf "$SECARA_BIN" /usr/local/bin/secara; then
        echo -e "${GREEN}✓ Successfully created symlink in /usr/local/bin/secara${RESET}"
    else
        echo -e "${RED}✗ Failed to create symlink. You may need to add ${SECARA_BIN%/*} to your PATH manually.${RESET}"
    fi
fi

# ── 4. Verify secara command ──────────────────────────────────────────────────
echo ""
if command -v secara &>/dev/null; then
    echo -e "${GREEN}✓ secara command is ready: $(command -v secara)${RESET}"
else
    echo -e "${YELLOW}  'secara' binary not found in PATH. You can run it via: python3 -m secara.cli${RESET}"
fi

# ── 5. Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}────────────────────────────────${RESET}"
echo -e "${GREEN}${BOLD}✅ Installation complete!${RESET}"
echo ""
echo -e "  ${BOLD}You can now scan a directory from anywhere:${RESET}"
echo -e "    ${CYAN}secara scan .${RESET}"
echo -e "    ${CYAN}secara scan ./src --severity HIGH${RESET}"
echo -e "    ${CYAN}secara scan . --verbose${RESET}"
echo ""
