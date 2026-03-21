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

# ── 3. Detect and fix PATH ────────────────────────────────────────────────────
LOCAL_BIN="$HOME/.local/bin"
NEEDS_PATH=false

if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
    NEEDS_PATH=true
fi

if $NEEDS_PATH; then
    echo ""
    echo -e "${YELLOW}⚠  ~/.local/bin is not in your PATH (this is why 'secara' command isn't found).${RESET}"

    # Detect shell and rc file
    SHELL_NAME=$(basename "$SHELL")
    case "$SHELL_NAME" in
        bash) RC_FILE="$HOME/.bashrc" ;;
        zsh)  RC_FILE="$HOME/.zshrc"  ;;
        fish) RC_FILE="$HOME/.config/fish/config.fish" ;;
        *)    RC_FILE="$HOME/.profile" ;;
    esac

    EXPORT_LINE='export PATH="$HOME/.local/bin:$PATH"'

    # Avoid duplicate entries
    if ! grep -qF "$LOCAL_BIN" "$RC_FILE" 2>/dev/null; then
        echo "" >> "$RC_FILE"
        echo "# Added by Secara installer" >> "$RC_FILE"
        echo "$EXPORT_LINE" >> "$RC_FILE"
        echo -e "${GREEN}✓ Added ~/.local/bin to PATH in ${RC_FILE}${RESET}"
    else
        echo -e "${GREEN}✓ ~/.local/bin already in ${RC_FILE}${RESET}"
    fi

    # Apply immediately for this session
    export PATH="$LOCAL_BIN:$PATH"
fi

# ── 4. Verify secara command ──────────────────────────────────────────────────
echo ""
if command -v secara &>/dev/null; then
    SECARA_PATH=$(command -v secara)
    echo -e "${GREEN}✓ secara command is ready: ${SECARA_PATH}${RESET}"
else
    # Last resort: try python -m secara
    echo -e "${YELLOW}  'secara' binary not found in PATH, checking fallback...${RESET}"
    if python3 -m secara.cli --version &>/dev/null 2>&1; then
        echo -e "${GREEN}✓ secara works via: python3 -m secara.cli${RESET}"
    fi
fi

# ── 5. Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}────────────────────────────────${RESET}"
echo -e "${GREEN}${BOLD}✅ Installation complete!${RESET}"
echo ""
echo -e "  ${BOLD}Reload your shell or run:${RESET}"
echo -e "    ${CYAN}source ${RC_FILE:-~/.bashrc}${RESET}"
echo ""
echo -e "  ${BOLD}Then scan a directory:${RESET}"
echo -e "    ${CYAN}secara scan .${RESET}"
echo -e "    ${CYAN}secara scan ./src --severity HIGH${RESET}"
echo -e "    ${CYAN}secara scan . --verbose${RESET}"
echo ""
