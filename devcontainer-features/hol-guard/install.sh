#!/usr/bin/env bash
set -euo pipefail

# HOL Guard DevContainer Feature
# Installs HOL Guard into a dev container for AI agent security

VERSION="${VERSION:-latest}"
INIT_HARNESS="${INITHARNESS:-auto}"
STRICT_MODE="${STRICTMODE:-false}"

echo "================================================"
echo "  HOL Guard DevContainer Feature"
echo "  https://hol.org/guard"
echo "================================================"

# Ensure Python is available
if ! command -v python3 &>/dev/null; then
    echo "ERROR: Python 3.10+ is required. Please install the Python feature first."
    echo "  Add to devcontainer.json: \"ghcr.io/devcontainers/features/python\""
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Detected Python: ${PY_VERSION}"

# Check minimum version (3.10+)
MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]; }; then
    echo "ERROR: HOL Guard requires Python 3.10+. Found ${PY_VERSION}."
    exit 1
fi

# Install pipx if not present
if ! command -v pipx &>/dev/null; then
    echo "Installing pipx..."
    python3 -m pip install --user pipx
    export PATH="${PATH}:${HOME}/.local/bin"
fi

# Install hol-guard
if [ "$VERSION" = "latest" ]; then
    echo "Installing HOL Guard (latest)..."
    pipx install hol-guard
else
    echo "Installing HOL Guard v${VERSION}..."
    pipx install "hol-guard==${VERSION}"
fi

# Initialize for harness if requested
if [ "$INIT_HARNESS" != "none" ]; then
    echo ""
    echo "Initializing HOL Guard for harness: ${INIT_HARNESS}..."
    if [ "$INIT_HARNESS" = "auto" ]; then
        hol-guard init
    else
        hol-guard init --harness "$INIT_HARNESS"
    fi

    if [ "$STRICT_MODE" = "true" ]; then
        echo "Enabling strict mode..."
        hol-guard config set strict true
    fi
fi

echo ""
echo "HOL Guard installed successfully."
echo "  Docs: https://hol.org/guard"
echo "  CLI:  hol-guard --help"
echo "================================================"
