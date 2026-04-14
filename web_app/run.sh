#!/bin/bash
# Run script for SIT web application
# Serves both the FastAPI backend and React SPA on a single port (8000).
#
# Usage:
#   ./run.sh              # Build frontend + start server on port 8000
#   ./run.sh --no-build   # Skip frontend build (use existing spa/ directory)
#   ./run.sh --dev        # Start backend only (for use with Vite dev server)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/frontend"
CERT_DIR="$SCRIPT_DIR/certs"
PORT="${SIT_PORT:-8000}"
NO_BUILD=false
DEV_MODE=false

for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        --dev)      DEV_MODE=true; NO_BUILD=true ;;
    esac
done

# Activate virtual environment if it exists
if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    source "$PROJECT_ROOT/venv/bin/activate"
fi

# Install Python dependencies
pip3 install -q -r "$PROJECT_ROOT/requirements.txt"

# Build React SPA (unless --no-build or --dev)
if [ "$NO_BUILD" = false ] && [ -d "$FRONTEND_DIR" ]; then
    echo "Building React frontend..."
    if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
        echo "Installing frontend dependencies..."
        (cd "$FRONTEND_DIR" && npm install)
    fi
    (cd "$FRONTEND_DIR" && npm run build)
    echo "Frontend build complete -> web_app/spa/"
fi

echo "Starting SIT on port $PORT (HTTPS)..."

# Run the FastAPI application using uvicorn with HTTPS
python3 -m uvicorn app:app --host 0.0.0.0 --port "$PORT" \
    --ssl-keyfile "$CERT_DIR/key.pem" \
    --ssl-certfile "$CERT_DIR/cert.pem"
