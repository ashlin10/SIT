#!/bin/bash
# Run script for Vyper web application

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/../frontend"

# Activate virtual environment if it exists
if [ -f "../venv/bin/activate" ]; then
    source ../venv/bin/activate
fi

# Install Python dependencies if needed
pip3 install -r requirements.txt

# Build React SPA (if frontend directory exists and has node_modules)
if [ -d "$FRONTEND_DIR" ]; then
    echo "Building React frontend..."
    if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
        echo "Installing frontend dependencies..."
        (cd "$FRONTEND_DIR" && npm install)
    fi
    (cd "$FRONTEND_DIR" && npm run build)
    echo "Frontend build complete -> web_app/spa/"
fi

# Run the FastAPI application using uvicorn with HTTPS
CERT_DIR="$SCRIPT_DIR/certs"
python3 -m uvicorn app:app --host 0.0.0.0 --port 8001 --reload \
    --ssl-keyfile "$CERT_DIR/key.pem" \
    --ssl-certfile "$CERT_DIR/cert.pem"
