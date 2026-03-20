#!/bin/bash
# Run script for FMC Tool web application

# Activate virtual environment if it exists
if [ -f "../venv/bin/activate" ]; then
    source ../venv/bin/activate
fi

# Install dependencies if needed
pip3 install -r requirements.txt

# Run the FastAPI application using uvicorn with HTTPS
CERT_DIR="$(dirname "$0")/certs"
python3 -m uvicorn app:app --host 0.0.0.0 --port 5001 --reload \
    --ssl-keyfile "$CERT_DIR/key.pem" \
    --ssl-certfile "$CERT_DIR/cert.pem"
