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
    # Ensure Node.js / npm is available
    if ! command -v npm &>/dev/null; then
        echo "npm not found — installing Node.js 20.x LTS..."
        if command -v apt-get &>/dev/null; then
            curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
            apt-get install -y nodejs
        else
            echo "ERROR: npm is not installed and auto-install is only supported on Debian/Ubuntu."
            echo "Install Node.js manually or run with --no-build (pre-build the frontend locally)."
            exit 1
        fi
    fi

    echo "Building React frontend..."
    if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
        echo "Installing frontend dependencies..."
        (cd "$FRONTEND_DIR" && npm install)
    fi
    (cd "$FRONTEND_DIR" && npm run build)
    echo "Frontend build complete -> web_app/spa/"
fi

# Optionally fetch a CA-signed certificate from Things at startup
if [ -n "${THINGS_API_TOKEN:-}" ] && [ -n "${THINGS_TOOL_SLUG:-}" ]; then
    echo "Things integration configured — checking certificate..."
    python3 -c "
import os, sys, socket, requests
base = os.environ.get('THINGS_BASE_URL', 'https://things.cisco.com')
slug = os.environ['THINGS_TOOL_SLUG']
token = os.environ['THINGS_API_TOKEN']
unseal = os.environ.get('THINGS_UNSEAL_KEY', '')
cert_dir = '$CERT_DIR'
cert_path = os.path.join(cert_dir, 'cert.pem')
# Auto-detect server IP (or use THINGS_CERT_CN override)
cn = os.environ.get('THINGS_CERT_CN', '').strip()
if not cn:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        cn = s.getsockname()[0]
        s.close()
    except Exception:
        cn = socket.gethostname()
alts = list({cn, 'localhost', '127.0.0.1'})
# Check if current cert is self-signed or missing
need_refresh = not os.path.exists(cert_path)
if not need_refresh:
    try:
        from cryptography import x509
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        need_refresh = cert.subject == cert.issuer  # self-signed
    except Exception:
        need_refresh = True
if need_refresh:
    print(f'Requesting CA-signed certificate from Things (CN={cn})...')
    try:
        hdrs = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        if unseal:
            hdrs['X-Unseal-Key'] = unseal
        resp = requests.post(
            f'{base}/api/tools/{slug}/certs',
            headers=hdrs,
            json={'common_name': cn, 'subject_alts': alts, 'validity_days': 365},
            timeout=30, verify=False,
        )
        resp.raise_for_status()
        d = resp.json()
        os.makedirs(cert_dir, exist_ok=True)
        chain = d['cert_pem']
        if d.get('ca_cert_pem'):
            chain = d['cert_pem'].rstrip('\n') + '\n' + d['ca_cert_pem']
        with open(os.path.join(cert_dir, 'cert.pem'), 'w') as f: f.write(chain)
        with open(os.path.join(cert_dir, 'key.pem'), 'w') as f: f.write(d['key_pem'])
        os.chmod(os.path.join(cert_dir, 'key.pem'), 0o600)
        if d.get('ca_cert_pem'):
            with open(os.path.join(cert_dir, 'ca.pem'), 'w') as f: f.write(d['ca_cert_pem'])
        print(f\"Certificate issued: CN={d.get('common_name')}, expires={d.get('expires_at')}\")
    except Exception as e:
        print(f'Warning: Could not fetch Things certificate: {e}', file=sys.stderr)
        print('Falling back to existing certificate.', file=sys.stderr)
else:
    print('Certificate is CA-signed — no refresh needed.')
" 2>&1 || true
fi

echo "Starting SIT on port $PORT (HTTPS)..."

# Run the FastAPI application using uvicorn with HTTPS
python3 -m uvicorn app:app --host 0.0.0.0 --port "$PORT" \
    --ssl-keyfile "$CERT_DIR/key.pem" \
    --ssl-certfile "$CERT_DIR/cert.pem"
