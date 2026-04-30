# Vyper — SIT (Security Integration Toolkit)

A web-based control plane for Cisco Firepower (FMC, FTD, FXOS), StrongSwan IPsec
endpoints, and Snort 3 traffic generators. Vyper consolidates day‑2 operations
(configuration, troubleshooting, traffic generation, VPN debugging) into a
single React SPA backed by a FastAPI service.

## Highlights

- **FMC Configuration** — multi-domain FMC connection, device/chassis/VPN
  configuration push and pull via YAML, VPN topology builder
- **Command Center** — bulk SSH operations on FTD/FMC fleets (proxy, static
  routes, upgrades, backup restore, dev-cert copy) plus a built-in terminal
- **VPN Console** — live tunnel introspection, SwanCtl template builder,
  StrongSwan/charon log viewer, traffic generation
- **Dashboard** — real-time system health, request rate, error rate,
  per-user activity, persisted in SQLite
- **Settings** — theme + connection presets

---

## Quick Start

### Prerequisites
- Python 3.8+
- Node 18+ (for building the React SPA)
- SSH reachability to your FTDs / FMCs / strongSwan endpoints

### Setup

```bash
git clone <repo-url>
cd SIT

# 1. Python deps
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Frontend build (produces web_app/spa)
cd frontend
npm install
npm run build
cd ..

# 3. Required env + users (see "Configuration" below)
cp .env.example .env  # if available, otherwise create it
# edit .env

# 4. Run
cd web_app
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Open `http://localhost:8000`. Default login: `cisco` / `cisco`.

---

## Pages

The SPA is mounted under `/` with these top-level pages (router definitions in
`@/Users/aleroyds/PycharmProjects/SIT/frontend/src/App.tsx:23-27`):

### 1. Dashboard (`/dashboard`)

Live operational metrics for the Vyper backend itself.

- **Key metrics**: Active Users, Requests-per-Minute, Error Rate %,
  Avg Response Time
- **Time-series charts**: requests + errors, CPU/memory, per-user activity
- **System health card**: CPU %, memory %, disk %, uptime, status
  (`healthy` / `warning` / `critical`)
- **Top active users** and **recent activity feed**
- **Time range selector**: 1h, 24h, 7d, 30d, 90d, 180d, 1y, all

All metrics are stored in `web_app/data/dashboard_metrics.db` (SQLite, WAL mode).
This file is **per-server runtime data** and is git-ignored — see
[Persistent Data Files](#persistent-data-files).

Implementation: backend `@/Users/aleroyds/PycharmProjects/SIT/web_app/dashboard_metrics.py`,
frontend `@/Users/aleroyds/PycharmProjects/SIT/frontend/src/pages/DashboardPage.tsx`.

### 2. FMC Configuration (`/fmc-configuration`)

Three tabs for managing Cisco FMC objects.

#### Connection panel
- Connect to an FMC instance (IP/hostname, username, password)
- Multi-domain support — pick the target domain after connect
- Save reusable **connection presets** (passwords are Fernet-encrypted at rest)

#### Device tab
- List FTDs registered in the chosen FMC domain
- **Get config** — fetch interfaces (Physical, Loopback, Subinterface,
  EtherChannel, VTI, BridgeGroup, InlineSet), routing (BGP, OSPF, EIGRP, Static,
  PBR, ECMP, VRF), and objects (Security Zones, Network Objects, Port Objects,
  Route Maps, BFD Templates, etc.)
- **Push config** via YAML upload — checkbox-driven section toggles, batch
  size + bulk-mode controls, real-time progress logs
- **HA modal** — manage Failover/HA pairing
- **Template Builder modal** — build device-side YAML interactively
- **Terminal panel** — open SSH to the selected FTD without leaving the page

#### Chassis tab
- Chassis-level configuration push/pull (FXOS-managed devices)
- Chassis-specific template builder

#### VPN tab
- List, download, upload, and apply S2S VPN topologies via FMC's `ftds2svpns`
  API
- **VPN Template Builder** — point-and-click topology authoring (FTD↔FTD or
  FTD↔Extranet, IKE/IPSec, BFD on/off, scaling helpers for hub-and-spoke)
- **Endpoint replacement** — migrate topologies between FMCs by re-resolving
  device/interface UUIDs by **name**

### 3. Command Center (`/command-center`)

Bulk SSH operations on a saved fleet of FTDs and FMCs.

#### Device inventory
- Upload devices via CSV/TXT:
  ```csv
  type,name,ip_address,username,password,port
  FTD,WM-8,10.106.239.165,admin,Cisco@12,12056
  FTD,WM-9,10.106.239.165,admin,Cisco@12,12057
  FMC,FMC-1,10.106.239.200,admin,Cisco@123,22
  ```
- Port ranges (`12056-12060`) and lists (`22,2222`) supported
- Persisted per-user at `web_app/data/users/<username>/devices.json`
- Multi-select operations, table search/filter

#### Operation sections
| Section | What it does |
|---------|--------------|
| **HTTP Proxy** | Configure outbound HTTP proxy on selected devices |
| **Static Routes** | Add/replace IPv4/IPv6 static routes |
| **Download Upgrade** | Stage upgrade packages onto target FTDs |
| **Restore Backup** | Pull and restore device backups from a URL |
| **Copy Dev Cert** | Distribute development TLS certificates |

Each section streams its execution log via SSE; results land in `ExecLog`.

#### Embedded SSH terminal
Click any device row → opens an interactive xterm.js session with
FTD expert-mode and FMC shell support.

### 4. VPN Console (`/vpn-console`)

Operational console for StrongSwan/swanctl — primarily for engineering
testbeds where you SSH into a strongSwan endpoint.

#### Connect popup
Connect to a local strongSwan endpoint (SSH credentials, optional remote peer
for ping/traceroute tests).

#### Tunnel Summary
Live counts of IKE SAs, Child SAs, XFRM interfaces, error breakdown.
Auto-refreshes on a configurable interval.

#### VPN Peers
Two tabs (Local / Remote) showing per-tunnel state. Searchable, filterable by
status, copy-able JSON dumps for any IKE SA or Child SA.

#### Tunnel Traffic
File-based traffic generator. Configure local-network and remote-network
flow files (Snort3 traffic generators integration via
`@/Users/aleroyds/PycharmProjects/SIT/utils/traffic_generators.py`).

#### SwanCtl Template Builder
The flagship feature for IPsec testbed authoring:

- **Modes**: policy-based (TS-driven) and route-based (XFRM interface)
- **IP Address Blocks**: IPv4 + IPv6 with scaling (octet/hextet increments)
- **IKE / Connection Settings**: version, rekey/reauth, DPD, fragmentation,
  if_id_in/out
- **IKE / ESP Proposal Builders**: multi-select algorithms (AEAD, AKE, PRF,
  DH groups, ESN)
- **Authentication**: PSK, pubkey, EAP, certificate-based, with local/remote
  ID configuration
- **XFRM Interfaces** (route-based): count, starting if_id, address scaling,
  physdev binding
- **Routing**: pick one of
  - **Static** — destination/via/dev rows
  - **BGPv4 / BGPv6** — local AS, router-id, neighbors (with full per-neighbor
    command popup: timers, password, eBGP-multihop, BFD + profile selector,
    update-source, route-maps, prefix-lists, weight, allowas-in, ...), networks
  - **OSPFv2 / OSPFv3** — router-id, per-interface command popup (area, cost,
    hello/dead/retransmit/transmit, network type, passive, MTU-ignore, BFD +
    profile selector, MD5/null auth), networks
  - **EIGRPv4 / EIGRPv6** — AS, router-id, networks
  - **BFD (Profiles & Bindings)** — define FRR BFD profiles (TX/RX intervals,
    detect multiplier, passive-mode, echo-mode, echo-interval, minimum-ttl) and
    bind them to xfrm interfaces (with optional scaling); profiles are
    referenceable by name from OSPF and BGP popups
- **Secrets**: PSK / pubkey / private-key
- **Preview**: full swanctl.conf preview before apply
- **Presets**: save/load builder state per user

Backend handlers live in `@/Users/aleroyds/PycharmProjects/SIT/web_app/app.py`
under the `/api/strongswan/*` routes.

#### CSC Administration / CSC Container Config
Cluster Sync Channel administration sections for multi-node strongSwan setups.

#### Troubleshooting
Live charon log tailing, ipsec.conf / swanctl.conf viewers, packet capture
helpers.

### 5. Settings (`/settings`)
- **Theme**: Light / Dark / Blue / Green
- **FMC Connection Presets** management (rename, delete, view encrypted blob)

---

## Configuration

### Required environment (`.env` in project root)

```bash
# Session secret for the web app — generate with: openssl rand -hex 32
WEB_APP_SESSION_SECRET=replace-me

# Fernet key used to encrypt FMC connection presets at rest
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
CREDENTIAL_ENCRYPTION_KEY=replace-me

# Default credentials used by some standalone scripts (optional)
DEFAULT_HOST=10.106.239.165
DEFAULT_SSH_USERNAME=admin
DEFAULT_FTD_PASSWORD=
DEFAULT_FMC_PASSWORD=
```

### Web-app users

Create `web_app/data/users.json`:

```json
{
  "admin": "your-password",
  "cisco": "cisco"
}
```

This file is git-ignored.

---

## Persistent Data Files

The `web_app/data/` directory holds **per-server runtime state**. None of these
files are tracked by git — see `@/Users/aleroyds/PycharmProjects/SIT/.gitignore`:

| File / Path | Purpose |
|-------------|---------|
| `users.json` | Web-app user credentials |
| `users/<username>/devices.json` | Command-Center device inventory |
| `users/<username>/operation.log` | Per-user activity log |
| `users/<username>/presets/*.json` | Per-user saved presets |
| `ai_chats/*.json` | AI chat history |
| `dashboard_metrics.db` (+ `-wal`, `-shm`) | SQLite metrics DB |

> ⚠️ **Important for remote deployments:** Make sure your server's
> `web_app/data/dashboard_metrics.db` is **not** tracked by git. If a previous
> commit accidentally added it, untrack it once with:
>
> ```bash
> git rm --cached web_app/data/dashboard_metrics.db
> git commit -m "Untrack dashboard metrics DB"
> ```
>
> After that, `git pull` on the remote will leave the server's metrics intact.

---

## Project Structure

```
SIT/
├── frontend/                      # React 18 + TS + Tailwind SPA
│   └── src/
│       ├── App.tsx                # Routes
│       ├── pages/
│       │   ├── DashboardPage.tsx
│       │   ├── FmcConfigPage.tsx
│       │   ├── CommandCenterPage.tsx
│       │   ├── VpnDebuggerPage.tsx
│       │   ├── SettingsPage.tsx
│       │   ├── LoginPage.tsx
│       │   ├── command-center/    # subsections
│       │   ├── fmc-config/        # subsections
│       │   └── vpn-debugger/      # subsections (incl. SwanctlTemplateBuilder)
│       ├── components/
│       └── stores/                # Zustand stores
├── web_app/
│   ├── app.py                     # FastAPI app, all REST endpoints
│   ├── dashboard_metrics.py       # SQLite metrics layer
│   ├── ai_service.py / ai_tools.py
│   ├── ssh_terminal.py            # WS-backed SSH terminal
│   ├── data/                      # runtime data (git-ignored)
│   ├── certs/                     # TLS certs (git-ignored)
│   ├── spa/                       # built frontend (git-ignored)
│   └── templates/                 # legacy HTML (login, fallback)
├── utils/
│   ├── fmc_api.py                 # FMC REST client
│   ├── configure_http_proxy.py
│   ├── configure_static_routes.py
│   ├── clone_device_config.py
│   ├── copy_dev_crt.py
│   ├── download_upgrade_package.py
│   ├── restore_device_backup_runner.py
│   └── traffic_generators.py
├── requirements.txt
└── README.MD
```

---

## API Surface

The backend exposes hundreds of endpoints; below are the families. Inspect
`@/Users/aleroyds/PycharmProjects/SIT/web_app/app.py` for the authoritative
list.

| Family | Prefix | Notes |
|--------|--------|-------|
| Auth | `/api/login`, `/api/logout`, `/api/me` | Session-based |
| FMC config | `/api/fmc-config/*` | Connect, get, apply, presets, VPN, HA |
| Command Center | `/api/command-center/*` | Devices, ops (proxy/routes/etc.) |
| StrongSwan / VPN | `/api/strongswan/*` | Connect, swanctl apply/preview, overlay routing (BGP/OSPF/EIGRP/BFD), CSC, traffic gen |
| Dashboard | `/api/dashboard/*` | Key metrics, time series, activity |
| AI | `/api/ai/*` | Chat, tools (Bedrock backend) |
| Terminal | `/ws/terminal/*` | WebSocket SSH |

---

## Deployment Notes

### Generating an encryption key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Behind a reverse proxy

Vyper writes session cookies marked `SameSite=Lax`. If you front it with nginx
or a load balancer, ensure `X-Forwarded-Proto: https` is preserved.

### Production launch

```bash
cd web_app
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

> Heavy SSH operations spawn threads — keep `--workers` modest (1–4) and rely
> on async I/O for HTTP traffic.

### Kubernetes

Mount the runtime data directory as a `PersistentVolumeClaim` to keep
`dashboard_metrics.db` and per-user presets across pod restarts. Use a
`Secret` for `WEB_APP_SESSION_SECRET`, `CREDENTIAL_ENCRYPTION_KEY`, and
default device credentials.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vyper-credentials
type: Opaque
stringData:
  WEB_APP_SESSION_SECRET: "..."
  CREDENTIAL_ENCRYPTION_KEY: "..."
  USERS_JSON: '{"admin":"...","cisco":"cisco"}'
---
spec:
  containers:
    - name: vyper
      envFrom:
        - secretRef:
            name: vyper-credentials
      volumeMounts:
        - name: vyper-data
          mountPath: /app/web_app/data
  volumes:
    - name: vyper-data
      persistentVolumeClaim:
        claimName: vyper-data
```

---

## Troubleshooting

### "BFD config submitted but no bfd block found in running-config"
The vtysh apply succeeded but bfdd silently rejected the input. Check:
1. `vtysh -c 'show daemons'` lists `bfdd`
2. `cat /etc/frr/daemons` has `bfdd=yes`
3. `systemctl status frr` is active
4. Profile names contain only `[A-Za-z0-9_-]`

### Dashboard reset to zero after `git pull`
You're tracking `web_app/data/dashboard_metrics.db`. Run:
```bash
git rm --cached web_app/data/dashboard_metrics.db
git commit -m "Stop tracking metrics DB"
```
Then re-pull. The server's local DB stays in place.

### FMC connection fails
- FMC API access enabled (Administration → Configuration → REST API
  Preferences → "Enable REST API")
- User has API role permissions
- FMC IP reachable from the Vyper host

### VPN topology apply errors
- Devices referenced by the YAML must exist (by **name**) in the destination
  FMC
- Interface names must match the registered interface names
- Missing IKE policies / IPSec proposals / network objects are auto-created
  on apply

---

## License

Internal Cisco tooling. Not for redistribution.
