# Vyper — SIT (Security Integration Toolkit)

A web-based control plane for Cisco Firepower (FMC, FTD, FXOS), StrongSwan IPsec
endpoints, Cisco Secure Client containers, and traffic generators. Vyper
consolidates day‑2 operations (configuration, policy replication, troubleshooting,
traffic generation, VPN debugging) into a single React SPA backed by a FastAPI
service.

## Highlights

- **FMC Configuration**
  - **Device** — get/push device config via YAML for one or **multiple devices**
    at once, pre-push **validation & sanitization**, **multi-instance
    conversion**, selective config/object **delete**, HA pairing, template builder
  - **Chassis** — FXOS chassis config get/push
  - **VPN** — S2S topology get/push/delete, template builder, endpoint replacement
  - **Policy** — replicate **Access Control Policies** (with prefilter,
    decryption, identity, intrusion and file policies, and every referenced
    object) from a source FMC to a target FMC
- **Command Center** — bulk SSH operations on FTD/FMC fleets (proxy, static
  routes, upgrades, backup restore, dev-cert copy) plus a built-in terminal
- **VPN Console** — live tunnel introspection, SwanCtl template builder, overlay
  routing (FRR BGP/OSPF/EIGRP/BFD), Cisco Secure Client container deployment,
  traffic generation, troubleshooting
- **AI Assistant** — chat with FMC-schema and swanctl RAG, tool execution
  (AWS Bedrock or CIRCUIT providers)
- **Dashboard** — real-time system health, request rate, error rate,
  per-user activity, persisted in SQLite
- **Authentication** — local users, SAML SSO (Duo), or Things SSO; optional
  CA-signed TLS certificates from Things
- **Settings** — theme + connection presets

---

## Quick Start

### Prerequisites
- Python 3.11 (3.8+ works for most features)
- Node 18+ and npm (for building the React SPA)
- `openssl` (used to generate a local self-signed certificate)
- Network reachability to your FMCs / FTDs / strongSwan endpoints

### Setup

```bash
git clone <repo-url>
cd SIT

# 1. Python deps
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Environment + users (see "Configuration" below)
#    - create .env in the project root
#    - create web_app/data/users.json

# 3. Build the frontend and start the server
cd web_app
./run.sh
```

Open **https://localhost:8000** and log in with a user from
`web_app/data/users.json`.

`run.sh` installs Python deps, builds the SPA into `web_app/spa/`, and serves
the API + SPA over **HTTPS on a single port (8000)**:

| Command | Effect |
|---------|--------|
| `./run.sh` | Build frontend, start server |
| `./run.sh --no-build` | Skip the frontend build (reuse `web_app/spa/`) |
| `./run.sh --dev` | Backend only — use with the Vite dev server (`cd frontend && npm run dev`) |
| `SIT_PORT=9443 ./run.sh` | Use a different port |

TLS certificates are read from `web_app/certs/{cert,key}.pem`:
- If Things is configured (`THINGS_API_TOKEN` + `THINGS_TOOL_SLUG`), a
  CA-signed certificate is requested at startup.
- Otherwise, if no certificate exists, a **self-signed** one for `localhost` is
  generated automatically (expect a browser warning).

---

## Pages

The SPA routes are defined in `frontend/src/App.tsx`:
`/dashboard`, `/fmc-configuration`, `/command-center`, `/vpn-console`,
`/settings`, `/login`.

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

Implementation: `web_app/dashboard_metrics.py`,
`frontend/src/pages/DashboardPage.tsx`.

### 2. FMC Configuration (`/fmc-configuration`)

Four tabs: **Device Configuration**, **Chassis Configuration**, **VPN**, **Policy**.

#### Connection panel
- Connect to an FMC instance (IP/hostname, username, password)
- Multi-domain support — pick the target domain after connect
- Save reusable **connection presets** (passwords are Fernet-encrypted at rest)
- Registered devices are listed with multi-select

#### Device Configuration tab
- **Get config** — fetch interfaces (Physical, Loopback, Subinterface,
  EtherChannel, VTI, BridgeGroup, InlineSet), routing (BGP, OSPF, EIGRP, Static,
  PBR, ECMP, VRF), and objects (Security Zones, Network Objects, Port Objects,
  Route Maps, BFD Templates, etc.)
- **Multi-device get/push** — select several devices and fetch or apply config
  to all of them in one operation
- **Push config** via YAML upload — checkbox-driven section toggles, batch
  size + bulk-mode controls, real-time progress logs. Individual VRF push
  fallback when a bulk VRF push fails.
- **Pre-push validation & sanitization** (`web_app/pre_push_validation/`) —
  deterministic checks before anything is sent to FMC:
  - target device model / version resolution against bundled model schemas
    (`schemas/model_schemas/`)
  - FMC OAS schema validation for the target FMC version
    (`schemas/oas_schemas/`)
  - interface conflict detection against the target device's interfaces
  - a **Validation Review** panel to accept fixes and map interfaces, then
    produce a sanitized config
- **Multi-instance conversion** — convert a single-device config into a
  multi-instance (one instance per VRF) device config plus an auto-derived
  chassis config
- **Delete** — remove selected configuration types or objects from a device,
  with streamed progress
- **HA modal** — create Failover/HA pairs
- **Template Builder modal** — build device-side YAML interactively (with
  resource-profile and lookup helpers)
- **Terminal panel** — open SSH to the selected FTD without leaving the page
- **Sample YAML / full schema** download

#### Chassis Configuration tab
- Chassis-level configuration get/upload/apply (FXOS-managed devices)
- Chassis-specific template builder

#### VPN tab
- List, download, upload, apply and delete S2S VPN topologies via FMC's
  `ftds2svpns` API
- **VPN Template Builder** — point-and-click topology authoring (FTD↔FTD or
  FTD↔Extranet, IKE/IPSec, BFD on/off, scaling helpers for hub-and-spoke)
- **Endpoint replacement** — migrate topologies between FMCs by re-resolving
  device/interface UUIDs by **name**

See `web_app/README.md` for the detailed VPN API workflow.

#### Policy tab — ACP replication

Replicates Access Control Policies from a **source** FMC to a **target** FMC
(possibly a different version). Code: `web_app/policy_configuration/`,
UI: `frontend/src/pages/policy-config/`.

**Workflow**
1. **Connect** a source FMC (or load a policy YAML) and the target FMC; the
   panel shows host, version, build and model for both.
2. **List ACPs** on the source and **fetch** the ones you want. Fetching pulls
   the ACP, its rules, and recursively every dependency:
   - assigned policies: Prefilter, Decryption (SSL), Identity, Security
     Intelligence
   - rule-referenced Intrusion and File policies
   - objects: networks/hosts/ranges/FQDNs and groups, ports, ICMP, zones,
     interface groups, **tunnel tags**, URLs, applications, VLAN tags, time
     ranges, SGTs, geolocation, realms, variable sets, …
3. **Save / load YAML** — download a self-contained policy YAML (per ACP or
   combined), upload one, or load YAMLs from the shared HTTPS server.
4. **Map** assigned policies (create new vs reuse existing on target), Internal
   CA / Internal Certificate mappings for decryption rules, and realms.
5. **Preview** — validates against the target FMC's OAS schema, lists objects to
   create / reuse / unresolved, overrides, name conflicts and circular
   references. Unsupported fields can be **stripped** in one click.
6. **Push** — creates objects in dependency order, then dependent policies, then
   the ACP and its rules, with a detailed log and a push summary.

**How references are resolved**
- Objects are matched on the target by type + name (and by value for
  hosts/networks/ports); compatible matches are reused, others are created.
  System objects (Applications, URL categories, geolocation) keep their global
  IDs.
- Every source UUID in rule and policy bodies is remapped to the target ID;
  references with no target equivalent are **pruned** and logged.
- Generic `NetworkObject` group members are resolved to their concrete
  Host/Network/Range/FQDN type.
- Updating an existing ACP reuses the target's default-action ID.

**Resilience**
- Bulk object and rule creation is used by default. If a bulk batch fails, it
  is **split recursively** so only the offending item(s) fail; optional
  per-rule fallback retries the failed batch one rule at a time.
- Results are summarized per category (objects created/reused/unresolved,
  pruned references, rules pushed/failed) and environmental causes (e.g. ISE
  disabled on target) are called out.

**FMC REST API limitations** (verified against `schemas/oas_schemas/`):
| Object | Limitation | Vyper behaviour |
|--------|------------|-----------------|
| Variable Sets | GET only | Reused by name; pruned from rules if missing on target |
| Identity Policies | POST only on FMC ≥ 10.0 | Reused by name; create skipped on older targets |
| ISE Security Group Tags | Need ISE enabled on target | Pruned and reported as environmental |

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
| **HTTP Proxy** | Configure outbound HTTP proxy on selected devices (with presets) |
| **Static Routes** | Add/replace IPv4/IPv6 static routes (with presets) |
| **Download Upgrade** | Stage upgrade packages onto target FTDs |
| **Restore Backup** | Pull and restore device backups from a URL |
| **Copy Dev Cert** | Distribute development TLS certificates |

Each section streams its execution log; results land in `ExecLog`.

#### Embedded SSH terminal
Click any device row → opens an interactive xterm.js session with
FTD expert-mode and FMC shell support.

### 4. VPN Console (`/vpn-console`)

Operational console for StrongSwan/swanctl testbeds reached over SSH.

#### Connect popup
Connect to a local strongSwan endpoint (SSH credentials, optional remote peer
for ping/traceroute tests).

#### Tunnel Summary
Live counts of IKE SAs, Child SAs, XFRM interfaces, error breakdown.
Auto-refreshes on a configurable interval; tunnel-level detail view.

#### VPN Peers
Two tabs (Local / Remote) showing per-tunnel state. Searchable, filterable by
status, copy-able JSON dumps for any IKE SA or Child SA.

#### Tunnel Traffic
Traffic generation across tunnels (iperf3 and other generators), with tool
install checks, interface discovery and `tc` traffic shaping.

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

#### Routing Administration
Manage the FRR service and overlay routing (BGP / OSPF / EIGRP / BFD) on the
endpoint.

#### Endpoint administration
- **Netplan** — view/edit network configuration
- **Interfaces**, **certificates**, **strongSwan service** control
  (restart / refresh), **monitoring**

#### Cisco Secure Client (CSC) Administration / Container Config
Deploy and manage Cisco Secure Client instances in Docker containers on the
endpoint:
- Docker install check / install, image build with live build logs
- Bulk deploy of N clients against a headend (SSL or IPsec, DTLS, PQC,
  per-client user/password increments, IPv4 address scaling)
- Per-container start/stop/logs, container netplan and `tc` settings,
  config-file editing, deploy presets

#### Troubleshooting
swanctl / syslog log viewers, config file viewers, report viewer, packet
capture helpers.

### 5. AI Assistant

Chat assistant available inside the app (`web_app/ai_service.py`,
`web_app/ai_tools.py`):
- Providers: **AWS Bedrock** and **CIRCUIT API** (selectable per chat)
- Retrieval over the FMC OAS schema (`web_app/fmc_schema_rag.py`) and swanctl /
  iperf3 / tc documentation (`utils/*_rag*`, `utils/*.md`)
- Tool execution (e.g. sync a generated chassis config into the UI)
- Persistent chat sessions per user (`web_app/data/ai_chats/`)

### 6. Settings (`/settings`)
- **Theme**: Light / Dark / Blue / Green
- **FMC Connection Presets** management (rename, delete, view encrypted blob)
- **Things certificate** status and refresh (admin)

---

## Configuration

### Environment (`.env` in project root)

```bash
# Session secret for the web app — generate with: openssl rand -hex 32
WEB_APP_SESSION_SECRET=replace-me

# Fernet key used to encrypt FMC connection presets at rest
# python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
CREDENTIAL_ENCRYPTION_KEY=replace-me

# Local users as JSON (alternative to web_app/data/users.json)
# USERS_JSON='{"admin":"...","cisco":"cisco"}'

# Default credentials used by some standalone scripts (optional)
DEFAULT_HOST=10.106.239.165
DEFAULT_SSH_USERNAME=admin
DEFAULT_FTD_PASSWORD=
DEFAULT_FMC_PASSWORD=
```

Optional integrations:

| Feature | Variables |
|---------|-----------|
| SAML SSO (Duo) | `SAML_IDP_ENTITY_ID`, `SAML_IDP_SSO_URL`, `SAML_IDP_CERT` |
| Things SSO + TLS certs | `THINGS_BASE_URL`, `THINGS_TOOL_SLUG`, `THINGS_API_TOKEN`, `THINGS_UNSEAL_KEY`, `THINGS_CERT_CN`, `THINGS_ADMIN_USERNAME` |
| AI — AWS Bedrock | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_BEDROCK_REGION`, `AWS_BEDROCK_DEFAULT_MODEL` |
| AI — CIRCUIT | `BRIDGE_API_CLIENT_ID`, `BRIDGE_API_CLIENT_SECRET`, `BRIDGE_API_APP_KEY`, `CIRCUIT_TOKEN_URL`, `CIRCUIT_CHAT_BASE_URL`, `CIRCUIT_API_VERSION`, `CIRCUIT_MODEL` |

### Web-app users

Create `web_app/data/users.json` (plain `username: password` map):

```json
{
  "admin": "your-password",
  "cisco": "cisco"
}
```

This file is git-ignored and is read **at startup** — restart the server after
editing it. If neither `users.json` nor `USERS_JSON` is present, local login is
disabled (startup logs `No users configured`).

---

## Persistent Data Files

The `web_app/data/` directory holds **per-server runtime state**. None of these
files are tracked by git:

| File / Path | Purpose |
|-------------|---------|
| `users.json` | Web-app user credentials |
| `users/<username>/devices.json` | Command-Center device inventory |
| `users/<username>/operation.log` | Per-user activity log |
| `users/<username>/*presets*.json` | Per-user saved presets (FMC presets encrypted) |
| `ai_chats/*.json` | AI chat history |
| `dashboard_metrics.db` (+ `-wal`, `-shm`) | SQLite metrics DB |

`web_app/certs/` (TLS certificates) and `web_app/spa/` (built frontend) are also
git-ignored.

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
├── frontend/                        # React + TS + Tailwind SPA (Vite)
│   └── src/
│       ├── App.tsx                  # Routes
│       ├── pages/
│       │   ├── DashboardPage.tsx
│       │   ├── FmcConfigPage.tsx
│       │   ├── CommandCenterPage.tsx
│       │   ├── VpnDebuggerPage.tsx
│       │   ├── SettingsPage.tsx
│       │   ├── LoginPage.tsx
│       │   ├── command-center/      # Command Center sections
│       │   ├── fmc-config/          # Device/Chassis/VPN tabs, validation, multi-instance
│       │   ├── policy-config/       # Policy (ACP replication) tab
│       │   └── vpn-debugger/        # VPN Console sections (SwanCtl builder, CSC, routing)
│       ├── components/
│       └── stores/                  # Zustand stores
├── web_app/
│   ├── app.py                       # FastAPI app, REST endpoints, SSO, SPA serving
│   ├── run.sh                       # Build + HTTPS launcher
│   ├── policy_configuration/        # ACP replication (mounted at /api/policy-config)
│   │   ├── api/router.py
│   │   ├── services/                # source/target clients, ACP fetch, push, dependent policies
│   │   ├── dependency_resolution/   # object discovery, matching, creation order, ID remap
│   │   ├── validation/              # OAS-based policy validation / field stripping
│   │   ├── yaml/                    # policy YAML serializer
│   │   ├── models/                  # data model
│   │   └── tests/                   # pytest suite
│   ├── pre_push_validation/         # device config validation + sanitizer
│   ├── dashboard_metrics.py         # SQLite metrics layer
│   ├── ai_service.py / ai_tools.py / fmc_schema_rag.py
│   ├── ssh_terminal.py              # WS-backed SSH terminal
│   ├── data/                        # runtime data (git-ignored)
│   ├── certs/                       # TLS certs (git-ignored)
│   ├── spa/                         # built frontend (git-ignored)
│   └── templates/                   # legacy HTML (login, fallback)
├── utils/
│   ├── fmc_api.py                   # FMC REST client
│   ├── credential_manager.py        # Fernet encryption for presets
│   ├── dependency_resolver.py
│   └── *.md / *_rag.jsonl           # RAG corpora (OAS, swanctl, iperf3, tc)
├── schemas/
│   ├── oas_schemas/                 # FMC OpenAPI specs (7.1 – 10.5)
│   └── model_schemas/               # per-platform device model schemas
├── clone_device_config.py, configure_http_proxy.py, configure_static_routes.py,
├── copy_dev_crt.py, download_upgrade_package.py, restore_device_backup*.py,
├── scale_bgp.py, scale_vrf.py, traffic_generators.py   # standalone / backend scripts
├── requirements.txt
├── AGENTS.md                        # dev notes (run/test commands)
└── README.MD
```

---

## API Surface

Inspect `web_app/app.py` and `web_app/policy_configuration/api/router.py` for
the authoritative list.

| Family | Prefix | Notes |
|--------|--------|-------|
| Auth | `/api/auth/login`, `/api/auth/logout`, `/api/auth/check` | Session-based |
| SSO | `/sso/login`, `/sso/acs`, `/sso/metadata`, `/sso/things/*` | SAML (Duo) and Things |
| FMC config | `/api/fmc-config/*` | Connect, get/apply/delete, validate/sanitize, multi-instance convert, chassis, VPN, HA, presets, schema |
| Policy replication | `/api/policy-config/*` | Source connect, ACP list/fetch, YAML upload/download/server YAMLs, target policies, preview, sanitize, push |
| Command Center | `/api/command-center/*` | Devices, ops (proxy/routes/etc.), presets |
| StrongSwan / VPN | `/api/strongswan/*` | Connect, swanctl apply/preview, overlay routing, FRR, netplan, certs, tc, monitoring, tunnel traffic |
| Cisco Secure Client | `/api/csc/*` | Docker install, image build, containers, netplan, tc |
| Traffic generators | `/api/traffic-generators/*` | Connect, tool install, generate traffic |
| Dashboard | `/api/dashboard/*` | Key metrics, time series, activity |
| AI | `/api/ai/*` | Chat, sessions, providers, RAG search, tool execution |
| Admin | `/api/admin/things-cert/*` | Things certificate status / refresh |
| Terminal | `/api/terminal` (WebSocket) | SSH terminal |
| Health | `/healthz` | Liveness probe |

---

## Testing

```bash
cd web_app
../venv/bin/pip install pytest      # once
../venv/bin/python -m pytest policy_configuration/tests -q
```

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

Use `run.sh` (HTTPS on port 8000), or run uvicorn directly with your own
certificates:

```bash
cd web_app
python -m uvicorn app:app --host 0.0.0.0 --port 8000 \
  --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem
```

> Per-user state (sessions, progress, resolution caches) is kept in-process —
> run a **single worker** unless you add shared session storage.

### Kubernetes

Mount the runtime data directory as a `PersistentVolumeClaim` to keep
`dashboard_metrics.db` and per-user presets across pod restarts. Use a
`Secret` for `WEB_APP_SESSION_SECRET`, `CREDENTIAL_ENCRYPTION_KEY`, users and
integration credentials.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vyper-credentials
type: Opaque
stringData:
  WEB_APP_SESSION_SECRET: "..."
  CREDENTIAL_ENCRYPTION_KEY: "..."
  USERS_JSON: '{"admin":"..."}'
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

### Server fails with `FileNotFoundError` in `load_cert_chain`
No TLS certificate in `web_app/certs/`. Current `run.sh` generates a self-signed
one automatically; make sure `openssl` is installed.

### Login returns 401
`web_app/data/users.json` is missing or was created after the server started.
Create it and restart the server.

### Policy push: rules or objects fail
Check the push log:
- `[ref] pruned unresolved …` — the reference has no equivalent on the target
  and was removed from the rule (see the API limitations table above).
- `[bulk] … splitting` — a bulk batch was rejected; the failing rule/object is
  reported individually with FMC's error.
- `environmental: …` in the summary — a target-side setting (e.g. ISE disabled)
  prevented resolution.
- Restart the server after code changes: resolution results are cached per
  session.

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
- User has API role permissions (a `403 The user is not authorized` on create
  usually means missing role or an unsupported endpoint on that FMC version)
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
