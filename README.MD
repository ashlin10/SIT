# Vyper - FMC Configuration Web Interface

A comprehensive web-based tool for managing Cisco Firepower Management Center (FMC) configurations. Vyper provides a modern UI for connecting to FMC, managing device configurations, VPN topologies, and executing commands on FTD/FMC devices.

## Features

- **FMC Configuration Management**
  - Connect to FMC with multi-domain support
  - Get device configurations (interfaces, routing, objects)
  - Push configurations via YAML upload
  - VPN topology management (get, push, download)
  - VPN endpoint replacement
  
- **Command Center (Terminal)**
  - SSH terminal access to FTD and FMC devices
  - Bulk device management via CSV upload
  - HTTP proxy configuration
  - Static route configuration
  - Device backup restoration

- **User Management**
  - Session-based authentication
  - Per-user configuration presets
  - Activity logging

---

## Installation

### Prerequisites
- Python 3.8+
- Access to a Cisco FMC instance

### Setup

1. Install dependencies:
   ```bash
   cd web_app
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   python app.py
   ```

3. Access the UI at:
   ```
   http://localhost:5000
   ```

Default login: `cisco` / `cisco`

---

## Architecture

| Component | Technology |
|-----------|------------|
| Frontend | HTML, TailwindCSS, JavaScript |
| Backend | FastAPI (Python) |
| API Integration | FMC REST API via `utils/fmc_api.py` |
| SSH | Paramiko + paramiko-expect |

### Project Structure
```
web_app/
├── app.py                 # Main FastAPI application
├── templates/
│   ├── base.html          # Base template with navigation
│   ├── fmc_configuration.html  # FMC Configuration page
│   ├── command_center.html     # Command Center/Terminal
│   ├── login.html         # Login page
│   └── settings.html      # User settings
├── static/
│   ├── css/               # Stylesheets
│   └── js/                # JavaScript files
├── data/
│   └── users/             # Per-user persisted data
└── requirements.txt
```

---

## Main Sections

### 1. FMC Configuration (`/fmc-configuration`)

The primary interface for managing FMC device configurations.

#### FMC Connection

1. Enter FMC details:
   - **FMC IP**: IP address or hostname (https:// prefix added automatically)
   - **Username**: FMC admin username
   - **Password**: FMC admin password
   
2. Click **Connect** to authenticate

3. On successful connection:
   - Available domains are listed in a dropdown
   - Registered devices (FTDs) for the selected domain are displayed
   - Connection presets can be saved for quick access

#### Get Configuration (from FMC)

Fetch existing configuration from a device registered in FMC:

1. Connect to FMC
2. Select a **Device** from the dropdown
3. Click **Get Config** to retrieve:
   - **Interfaces**: Physical, Loopback, Subinterfaces, EtherChannel, VTI, Bridge Groups, Inline Sets
   - **Routing**: BGP, OSPF, EIGRP, Static Routes, PBR, ECMP Zones, VRFs
   - **Objects**: Security Zones, Network Objects, Port Objects, Route Maps, etc.

4. Configuration is displayed in the UI with item counts
5. Click **Download YAML** to export the configuration

#### Push Configuration (to FMC)

Apply configuration from a YAML file to a device:

1. Connect to FMC
2. Select target **Device**
3. Click **Upload YAML** and select your configuration file
4. The UI displays parsed configuration counts by category
5. Use checkboxes to select which sections to apply:
   - **Objects** (Level 1 & 2): Network objects, Security Zones, BFD Templates, etc.
   - **Interfaces**: Loopback, Physical, EtherChannel, Subinterfaces, VTI
   - **Routing**: BGP, OSPF, EIGRP, Static Routes, etc.

6. Configure options:
   - **Batch Size**: Number of items per bulk API call (default: 50)
   - **Bulk Mode**: Enable/disable bulk API operations

7. Click **Apply Config** to push configuration
8. Real-time logs show progress and any errors

#### YAML Configuration Format

Download sample schemas via:
- **Download Sample YAML** - Minimal schema with all interface types
- **Download Full Schema** - Complete FMC components schema (JSON)

Example YAML structure:
```yaml
loopback_interfaces:
  - enabled: true
    ifname: loopback-5
    loopbackId: 5
    ipv4:
      static:
        address: 169.254.100.1
        netmask: 255.255.255.252

physical_interfaces:
  - name: Ethernet1/1
    ifname: inside
    enabled: true
    mode: NONE
    securityZone:
      name: INSIDE
      type: SecurityZone

objects:
  interface:
    security_zones:
      - name: INSIDE
        type: SecurityZone
        interfaceMode: ROUTED
```

---

### 2. VPN Topology Management

#### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/fmc-config/vpn/list` | POST | Fetch all VPN topologies from FMC |
| `/api/fmc-config/vpn/download` | POST | Download selected topologies as YAML |
| `/api/fmc-config/vpn/upload` | POST | Parse uploaded VPN YAML file |
| `/api/fmc-config/vpn/apply` | POST | Apply VPN topologies to FMC |

#### FMC API Endpoints Used

The following FMC REST API endpoints are called during VPN operations:

| FMC Endpoint | Operation | Description |
|--------------|-----------|-------------|
| `GET /api/fmc_config/v1/domain/{domain}/policy/s2svpnsummaries` | List | Fetch VPN topology summaries |
| `GET /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns` | List | Fetch full FTDS2SVpn objects |
| `GET /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns/{id}/endpoints` | List | Fetch endpoints for a topology |
| `GET /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns/{id}/ikesettings` | List | Fetch IKE settings |
| `GET /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns/{id}/ipsecsettings` | List | Fetch IPSec settings |
| `GET /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns/{id}/advancedsettings` | List | Fetch advanced settings |
| `GET /api/fmc_config/v1/domain/{domain}/object/ikev2policies/{id}` | Get | Fetch IKEv2 policy details |
| `GET /api/fmc_config/v1/domain/{domain}/object/ikev2ipsecproposals/{id}` | Get | Fetch IPSec proposal details |
| `POST /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns` | Apply | Create VPN topology |
| `POST /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns/{id}/endpoints` | Apply | Create VPN endpoints |
| `PUT /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns/{id}/ikesettings/{sid}` | Apply | Update IKE settings |
| `PUT /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns/{id}/ipsecsettings/{sid}` | Apply | Update IPSec settings |
| `PUT /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns/{id}/advancedsettings/{sid}` | Apply | Update advanced settings |
| `POST /api/fmc_config/v1/domain/{domain}/object/ikev2policies` | Apply | Create IKEv2 policy |
| `POST /api/fmc_config/v1/domain/{domain}/object/ikev2ipsecproposals` | Apply | Create IPSec proposal |
| `POST /api/fmc_config/v1/domain/{domain}/object/networks` | Apply | Create network object |
| `POST /api/fmc_config/v1/domain/{domain}/object/extendedaccesslists` | Apply | Create access list |

---

#### Get VPN Topologies Workflow

**UI Steps:**
1. Connect to FMC
2. Click **Get VPN Topologies**
3. View topologies in table with name, type, route-based flag, and peers
4. Select topologies and click **Download Selected** to export as YAML

**Backend Workflow (`/api/fmc-config/vpn/list`):**

```
1. Authenticate to FMC
   └─> POST /api/fmc_platform/v1/auth/generatetoken
   
2. Fetch VPN topology summaries
   └─> GET /api/fmc_config/v1/domain/{domain}/policy/s2svpnsummaries?expanded=true&limit=1000
   
3. Fetch full FTDS2SVpn objects (for raw payload)
   └─> GET /api/fmc_config/v1/domain/{domain}/policy/ftds2svpns?expanded=true&limit=1000
   
4. For each topology, expand related data:
   │
   ├─> GET .../ftds2svpns/{vpn_id}/endpoints?expanded=true
   │   └─ Retrieves all endpoints (devices, interfaces, protected networks)
   │
   ├─> GET .../ftds2svpns/{vpn_id}/ikesettings?expanded=true
   │   └─ For each IKE policy reference:
   │      └─> GET .../object/ikev2policies/{policy_id}
   │          └─ Expands full policy (encryption, integrity, PRF, DH groups)
   │
   ├─> GET .../ftds2svpns/{vpn_id}/ipsecsettings?expanded=true
   │   └─ For each IPSec proposal reference:
   │      └─> GET .../object/ikev2ipsecproposals/{proposal_id}
   │          └─ Expands full proposal (encryption, integrity algorithms)
   │
   └─> GET .../ftds2svpns/{vpn_id}/advancedsettings?expanded=true
       └─ Retrieves NAT, path monitoring, tunnel settings
   
5. For endpoints with protectedNetworks:
   ├─> Collect referenced network object names
   ├─> GET .../object/networks?expanded=true (fetch all)
   ├─> Collect referenced access list names
   └─> GET .../object/extendedaccesslists?expanded=true (fetch all)
   
6. Return combined topology data with:
   - summary: Topology metadata
   - endpoints: Full endpoint list
   - ikeSettings: Expanded IKE configuration
   - ipsecSettings: Expanded IPSec configuration
   - advancedSettings: NAT and tunnel settings
   - objects: Referenced network/access list objects
```

---

#### Push VPN Topologies Workflow

**UI Steps:**
1. Connect to FMC
2. Click **Upload VPN YAML** and select configuration file
3. Review parsed topologies in table
4. Click **Apply VPN Topologies**
5. Monitor real-time logs for progress

**Backend Workflow (`/api/fmc-config/vpn/apply`):**

```
1. Authenticate to FMC
   └─> POST /api/fmc_platform/v1/auth/generatetoken

2. Fetch existing resources for reference resolution:
   ├─> GET .../object/ikev2policies (cache IKE policies by name)
   └─> GET .../object/ikev2ipsecproposals (cache IPSec proposals by name)

3. For each topology in YAML:
   │
   ├─ Phase 1: Resolve IKE/IPSec Policy References
   │  ├─ For each ikeSettings.ikeV2Settings.policies[]:
   │  │  ├─ If policy.name exists in FMC → set policy.id
   │  │  └─ If not found → POST .../object/ikev2policies (create it)
   │  │
   │  └─ For each ipsecSettings.ikeV2IpsecProposal[]:
   │     ├─ If proposal.name exists in FMC → set proposal.id
   │     └─ If not found → POST .../object/ikev2ipsecproposals (create it)
   │
   ├─ Phase 2: Resolve Protected Network Objects
   │  ├─ Fetch existing: GET .../object/networks, .../object/extendedaccesslists
   │  └─ For each endpoint.protectedNetworks.networks/accessLists[]:
   │     ├─ If object.name exists in FMC → set object.id
   │     └─ If not found but defined in YAML objects section → create it
   │
   ├─ Phase 3: Create or Find VPN Topology
   │  ├─ GET .../policy/ftds2svpns (check if topology.name exists)
   │  ├─ If exists → reuse vpn_id, skip creation
   │  └─ If not → POST .../policy/ftds2svpns (create topology)
   │     └─ Response contains vpn_id
   │
   ├─ Phase 4: Resolve Device and Interface UUIDs
   │  │  (Critical for cross-FMC migration - UUIDs differ between FMCs)
   │  │
   │  └─ For each endpoint:
   │     ├─ Resolve device.name → device.id
   │     │  └─> GET .../devices/devicerecords?filter=name:{name}
   │     │
   │     ├─ Load device interfaces:
   │     │  └─> GET .../devices/devicerecords/{device_id}/physicalinterfaces
   │     │  └─> GET .../devices/devicerecords/{device_id}/subinterfaces
   │     │  └─> GET .../devices/devicerecords/{device_id}/vtinterfaces
   │     │
   │     ├─ Resolve interface.name → interface.id (match by name/ifname)
   │     └─ Resolve tunnelSourceInterface.name → tunnelSourceInterface.id
   │
   ├─ Phase 5: Resolve Settings UUIDs
   │  │  (Settings are auto-created with topology; we need their IDs for PUT)
   │  │
   │  ├─> GET .../ftds2svpns/{vpn_id}/ikesettings → get ikeSettings.id
   │  ├─> GET .../ftds2svpns/{vpn_id}/ipsecsettings → get ipsecSettings.id
   │  └─> GET .../ftds2svpns/{vpn_id}/advancedsettings → get advancedSettings.id
   │
   ├─ Phase 6: Apply Settings (if provided in YAML)
   │  ├─> PUT .../ftds2svpns/{vpn_id}/ikesettings/{ike_id}
   │  ├─> PUT .../ftds2svpns/{vpn_id}/ipsecsettings/{ipsec_id}
   │  └─> PUT .../ftds2svpns/{vpn_id}/advancedsettings/{adv_id}
   │
   └─ Phase 7: Create Endpoints
      ├─ GET .../ftds2svpns/{vpn_id}/endpoints (check existing)
      ├─ Filter out endpoints that already exist (by name)
      └─ POST .../ftds2svpns/{vpn_id}/endpoints (bulk create)
         └─ Payload includes resolved device.id, interface.id, protectedNetworks

4. Return summary:
   - Topologies created/updated
   - Endpoints created
   - Errors (with detailed FMC error descriptions)
```

---

#### Replace VPN Endpoints Workflow

**Use Case:** Migrate VPN topologies from one FMC to another, or replace endpoint devices within the same FMC.

**Workflow:**

```
Source FMC                           Destination FMC
───────────                          ────────────────
1. Get VPN Topologies
   └─> Downloads full topology
       with all settings and
       endpoints expanded
       
2. Download as YAML
   └─> Exports to file with:
       - Topology summary
       - Endpoints (device names)     ──┐
       - IKE/IPSec settings             │
       - Protected networks             │
                                        │
3. Edit YAML                            │
   └─> Change device names:             │
       device:                          │
         name: OLD-FTD-1  ────────────> name: NEW-FTD-1
         type: Device                   type: Device
       interface:
         name: outside    (keep same)
         type: PhysicalInterface
                                        │
4. Upload to Destination FMC  <─────────┘
   └─> /api/fmc-config/vpn/upload
       (parses YAML, shows preview)
       
5. Apply VPN Topologies
   └─> /api/fmc-config/vpn/apply
       │
       ├─ Resolves NEW-FTD-1 → new device UUID
       │  (looks up by NAME in destination FMC)
       │
       ├─ Resolves interface "outside" → new interface UUID
       │  (looks up by NAME on the resolved device)
       │
       ├─ Creates missing IKE policies (by name)
       ├─ Creates missing IPSec proposals (by name)
       ├─ Creates missing network objects (by name)
       │
       └─ Creates topology with new UUIDs
```

**Key Points:**
- **UUIDs are NOT portable** between FMCs - they are resolved by **name**
- Device names must match registered devices in destination FMC
- Interface names (e.g., "outside", "GigabitEthernet0/0") must match
- IKE policies and IPSec proposals are created automatically if missing
- Protected network objects are created if defined in YAML `objects` section

---

#### VPN YAML Format

**Download format** (from Get VPN Topologies):
```yaml
vpn_topologies:
  - name: My-VPN-Topology
    routeBased: true
    topologyType: POINT_TO_POINT      # POINT_TO_POINT | HUB_AND_SPOKE | FULL_MESH
    ikeV1Enabled: false
    ikeV2Enabled: true
    endpoints:
      - name: endpoint-1
        device:
          name: FTD-Device-1          # Device name (UUID resolved at apply time)
          type: Device
        interface:
          name: outside               # Interface name (UUID resolved at apply time)
          type: PhysicalInterface
        role: HUB                     # HUB | SPOKE (for Hub-and-Spoke)
        peerType: PEER                # PEER | EXTRANET
        protectedNetworks:
          networks:
            - name: inside-network
              type: Network
          accessLists:
            - name: vpn-acl
              type: ExtendedAccessList
    ikeSettings:
      - id: <IKE_SETTINGS_UUID>       # Placeholder, resolved at apply
        ikeV2Settings:
          policies:
            - name: AES256-SHA512     # Policy name (created if missing)
              type: IKEv2Policy
              encryptionAlgorithms: [AES-256]
              integrityAlgorithms: [SHA-512]
              prfIntegrityAlgorithms: [SHA-512]
              diffieHellmanGroups: [21]
              lifetimeInSeconds: 86400
    ipsecSettings:
      - id: <IPSEC_SETTINGS_UUID>     # Placeholder, resolved at apply
        ikeV2IpsecProposal:
          - name: AES256-GCM          # Proposal name (created if missing)
            type: IKEv2IPsecProposal
            encryptionAlgorithms: [AES-GCM-256]
            integrityAlgorithms: [NULL]
    advancedSettings:
      - id: <ADVANCED_SETTINGS_UUID>  # Placeholder, resolved at apply
        # NAT settings, path monitoring, etc.
    objects:                          # Optional: object definitions for auto-creation
      networks:
        - name: inside-network
          type: Network
          value: 10.0.0.0/24
      accesslists:
        - name: vpn-acl
          type: ExtendedAccessList
          entries: [...]
```

**Placeholder UUIDs:** When downloading from FMC, certain IDs are replaced with placeholders like `<IKE_SETTINGS_UUID>`. These are automatically resolved when applying to a destination FMC.

---

### 3. Command Center (`/command-center`)

SSH-based device management for FTD and FMC devices.

#### Device Management

1. **Upload Devices**: Upload CSV/TXT file with device list
   ```csv
   type,name,ip_address,username,password,port
   FTD,WM-8,10.106.239.165,admin,Cisco@12,12056
   FTD,WM-9,10.106.239.165,admin,Cisco@12,12057
   FMC,FMC-1,10.106.239.200,admin,Cisco@123,22
   ```

2. **Port Ranges**: Supports port ranges (`12056-12060`) and comma-separated ports (`22,2222`)

3. Devices are persisted per-user in `data/users/<username>/devices.json`

#### Available Operations

| Operation | Description |
|-----------|-------------|
| **HTTP Proxy** | Configure HTTP proxy settings on selected devices |
| **Static Routes** | Add static routes (IPv4/IPv6) to selected devices |
| **Download Upgrade** | Download upgrade packages to devices |
| **Restore Backup** | Restore device backups from URL |
| **Copy Dev Cert** | Copy development certificates |

#### Terminal Access

- Select a device and click to open SSH terminal
- Interactive terminal with real-time output
- Supports FTD expert mode and FMC shell access

---

### 4. Settings (`/settings`)

- **Theme Selection**: Light, Dark, Blue, Green themes
- **Connection Presets**: Manage saved FMC connection presets

---

## API Endpoints

### FMC Configuration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/fmc-config/connect` | POST | Connect to FMC |
| `/api/fmc-config/config/upload` | POST | Upload configuration YAML |
| `/api/fmc-config/config/get` | POST | Get device configuration |
| `/api/fmc-config/config/apply` | POST | Apply configuration to device |
| `/api/fmc-config/vpn/list` | POST | List VPN topologies |
| `/api/fmc-config/vpn/upload` | POST | Upload VPN YAML |
| `/api/fmc-config/vpn/apply` | POST | Apply VPN topologies |
| `/api/fmc-config/vpn/download` | POST | Download VPN as YAML |
| `/api/fmc-config/presets` | GET | List saved presets |
| `/api/fmc-config/presets/save` | POST | Save connection preset |

### Command Center

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/command-center/devices` | GET | Get user's devices |
| `/api/command-center/devices/upload` | POST | Upload device CSV |
| `/api/command-center/proxy/execute` | POST | Configure HTTP proxy |
| `/api/command-center/static-routes/execute` | POST | Configure static routes |
| `/api/command-center/backups/list` | POST | List available backups |

---

## Logging

- Real-time operation logs displayed in UI
- Per-user log files stored in `data/users/<username>/operation.log`
- Logs include FMC API calls, responses, and error details

---

## Security & Credential Management

### Overview

Credentials are managed securely using:
- **Environment variables** for sensitive configuration
- **Fernet encryption** for stored FMC connection presets
- **External JSON file** for web app user credentials

### Files Not in Git (`.gitignore`)

| File | Purpose |
|------|---------|
| `.env` | Environment variables with secrets |
| `web_app/data/users.json` | Web app user credentials |

### Environment Variables

Create a `.env` file in the project root:

```bash
# Session secret for web app (generate a random 32+ character string)
WEB_APP_SESSION_SECRET=your-random-secret-key-here

# Encryption key for stored FMC credentials
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
CREDENTIAL_ENCRYPTION_KEY=your-fernet-key-here

# Default credentials for standalone scripts
DEFAULT_HOST=10.106.239.165
DEFAULT_SSH_USERNAME=admin
DEFAULT_FTD_PASSWORD=your-ftd-password
DEFAULT_FMC_PASSWORD=your-fmc-password
```

### Web App Users

Create `web_app/data/users.json`:

```json
{
  "admin": "your-admin-password",
  "cisco": "cisco",
  "username": "password"
}
```

### FMC Preset Encryption

FMC connection presets (saved via UI) have passwords encrypted at rest:

```json
{
  "name": "My-FMC",
  "fmc_ip": "https://10.0.0.1",
  "username": "admin",
  "password": "ENC:gAAAAABpcLpP..."
}
```

---

## Deployment

### Local Development

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd SIT
   ```

2. Create virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Create `.env` file (see Environment Variables section above)

4. Create `web_app/data/users.json` (see Web App Users section above)

5. Run the application:
   ```bash
   cd web_app
   python -m uvicorn app:app --host 0.0.0.0 --port 5001 --reload
   ```

### Remote Server Deployment

After `git pull`, the following files won't exist (they're in `.gitignore`):

1. **Install dependencies:**
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Create `.env` file:**
   ```bash
   cat > .env << 'EOF'
   WEB_APP_SESSION_SECRET=generate-a-new-random-secret-for-production
   CREDENTIAL_ENCRYPTION_KEY=your-fernet-key-here
   DEFAULT_HOST=10.106.239.165
   DEFAULT_SSH_USERNAME=admin
   DEFAULT_FTD_PASSWORD=your-password
   DEFAULT_FMC_PASSWORD=your-password
   EOF
   ```

3. **Create `web_app/data/users.json`:**
   ```bash
   cat > web_app/data/users.json << 'EOF'
   {
     "admin": "your-admin-password",
     "cisco": "cisco"
   }
   EOF
   ```

4. **Migrate existing FMC presets (if copying from another environment):**
   ```bash
   python migrate_credentials.py
   ```
   
   > ⚠️ **Important:** If copying `fmc_config_presets.json` from another environment, ensure `CREDENTIAL_ENCRYPTION_KEY` is the same, otherwise passwords won't decrypt.

5. **Start the application**

### Kubernetes Deployment

Create a Secret for credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sit-credentials
  namespace: sit
type: Opaque
stringData:
  WEB_APP_SESSION_SECRET: "generate-a-new-random-secret"
  CREDENTIAL_ENCRYPTION_KEY: "your-fernet-key-here"
  DEFAULT_HOST: "10.106.239.165"
  DEFAULT_SSH_USERNAME: "admin"
  DEFAULT_FTD_PASSWORD: "your-password"
  DEFAULT_FMC_PASSWORD: "your-password"
  USERS_JSON: '{"admin":"password","cisco":"cisco"}'
```

Reference in your Deployment:

```yaml
spec:
  containers:
    - name: sit
      envFrom:
        - secretRef:
            name: sit-credentials
```

### Generating Encryption Key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Troubleshooting

### Connection Issues
- Ensure FMC is reachable from the web app host
- Verify credentials have API access enabled in FMC
- Check FMC API is enabled (Administration > Configuration > REST API Preferences)

### Configuration Apply Errors
- Review real-time logs for specific error messages
- FMC API errors include detailed descriptions
- Objects must exist before interfaces that reference them
- Security Zones are created automatically if in YAML `objects` section

### VPN Apply Issues
- Devices must be registered in destination FMC
- Interface names must match between source and destination
- IKE policies and IPSec proposals are created if missing
