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

#### Get VPN Topologies

1. Connect to FMC
2. Click **Get VPN Topologies**
3. Displays all S2S VPN topologies with:
   - Topology name and type (Hub-and-Spoke, Full Mesh, Point-to-Point)
   - Route-based indicator
   - Peer/endpoint list with roles

4. Select topologies and click **Download Selected** to export as YAML

#### Push VPN Topologies

1. Connect to FMC
2. Click **Upload VPN YAML** and select your VPN configuration file
3. Review parsed topologies in the UI
4. Click **Apply VPN Topologies**

The system automatically:
- Creates the VPN topology if it doesn't exist
- Resolves device UUIDs by name (supports cross-FMC migration)
- Resolves interface UUIDs by name
- Creates missing IKEv2 policies and IPSec proposals
- Creates missing protected network objects
- Applies IKE, IPSec, and Advanced settings
- Creates endpoints with proper references

#### VPN YAML Format

```yaml
vpn_topologies:
  - name: My-VPN-Topology
    routeBased: true
    topologyType: POINT_TO_POINT
    ikeV1Enabled: false
    ikeV2Enabled: true
    endpoints:
      - name: endpoint-1
        device:
          name: FTD-Device-1
          type: Device
        interface:
          name: outside
          type: PhysicalInterface
        role: HUB
        protectedNetworks:
          networks:
            - name: inside-network
              type: Network
    ikeSettings:
      - ikeV2Settings:
          policies:
            - name: AES256-SHA512
              type: IKEv2Policy
    ipsecSettings:
      - ikeV2IpsecProposal:
          - name: AES256-GCM
            type: IKEv2IPsecProposal
```

#### Replace VPN Endpoints

For migrating VPN topologies between devices:

1. Get VPN topologies from source FMC
2. Download as YAML
3. Edit YAML to update device names to target devices
4. Upload to destination FMC
5. Apply - device/interface UUIDs are resolved automatically by name

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

## Security Notes

- SSL verification is disabled for FMC API calls (self-signed certs)
- Credentials are stored in session only (not persisted to disk)
- Presets store credentials in per-user JSON files
- Session timeout: 7 days

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
