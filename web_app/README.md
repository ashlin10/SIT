# FMC Tool - Web Interface

A web-based frontend for the clone_device_config.py script, allowing users to clone configurations between FTD devices through a modern UI.

## Features

- Clean, modern UI similar to Cisco Secure Client DAMT
- Dashboard with traffic insights visualization
- Clone Device Configuration interface with:
  - FMC connection management
  - Source and destination FTD selection
  - Configuration export/import options
  - VPN endpoint replacement
  - Batch size configuration
  - Operation status tracking

## Installation

1. Make sure you have Python 3.8+ installed

2. Install the required dependencies:
   ```bash
   cd web_app
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python app.py
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

### Testing FMC Connection

1. Enter your FMC IP address, username, and password
2. Click "Test Connection" to verify connectivity

### Cloning Device Configuration

1. After successful connection, select source and destination FTDs
2. Choose the operation type:
   - **Clone (Direct)**: Clone directly from source to destination
   - **Export Configuration**: Export source configuration to YAML file
   - **Import Configuration**: Import configuration from YAML file to destination
3. Set batch size for bulk operations (default: 50)
4. Click "Clone Configuration" to start the process

### Replacing VPN Endpoints

1. After successful connection and device selection
2. Click "Replace VPN Endpoints" to replace VPN endpoints in VPN topologies

## Architecture

- **Frontend**: HTML, CSS, JavaScript with Bootstrap 5
- **Backend**: FastAPI (Python)
- **Integration**: Interfaces with existing clone_device_config.py script

## Notes

- This is a local web application and does not require internet connectivity
- All operations are performed through the FMC API
- The application does not modify the original scripts, only provides a UI wrapper
