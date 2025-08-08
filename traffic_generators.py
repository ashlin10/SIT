import paramiko
import time
import logging
import re
from typing import Dict, List, Optional, Tuple, Any
from pydantic import BaseModel

# Configure logging
logger = logging.getLogger(__name__)

class SSHConnectionDetails(BaseModel):
    """Model for SSH connection details"""
    ip_address: str
    port: int = 22
    username: str
    password: str

class NetworkInterface(BaseModel):
    """Model for network interface details"""
    name: str
    ipv4_addresses: List[str] = []
    ipv6_addresses: List[str] = []

class SSHClient:
    """Class to handle SSH connections and operations"""
    
    def __init__(self, connection_details: SSHConnectionDetails):
        self.connection_details = connection_details
        self.client = None
        self.connected = False
    
    def connect(self) -> Tuple[bool, str]:
        """
        Establish SSH connection to the target and configure sudo access without password
        
        Returns:
            Tuple[bool, str]: Success status and message
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.client.connect(
                hostname=self.connection_details.ip_address,
                port=self.connection_details.port,
                username=self.connection_details.username,
                password=self.connection_details.password,
                timeout=10
            )
            
            # Configure sudo to not require password for this session
            # Create a temporary sudoers file for the current user
            username = self.connection_details.username
            sudoers_command = f"echo '{username} ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/{username}_temp"
            
            # Execute the command directly with the password
            stdin, stdout, stderr = self.client.exec_command(sudoers_command)
            stdin.write(f"{self.connection_details.password}\n")
            stdin.flush()
            
            # Wait for command to complete
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                logger.warning(f"Could not configure passwordless sudo: {stderr.read().decode('utf-8')}")
                # Continue anyway, as the connection is established
            
            self.connected = True
            return True, f"Successfully connected to {self.connection_details.ip_address}"
        
        except Exception as e:
            logger.error(f"SSH connection error: {str(e)}")
            return False, f"Failed to connect: {str(e)}"
    
    def disconnect(self):
        """Close the SSH connection"""
        if self.client:
            self.client.close()
            self.connected = False
    
    def execute_command(self, command: str, use_sudo: bool = False) -> Tuple[bool, str, str]:
        """
        Execute a command on the remote host
        
        Args:
            command: The command to execute
            use_sudo: Whether to use sudo with password input
            
        Returns:
            Tuple[bool, str, str]: Success status, stdout, and stderr
        """
        if not self.connected or not self.client:
            return False, "", "Not connected to SSH server"
        
        try:
            if use_sudo:
                # Prepend sudo -S to the command to read password from stdin
                sudo_command = f"sudo -S {command}"
                logger.info(f"Executing sudo command: {sudo_command}")
                
                # Execute with sudo
                stdin, stdout, stderr = self.client.exec_command(sudo_command)
                
                # Send password to stdin
                stdin.write(f"{self.connection_details.password}\n")
                stdin.flush()
            else:
                # Execute normal command
                stdin, stdout, stderr = self.client.exec_command(command)
            
            # Read output
            stdout_str = stdout.read().decode('utf-8')
            stderr_str = stderr.read().decode('utf-8')
            
            # Check exit status
            exit_status = stdout.channel.recv_exit_status()
            success = exit_status == 0
            
            # Check for permission denied errors
            if not success and ("permission denied" in stderr_str.lower() or 
                               "not in the sudoers file" in stderr_str.lower()):
                logger.error(f"Permission denied error: {stderr_str}")
                return False, stdout_str, f"Permission denied: {stderr_str}"
            
            return success, stdout_str, stderr_str
        
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            return False, "", str(e)
    
    def get_network_interfaces(self) -> List[NetworkInterface]:
        """
        Get list of network interfaces and their IP addresses
        
        Returns:
            List[NetworkInterface]: List of network interfaces with their details
        """
        interfaces = []
        
        # Get interface names
        success, stdout, _ = self.execute_command("ip -o link show | awk -F': ' '{print $2}'")
        if not success:
            return interfaces
        
        interface_names = [name.strip() for name in stdout.split('\n') if name.strip()]
        
        for name in interface_names:
            if name == 'lo':  # Skip loopback interface
                continue
                
            interface = NetworkInterface(name=name)
            
            # Get IPv4 addresses
            success, stdout, _ = self.execute_command(f"ip -4 addr show {name} | grep inet | awk '{{print $2}}'")
            if success and stdout:
                interface.ipv4_addresses = [addr.strip() for addr in stdout.split('\n') if addr.strip()]
            
            # Get IPv6 addresses
            success, stdout, _ = self.execute_command(f"ip -6 addr show {name} | grep inet6 | awk '{{print $2}}'")
            if success and stdout:
                interface.ipv6_addresses = [addr.strip() for addr in stdout.split('\n') if addr.strip()]
            
            interfaces.append(interface)
        
        return interfaces

# Global storage for SSH clients
ssh_clients = {
    "client": None,
    "server": None
}

def connect_to_hosts(client_details: SSHConnectionDetails, server_details: SSHConnectionDetails) -> Dict[str, Any]:
    """
    Connect to both client and server hosts
    
    Args:
        client_details: SSH connection details for the client
        server_details: SSH connection details for the server
        
    Returns:
        Dict with connection results
    """
    results = {
        "client": {"success": False, "message": ""},
        "server": {"success": False, "message": ""},
        "overall_success": False
    }
    
    # Connect to client
    client = SSHClient(client_details)
    client_success, client_message = client.connect()
    results["client"]["success"] = client_success
    results["client"]["message"] = client_message
    
    if client_success:
        ssh_clients["client"] = client
    
    # Connect to server
    server = SSHClient(server_details)
    server_success, server_message = server.connect()
    results["server"]["success"] = server_success
    results["server"]["message"] = server_message
    
    if server_success:
        ssh_clients["server"] = server
    
    # Overall success only if both connections succeeded
    results["overall_success"] = client_success and server_success
    
    return results

def get_interfaces(host_type: str) -> List[Dict[str, Any]]:
    """
    Get network interfaces for the specified host
    
    Args:
        host_type: Either "client" or "server"
        
    Returns:
        List of network interfaces with their details
    """
    if host_type not in ssh_clients or not ssh_clients[host_type]:
        return []
    
    client = ssh_clients[host_type]
    interfaces = client.get_network_interfaces()
    
    # Convert to dictionary format for JSON response
    return [
        {
            "name": interface.name,
            "ipv4_addresses": interface.ipv4_addresses,
            "ipv6_addresses": interface.ipv6_addresses
        }
        for interface in interfaces
    ]

def check_tool_installation(host_type: str, tool: str) -> Dict[str, Any]:
    """
    Check if a specific tool is installed on the specified host and get its version
    
    Args:
        host_type: Either "client" or "server"
        tool: The tool to check ("scapy", "hping3", or "iperf3")
        
    Returns:
        Dict with installation status and version information
    """
    if host_type not in ssh_clients or not ssh_clients[host_type]:
        return {
            "installed": False,
            "version": None,
            "message": "Not connected to host"
        }
    
    client = ssh_clients[host_type]
    
    # Different commands for different tools
    if tool == "scapy":
        # Enhanced scapy detection with more robust version checking
        # First try with python3
        check_cmd = "python3 -c \"try:\n    import scapy\n    try:\n        print(scapy.__version__)\n    except AttributeError:\n        print('installed-no-version')\nexcept ImportError:\n    exit(1)\"" 
        
        success, stdout, stderr = client.execute_command(check_cmd)
        
        logging.info(f"Scapy check on {host_type} - success: {success}, stdout: '{stdout.strip()}', stderr: '{stderr.strip()}'")
        
        if success and stdout.strip() and "Traceback" not in stdout and "ImportError" not in stdout:
            # Extract version from output
            version = stdout.strip()
            
            # Handle case where scapy is installed but version can't be determined
            if version == 'installed-no-version':
                return {
                    "installed": True,
                    "version": "installed",
                    "message": "Scapy is installed (version unknown)"
                }
            
            # Validate that version looks reasonable (contains numbers/dots)
            import re
            if re.match(r'^[0-9.]+', version):
                return {
                    "installed": True,
                    "version": version,
                    "message": f"Scapy {version} is installed"
                }
        
        # Try with python (not python3) as fallback
        check_cmd2 = "python -c \"try:\n    import scapy\n    try:\n        print(scapy.__version__)\n    except AttributeError:\n        print('installed-no-version')\nexcept ImportError:\n    exit(1)\"" 
        
        success2, stdout2, stderr2 = client.execute_command(check_cmd2)
        
        logging.info(f"Scapy fallback check on {host_type} - success: {success2}, stdout: '{stdout2.strip()}', stderr: '{stderr2.strip()}'")
        
        if success2 and stdout2.strip() and "Traceback" not in stdout2 and "ImportError" not in stdout2:
            version = stdout2.strip()
            
            # Handle case where scapy is installed but version can't be determined
            if version == 'installed-no-version':
                return {
                    "installed": True,
                    "version": "installed",
                    "message": "Scapy is installed (version unknown)"
                }
            
            # Validate that version looks reasonable
            import re
            if re.match(r'^[0-9.]+', version):
                return {
                    "installed": True,
                    "version": version,
                    "message": f"Scapy {version} is installed"
                }
        
        # If we get here, scapy is definitely not installed
        return {
            "installed": False,
            "version": "Not Installed",
            "message": "Scapy is not installed"
        }
    elif tool == "hping3":
        # First check if hping3 exists on the system
        exists_check, exists_stdout, _ = client.execute_command("which hping3")
        
        if not exists_check or not exists_stdout.strip():
            # Command not found, hping3 is not installed
            return {
                "installed": False,
                "version": "Not Installed",
                "message": "hping3 is not installed"
            }
        
        # Check hping3 version
        success, stdout, stderr = client.execute_command("hping3 -v 2>&1 | head -n 1")
        
        if success and stdout.strip():
            # Extract version from output (format varies)
            version_text = stdout.strip()
            # Try to extract version number, or use the text as is
            import re
            version_match = re.search(r'version\s+([0-9.]+)', version_text, re.IGNORECASE)
            version = version_match.group(1) if version_match else "unknown"
            
            return {
                "installed": True,
                "version": version,
                "message": f"hping3 {version} is installed"
            }
        else:
            # Command exists but version check failed
            return {
                "installed": True,
                "version": "unknown",
                "message": "hping3 is installed (version unknown)"
            }
    elif tool == "iperf3":
        # First check if iperf3 exists on the system
        exists_check, exists_stdout, _ = client.execute_command("which iperf3")
        
        if not exists_check or not exists_stdout.strip():
            # Command not found, iperf3 is not installed
            return {
                "installed": False,
                "version": "Not Installed",
                "message": "iperf3 is not installed"
            }
        
        # Check iperf3 version
        success, stdout, stderr = client.execute_command("iperf3 --version")
        
        if success and stdout.strip():
            # Extract version from output
            version_text = stdout.strip()
            import re
            version_match = re.search(r'iperf\s+([0-9.]+)', version_text, re.IGNORECASE)
            version = version_match.group(1) if version_match else "unknown"
            
            return {
                "installed": True,
                "version": version,
                "message": f"iperf3 {version} is installed"
            }
        else:
            # Command exists but version check failed
            return {
                "installed": True,
                "version": "unknown",
                "message": "iperf3 is installed (version unknown)"
            }
    else:
        return {
            "installed": False,
            "version": None,
            "message": f"Unknown tool: {tool}"
        }

# Removed redundant check_scapy_installation function - consolidated with check_tool_installation

def install_tool_on_host(host_type: str, tool: str) -> Dict[str, Any]:
    """
    Install a specific tool on the specified host
    
    Args:
        host_type: Either "client" or "server"
        tool: The tool to install ("scapy", "hping3", or "iperf3")
        
    Returns:
        Dict with installation status and message
    """
    logging.info(f"Starting installation of {tool} on {host_type} host")
    
    if host_type not in ssh_clients or not ssh_clients[host_type]:
        logging.error(f"Cannot install {tool} on {host_type}: Not connected to host")
        return {
            "success": False,
            "message": "Not connected to host"
        }
    
    client = ssh_clients[host_type]
    
    # Detect OS type to determine installation method
    logging.info(f"Detecting OS type on {host_type} host")
    success, stdout, stderr = client.execute_command("cat /etc/os-release")
    
    if not success:
        logging.error(f"Failed to detect OS on {host_type}: {stderr}")
        return {
            "success": False,
            "message": f"Failed to detect OS: {stderr}"
        }
    
    os_info = stdout.lower()
    logging.info(f"OS info on {host_type}: {os_info[:100]}...")
    
    # Determine package manager
    if "ubuntu" in os_info or "debian" in os_info:
        package_manager = "apt-get"
        update_cmd = "apt-get update"
        logging.info(f"Detected Debian/Ubuntu on {host_type}, using apt-get")
    elif "centos" in os_info or "fedora" in os_info or "rhel" in os_info:
        package_manager = "yum"
        update_cmd = "yum check-update || true"
        logging.info(f"Detected CentOS/RHEL/Fedora on {host_type}, using yum")
    elif "arch" in os_info:
        package_manager = "pacman"
        update_cmd = "pacman -Sy"
        logging.info(f"Detected Arch Linux on {host_type}, using pacman")
    elif "alpine" in os_info:
        package_manager = "apk"
        update_cmd = "apk update"
        logging.info(f"Detected Alpine Linux on {host_type}, using apk")
    else:
        # Default to apt-get if we can't determine the OS
        package_manager = "apt-get"
        update_cmd = "apt-get update"
        logging.warning(f"Could not determine OS on {host_type}, defaulting to apt-get")
    
    # Update package lists
    logging.info(f"Updating package lists on {host_type} using {update_cmd}")
    success, stdout, stderr = client.execute_command(update_cmd)
    
    if not success:
        logging.warning(f"Package update on {host_type} may have issues: {stderr}")
    
    # Install the requested tool
    logging.info(f"Installing {tool} on {host_type} host")
    
    if tool == "scapy":
        return install_scapy(client, package_manager)
    elif tool == "hping3":
        return install_hping3(client, package_manager)
    elif tool == "iperf3":
        return install_iperf3(client, package_manager)
    else:
        logging.error(f"Unknown tool requested: {tool}")
        return {
            "success": False,
            "message": f"Unknown tool: {tool}"
        }

def install_scapy(client: SSHClient, package_manager: str) -> Dict[str, Any]:
    """
    Install Scapy on the remote host
    
    Args:
        client: SSH client to use
        package_manager: The package manager to use
        
    Returns:
        Dict with installation status and message
    """
    logging.info("Starting Scapy installation")
    
    # First check if pip/pip3 is installed
    logging.info("Checking if pip is installed")
    success, stdout, stderr = client.execute_command("which pip3 || which pip")
    
    if not success or not stdout.strip():
        logging.info("Pip not found, installing pip first")
        # Install pip first
        if package_manager == "apt-get":
            logging.info("Installing pip using apt-get")
            success, stdout, stderr = client.execute_command("apt-get install -y python3-pip", use_sudo=True)
            if not success:
                logging.error(f"Failed to install pip: {stderr}")
                return {"success": False, "message": f"Failed to install pip: {stderr}"}
        elif package_manager == "yum":
            logging.info("Installing pip using yum")
            success, stdout, stderr = client.execute_command("yum install -y python3-pip", use_sudo=True)
            if not success:
                logging.error(f"Failed to install pip: {stderr}")
                return {"success": False, "message": f"Failed to install pip: {stderr}"}
        elif package_manager == "pacman":
            logging.info("Installing pip using pacman")
            success, stdout, stderr = client.execute_command("pacman -S --noconfirm python-pip", use_sudo=True)
            if not success:
                logging.error(f"Failed to install pip: {stderr}")
                return {"success": False, "message": f"Failed to install pip: {stderr}"}
        elif package_manager == "apk":
            logging.info("Installing pip using apk")
            success, stdout, stderr = client.execute_command("apk add py3-pip", use_sudo=True)
            if not success:
                logging.error(f"Failed to install pip: {stderr}")
                return {"success": False, "message": f"Failed to install pip: {stderr}"}
    
    # Install Scapy using pip - with retry mechanism
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        logging.info(f"Installing Scapy using pip (attempt {retry_count + 1}/{max_retries})")
        
        # First try with sudo
        success, stdout, stderr = client.execute_command("pip3 install scapy || pip install scapy", use_sudo=True)
        
        if not success:
            # If sudo fails, try user-level installation
            logging.info("Sudo installation failed, trying user-level installation")
            success, stdout, stderr = client.execute_command("pip3 install --user scapy || pip install --user scapy")
        
        if success:
            # Verify installation
            logging.info("Verifying Scapy installation")
            success, stdout, stderr = client.execute_command("python3 -c 'import scapy; print(scapy.__version__)'")
            if success and stdout.strip():
                version = stdout.strip()
                logging.info(f"Successfully installed Scapy {version}")
                return {
                    "success": True,
                    "message": f"Successfully installed Scapy {version}"
                }
            else:
                # Try with python instead of python3
                success, stdout, stderr = client.execute_command("python -c 'import scapy; print(scapy.__version__)'")
                if success and stdout.strip():
                    version = stdout.strip()
                    logging.info(f"Successfully installed Scapy {version}")
                    return {
                        "success": True,
                        "message": f"Successfully installed Scapy {version}"
                    }
        
        logging.warning(f"Scapy installation attempt {retry_count + 1} failed: {stderr}")
        retry_count += 1
        time.sleep(2)  # Wait before retrying
    
    logging.error(f"Failed to install Scapy after {max_retries} attempts: {stderr}")
    return {
        "success": False,
        "message": f"Failed to install Scapy after {max_retries} attempts: {stderr}"
    }

def install_hping3(client: SSHClient, package_manager: str) -> Dict[str, Any]:
    """
    Install hping3 on the remote host
    
    Args:
        client: SSH client to use
        package_manager: The package manager to use
        
    Returns:
        Dict with installation status and message
    """
    logging.info("Starting hping3 installation")
    
    # First update package lists
    if package_manager == "apt-get":
        logging.info("Updating package lists using apt-get update")
        update_success, update_stdout, update_stderr = client.execute_command("apt-get update", use_sudo=True)
        if not update_success:
            logging.warning(f"Package update may have issues: {update_stderr}")
    elif package_manager == "yum":
        logging.info("Updating package lists using yum check-update")
        # yum check-update returns 100 if updates are available, which is considered an error by SSH
        client.execute_command("yum check-update", use_sudo=True)
    
    # Install hping3 using the appropriate package manager - with retry mechanism
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        logging.info(f"Installing hping3 (attempt {retry_count + 1}/{max_retries})")
        
        if package_manager == "apt-get":
            logging.info("Installing hping3 using apt-get")
            success, stdout, stderr = client.execute_command("apt-get install -y hping3", use_sudo=True)
        elif package_manager == "yum":
            logging.info("Installing hping3 using yum")
            success, stdout, stderr = client.execute_command("yum install -y hping3", use_sudo=True)
        elif package_manager == "pacman":
            logging.info("Installing hping3 using pacman")
            success, stdout, stderr = client.execute_command("pacman -S --noconfirm hping3", use_sudo=True)
        elif package_manager == "apk":
            logging.info("Installing hping3 using apk")
            success, stdout, stderr = client.execute_command("apk add hping3", use_sudo=True)
        
        if success:
            # Verify installation
            logging.info("Verifying hping3 installation")
            # First check if the binary exists
            exists_success, exists_stdout, _ = client.execute_command("which hping3")
            
            if exists_success and exists_stdout.strip():
                # Now check the version
                success, stdout, stderr = client.execute_command("hping3 -v")
                if success:
                    version_info = stdout.strip() if stdout.strip() else "version unknown"
                    logging.info(f"Successfully installed hping3: {version_info}")
                    return {
                        "success": True,
                        "message": f"Successfully installed hping3: {version_info}"
                    }
                else:
                    logging.info("hping3 binary found but version check failed")
                    return {
                        "success": True,
                        "message": "Successfully installed hping3 (version unknown)"
                    }
        
        logging.warning(f"hping3 installation attempt {retry_count + 1} failed: {stderr}")
        retry_count += 1
        time.sleep(2)  # Wait before retrying
    
    logging.error(f"Failed to install hping3 after {max_retries} attempts: {stderr}")
    return {
        "success": False,
        "message": f"Failed to install hping3 after {max_retries} attempts: {stderr}"
    }

def install_iperf3(client: SSHClient, package_manager: str) -> Dict[str, Any]:
    """
    Install iperf3 on the remote host
    
    Args:
        client: SSH client to use
        package_manager: The package manager to use
        
    Returns:
        Dict with installation status and message
    """
    logging.info("Starting iperf3 installation")
    
    # First update package lists
    if package_manager == "apt-get":
        logging.info("Updating package lists using apt-get update")
        update_success, update_stdout, update_stderr = client.execute_command("apt-get update", use_sudo=True)
        if not update_success:
            logging.warning(f"Package update may have issues: {update_stderr}")
    elif package_manager == "yum":
        logging.info("Updating package lists using yum check-update")
        # yum check-update returns 100 if updates are available, which is considered an error by SSH
        client.execute_command("yum check-update", use_sudo=True)
    
    # Install iperf3 using the appropriate package manager - with retry mechanism
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        logging.info(f"Installing iperf3 (attempt {retry_count + 1}/{max_retries})")
        
        if package_manager == "apt-get":
            logging.info("Installing iperf3 using apt-get")
            success, stdout, stderr = client.execute_command("apt-get install -y iperf3", use_sudo=True)
        elif package_manager == "yum":
            logging.info("Installing iperf3 using yum")
            # Some systems may need epel-release for iperf3
            client.execute_command("yum install -y epel-release", use_sudo=True)
            success, stdout, stderr = client.execute_command("yum install -y iperf3", use_sudo=True)
        elif package_manager == "pacman":
            logging.info("Installing iperf3 using pacman")
            success, stdout, stderr = client.execute_command("pacman -S --noconfirm iperf3", use_sudo=True)
        elif package_manager == "apk":
            logging.info("Installing iperf3 using apk")
            success, stdout, stderr = client.execute_command("apk add iperf3", use_sudo=True)
        
        if success:
            # Verify installation
            logging.info("Verifying iperf3 installation")
            # First check if the binary exists
            exists_success, exists_stdout, _ = client.execute_command("which iperf3")
            
            if exists_success and exists_stdout.strip():
                # Now check the version
                success, stdout, stderr = client.execute_command("iperf3 --version")
                if success and stdout.strip():
                    version_info = stdout.strip()
                    logging.info(f"Successfully installed iperf3: {version_info}")
                    return {
                        "success": True,
                        "message": f"Successfully installed iperf3: {version_info}"
                    }
                else:
                    logging.info("iperf3 binary found but version check failed")
                    return {
                        "success": True,
                        "message": "Successfully installed iperf3 (version unknown)"
                    }
        
        logging.warning(f"iperf3 installation attempt {retry_count + 1} failed: {stderr}")
        retry_count += 1
        time.sleep(2)  # Wait before retrying
    
    logging.error(f"Failed to install iperf3 after {max_retries} attempts: {stderr}")
    return {
        "success": False,
        "message": f"Failed to install iperf3 after {max_retries} attempts: {stderr}"
    }

def disconnect_all():
    """Disconnect all SSH connections"""
    for host_type, client in ssh_clients.items():
        if client:
            client.disconnect()
            ssh_clients[host_type] = None


class TrafficGenerationRequest(BaseModel):
    """Model for traffic generation request"""
    tool: str  # 'scapy', 'hping3', or 'iperf3'
    source_host: str  # 'client' or 'server'
    target_host: str  # 'client' or 'server' or custom IP
    interface: str
    # Common options
    duration: int = 10  # seconds
    # Tool-specific options
    # Hping3 options
    hping3_options: Optional[Dict[str, Any]] = None
    # Iperf3 options
    iperf3_options: Optional[Dict[str, Any]] = None
    # Scapy options
    scapy_options: Optional[Dict[str, Any]] = None


def generate_traffic(request: TrafficGenerationRequest) -> Dict[str, Any]:
    """
    Generate network traffic using the specified tool
    
    Args:
        request: Traffic generation request details
        
    Returns:
        Dict with generation results
    """
    if request.source_host not in ssh_clients or not ssh_clients[request.source_host]:
        return {
            "success": False,
            "message": f"Not connected to {request.source_host}"
        }
    
    client = ssh_clients[request.source_host]
    
    # Determine target IP
    target_ip = request.target_host
    if request.target_host in ["client", "server"]:
        # Get the IP of the target host
        if request.target_host not in ssh_clients or not ssh_clients[request.target_host]:
            return {
                "success": False,
                "message": f"Not connected to target host {request.target_host}"
            }
        
        target_details = ssh_clients[request.target_host].connection_details
        target_ip = target_details.ip_address
    
    # Generate traffic based on the selected tool
    if request.tool == "hping3":
        return generate_hping3_traffic(client, target_ip, request)
    elif request.tool == "iperf3":
        return generate_iperf3_traffic(client, target_ip, request)
    elif request.tool == "scapy":
        return generate_scapy_traffic(client, target_ip, request)
    else:
        return {
            "success": False,
            "message": f"Unknown tool: {request.tool}"
        }


def generate_hping3_traffic(client: SSHClient, target_ip: str, request: TrafficGenerationRequest) -> Dict[str, Any]:
    """
    Generate traffic using hping3 with comprehensive options support
    
    Args:
        client: SSH client to use (source host)
        target_ip: Target IP address
        request: Traffic generation request details
        
    Returns:
        Dict with generation results
    """
    # Default options
    options = {
        "count": 10,  # Number of packets to send
        "interval": "u1000",  # Default interval (microseconds)
        "port": 80,  # Default port
        "flags": ["syn"],  # TCP flags as list
        "size": 64,  # Default packet size
        "interface": request.interface,  # Interface to use
        "protocol": "tcp",  # Default protocol
        "ttl": 64,  # Default TTL
        "verbose": True,  # Verbose output
        "fast": False,  # Fast mode (flood)
        "window": 64,  # TCP window size
        "sport": None,  # Source port (random if None)
        "id": None,  # IP ID (random if None)
    }
    
    # Override with user-specified options
    if request.hping3_options:
        options.update(request.hping3_options)
    
    # Build the hping3 command - sudo is now passwordless
    cmd_parts = ["hping3"]
    
    # Add protocol-specific flags
    if options["protocol"] == "tcp":
        # Handle TCP flags
        if isinstance(options["flags"], list):
            flag_string = ""
            if "syn" in options["flags"]: flag_string += "S"
            if "ack" in options["flags"]: flag_string += "A"
            if "fin" in options["flags"]: flag_string += "F"
            if "rst" in options["flags"]: flag_string += "R"
            if "psh" in options["flags"]: flag_string += "P"
            if "urg" in options["flags"]: flag_string += "U"
            if flag_string:
                cmd_parts.append(f"-{flag_string}")
        else:
            cmd_parts.append(f"-{options['flags']}")
    elif options["protocol"] == "udp":
        cmd_parts.append("-2")
    elif options["protocol"] == "icmp":
        cmd_parts.append("-1")
    
    # Add port for TCP/UDP
    if options["protocol"] in ["tcp", "udp"]:
        cmd_parts.append(f"-p {options['port']}")
    
    # Add count (unless fast mode)
    if not options["fast"]:
        cmd_parts.append(f"-c {options['count']}")
    else:
        cmd_parts.append("--flood")
    
    # Add interval (unless fast mode)
    if not options["fast"]:
        cmd_parts.append(f"--interval {options['interval']}")
    
    # Add packet size
    cmd_parts.append(f"-d {options['size']}")
    
    # Add TTL
    cmd_parts.append(f"--ttl {options['ttl']}")
    
    # Add TCP window size for TCP protocol
    if options["protocol"] == "tcp":
        cmd_parts.append(f"-w {options['window']}")
    
    # Add source port if specified
    if options["sport"]:
        cmd_parts.append(f"-s {options['sport']}")
    
    # Add IP ID if specified
    if options["id"]:
        cmd_parts.append(f"-N {options['id']}")
    
    # Add interface binding (use source IP from interface if available)
    if request.interface:
        # Try to bind to the interface IP address if it contains one
        if '/' in request.interface:  # Format like "192.168.1.10/24"
            source_ip = request.interface.split('/')[0]
            cmd_parts.append(f"-a {source_ip}")
        else:
            # Use interface name
            cmd_parts.append(f"-I {request.interface}")
    
    # Add verbose flag
    if options["verbose"]:
        cmd_parts.append("-V")
    
    # Handle scan mode if specified
    if "scan" in options and options["scan"]:
        scan_config = options["scan"]
        if scan_config["type"] == "port" and scan_config.get("port_range"):
            # Port scan mode
            cmd_parts.append("--scan")
            if "-" in scan_config["port_range"]:
                start_port, end_port = scan_config["port_range"].split("-")
                cmd_parts.append(f"--destport ++{start_port}-{end_port}")
    
    # Add target IP
    cmd_parts.append(target_ip)
    
    # Join the command parts
    command = " ".join(cmd_parts)
    
    # Execute the command
    success, stdout, stderr = client.execute_command(command)
    
    if success:
        return {
            "success": True,
            "message": "hping3 traffic generation completed successfully",
            "output": stdout,
            "command": command
        }
    else:
        return {
            "success": False,
            "message": f"hping3 failed: {stderr}",
            "command": command
        }


def generate_iperf3_traffic(client: SSHClient, target_ip: str, request: TrafficGenerationRequest) -> Dict[str, Any]:
    """
    Generate traffic using iperf3 with proper client/server coordination
    
    Args:
        client: SSH client to use (source host)
        target_ip: Target IP address  
        request: Traffic generation request details
        
    Returns:
        Dict with generation results
    """
    # Default options
    options = {
        "port": 5201,  # Default iperf3 port
        "time": request.duration,  # Test duration in seconds
        "bandwidth": "1M",  # Default bandwidth
        "protocol": "tcp",  # Default protocol
        "parallel": 1,  # Default number of parallel connections
        "format": "m",  # Default format (Mbits/sec)
        "interval": 1,  # Default interval for reports
        "interface": request.interface,  # Interface to use
        "reverse": False,  # Reverse direction
        "json": False,  # JSON output
        "mode": "client"  # Default to client mode
    }
    
    # Override with user-specified options
    if request.iperf3_options:
        options.update(request.iperf3_options)
    
    # Get target client for server operations
    target_client = None
    if request.target_host in ssh_clients and ssh_clients[request.target_host]:
        target_client = ssh_clients[request.target_host]
    
    try:
        # Step 1: Start iperf3 server on target host
        if target_client:
            # First, make sure no previous iperf3 server is running on this port
            cleanup_cmd = f"pkill -f 'iperf3.*-s.*-p {options['port']}' || true"
            target_client.execute_command(cleanup_cmd)
            
            # Build server command
            server_cmd_parts = ["iperf3 -s"]  # Remove -D (daemon) mode for better error visibility
            server_cmd_parts.append("-p {}".format(options["port"]))
            
            if options["protocol"] == "udp":
                server_cmd_parts.append("-u")
                
            # Add one-off flag to automatically exit after test
            server_cmd_parts.append("--one-off")
            
            # Run in background with nohup
            server_command = "nohup " + " ".join(server_cmd_parts) + " > /tmp/iperf3_server.log 2>&1 &"
            
            # Start the server
            server_success, server_stdout, server_stderr = target_client.execute_command(server_command)
            if not server_success:
                return {
                    "success": False,
                    "message": f"Failed to start iperf3 server: {server_stderr}",
                    "command": server_command
                }
            
            # Verify server is running
            verify_cmd = "pgrep -f 'iperf3.*-s.*-p {}'".format(options["port"])
            success, stdout, _ = target_client.execute_command(verify_cmd)
            if not success or not stdout.strip():
                return {
                    "success": False,
                    "message": "Failed to start iperf3 server: Server process not found after startup",
                    "command": server_command
                }
                
            # Wait for server to initialize and be ready to accept connections
            import time
            time.sleep(3)  # Increase wait time to ensure server is fully ready
        
        # Step 2: Build client command
        cmd_parts = ["iperf3 -c {}".format(target_ip)]
        
        # Add port
        cmd_parts.append("-p {}".format(options["port"]))
        
        # Add time
        cmd_parts.append("-t {}".format(options["time"]))
        
        # Add bandwidth (only for UDP or to limit TCP)
        if options["protocol"] == "udp" or "bandwidth" in options:
            cmd_parts.append("-b {}".format(options["bandwidth"]))
        
        # Add protocol
        if options["protocol"] == "udp":
            cmd_parts.append("-u")
        
        # Add parallel connections
        if options["parallel"] > 1:
            cmd_parts.append("-P {}".format(options["parallel"]))
        
        # Add format
        cmd_parts.append("-f {}".format(options["format"]))
        
        # Add interval
        cmd_parts.append("-i {}".format(options["interval"]))
        
        # Add interface binding (source IP)
        if request.interface:
            # Use the interface IP for binding
            cmd_parts.append("--bind {}".format(request.interface))
        
        # Add advanced options
        if options.get("reverse"):
            cmd_parts.append("-R")
        
        if options.get("json"):
            cmd_parts.append("-J")
            
        if options.get("zerocopy"):
            cmd_parts.append("-Z")
            
        if options.get("no_delay"):
            cmd_parts.append("-N")
            
        if options.get("window"):
            cmd_parts.append("-w {}".format(options["window"]))
            
        if options.get("mss"):
            cmd_parts.append("-M {}".format(options["mss"]))
            
        if options.get("version4"):
            cmd_parts.append("-4")
        
        # Join the command parts
        client_command = " ".join(cmd_parts)
        
        # Step 3: Execute the client command with retry logic
        max_retries = 2
        retry_count = 0
        success = False
        stdout = ""
        stderr = ""
        
        while retry_count <= max_retries and not success:
            if retry_count > 0:
                # If this is a retry, wait a bit longer for the server to be ready
                import time
                time.sleep(2)
                logger.info(f"Retrying iperf3 client connection (attempt {retry_count+1}/{max_retries+1})")
            
            # Execute the client command
            success, stdout, stderr = client.execute_command(client_command)
            
            # Check for specific error conditions that warrant a retry
            if not success and ("Bad file descriptor" in stderr or "Connection refused" in stderr):
                retry_count += 1
                if retry_count <= max_retries:
                    # Restart the server if we're going to retry
                    if target_client:
                        # Kill any existing server
                        cleanup_cmd = f"pkill -f 'iperf3.*-s.*-p {options['port']}' || true"
                        target_client.execute_command(cleanup_cmd)
                        
                        # Start a new server
                        server_cmd_parts = ["iperf3 -s"]
                        server_cmd_parts.append("-p {}".format(options["port"]))
                        if options["protocol"] == "udp":
                            server_cmd_parts.append("-u")
                        server_cmd_parts.append("--one-off")
                        server_command = "nohup " + " ".join(server_cmd_parts) + " > /tmp/iperf3_server.log 2>&1 &"
                        target_client.execute_command(server_command)
                        
                        # Wait for server to be ready
                        import time
                        time.sleep(3)
            else:
                # Either success or a different error that doesn't warrant retry
                break
        
        # Step 4: Stop the server (cleanup)
        if target_client:
            # Kill iperf3 server processes
            cleanup_cmd = f"pkill -f 'iperf3.*-s.*-p {options['port']}' || true"
            target_client.execute_command(cleanup_cmd)
        
        if success:
            full_output = stdout
            if target_client:
                full_output = f"Server started on {request.target_host}:{options['port']}\n" + stdout
                
            return {
                "success": True,
                "message": "iperf3 traffic test completed successfully",
                "output": full_output,
                "command": f"Server: {server_command if target_client else 'N/A'}; Client: {client_command}"
            }
        else:
            return {
                "success": False,
                "message": f"iperf3 client failed: {stderr}",
                "command": client_command
            }
            
    except Exception as e:
        # Cleanup server if something went wrong
        if target_client:
            cleanup_cmd = f"pkill -f 'iperf3.*-s.*-p {options['port']}' || true"
            target_client.execute_command(cleanup_cmd)
        
        return {
            "success": False,
            "message": f"iperf3 operation failed: {str(e)}",
            "command": "N/A"
        }


def generate_scapy_traffic(client: SSHClient, target_ip: str, request: TrafficGenerationRequest) -> Dict[str, Any]:
    """
    Generate traffic using Scapy
    
    Args:
        client: SSH client to use
        target_ip: Target IP address
        request: Traffic generation request details
        
    Returns:
        Dict with generation results
    """
    # Default options
    options = {
        "count": 10,  # Number of packets to send
        "interval": 1,  # Default interval (1 second)
        "port": 80,  # Default port
        "protocol": "tcp",  # Default protocol
        "size": 64,  # Default packet size
        "interface": request.interface,  # Interface to use
        "fuzzing": False,  # Fuzzing enabled
        "fuzzing_fields": [],  # Fields to fuzz
    }
    
    # Override with user-specified options
    if request.scapy_options:
        options.update(request.scapy_options)
    
    # Create a Python script for Scapy
    script = f"""
#!/usr/bin/env python3
from scapy.all import *
import time

interface = "{options['interface']}"
target_ip = "{target_ip}"
port = {options['port']}
count = {options['count']}
interval = {options['interval']}
size = {options['size']}
protocol = "{options['protocol']}"

for i in range(count):
    if protocol == "tcp":
        packet = IP(dst=target_ip)/TCP(dport=port)/Raw(load="X"*size)
    elif protocol == "udp":
        packet = IP(dst=target_ip)/UDP(dport=port)/Raw(load="X"*size)
    elif protocol == "icmp":
        packet = IP(dst=target_ip)/ICMP()/Raw(load="X"*size)
    else:
        print(f"Unknown protocol: {{protocol}}")
        exit(1)
    
    send(packet, iface=interface, verbose=1)
    time.sleep(interval)

print("Traffic generation completed.")
"""
    
    # If fuzzing is enabled, modify the script
    if options["fuzzing"] and options["fuzzing_fields"]:
        fuzzing_script = f"""
#!/usr/bin/env python3
from scapy.all import *
import time
import random

interface = "{options['interface']}"
target_ip = "{target_ip}"
port = {options['port']}
count = {options['count']}
interval = {options['interval']}
size = {options['size']}
protocol = "{options['protocol']}"

for i in range(count):
    # Base packet
    if protocol == "tcp":
        packet = IP(dst=target_ip)/TCP(dport=port)/Raw(load="X"*size)
    elif protocol == "udp":
        packet = IP(dst=target_ip)/UDP(dport=port)/Raw(load="X"*size)
    elif protocol == "icmp":
        packet = IP(dst=target_ip)/ICMP()/Raw(load="X"*size)
    else:
        print(f"Unknown protocol: {{protocol}}")
        exit(1)
    
    # Apply fuzzing
"""
        
        # Add fuzzing for each field
        for field in options["fuzzing_fields"]:
            if field == "ip_src":
                fuzzing_script += "    packet[IP].src = '.'.join([str(random.randint(1, 254)) for _ in range(4)])\n"
            elif field == "ip_ttl":
                fuzzing_script += "    packet[IP].ttl = random.randint(1, 255)\n"
            elif field == "tcp_sport" and options["protocol"] == "tcp":
                fuzzing_script += "    packet[TCP].sport = random.randint(1024, 65535)\n"
            elif field == "tcp_flags" and options["protocol"] == "tcp":
                fuzzing_script += "    packet[TCP].flags = random.choice(['S', 'A', 'SA', 'F', 'FA', 'R', 'RA'])\n"
            elif field == "udp_sport" and options["protocol"] == "udp":
                fuzzing_script += "    packet[UDP].sport = random.randint(1024, 65535)\n"
            elif field == "payload_size":
                fuzzing_script += "    packet[Raw].load = 'X' * random.randint(1, 1400)\n"
        
        fuzzing_script += """
    send(packet, iface=interface, verbose=1)
    time.sleep(interval)

print("Fuzzing traffic generation completed.")
"""
        
        script = fuzzing_script
    
    # Write the script to a temporary file on the remote host
    script_path = "/tmp/scapy_traffic.py"
    success, _, stderr = client.execute_command(f"cat > {script_path} << 'EOL'\n{script}\nEOL")
    
    if not success:
        return {
            "success": False,
            "message": f"Failed to create script: {stderr}"
        }
    
    # Make the script executable
    client.execute_command(f"chmod +x {script_path}")
    
    # Execute the script
    success, stdout, stderr = client.execute_command(f"python3 {script_path}")
    
    # Clean up the script
    client.execute_command(f"rm {script_path}")
    
    if success:
        return {
            "success": True,
            "message": "Traffic generated successfully",
            "output": stdout,
            "command": f"python3 {script_path}"
        }
    else:
        return {
            "success": False,
            "message": f"Failed to generate traffic: {stderr}",
            "command": f"python3 {script_path}"
        }
