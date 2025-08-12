import paramiko
import time
import logging
import re
from typing import Dict, List, Optional, Tuple, Any
from pydantic import BaseModel

# Configure logging
logger = logging.getLogger(__name__)
RED_BEGIN, RED_END = "\033[91m", "\033[0m"

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
                logger.info(f"{RED_BEGIN}Executing sudo command: {sudo_command}{RED_END}")
                
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
    # Selected IP addresses for client and server
    client_selected_ipv4: Optional[str] = None
    client_selected_ipv6: Optional[str] = None
    server_selected_ipv4: Optional[str] = None
    server_selected_ipv6: Optional[str] = None
    # IP version preference
    ip_version: Optional[str] = None  # 'ipv4', 'ipv6', or 'both'
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
    # Validate source host
    if request.source_host not in ["client", "server"]:
        return {
            "success": False,
            "message": "Invalid source host. Must be 'client' or 'server'"
        }
    
    # Validate tool
    if request.tool not in ["scapy", "hping3", "iperf3"]:
        return {
            "success": False,
            "message": "Invalid tool. Must be 'scapy', 'hping3', or 'iperf3'"
        }
    
    # Get client for the source host
    client = ssh_clients.get(request.source_host)
    if not client or not client.connected:
        return {
            "success": False,
            "message": f"Source host '{request.source_host}' is not connected"
        }
    
    # Determine target IP address
    target_ip = ""
    
    # If target is a custom IP, use it directly
    if request.target_host not in ["client", "server"]:
        target_ip = request.target_host
    else:
        # If target is client or server, get its IP from SSH connection
        target_client = ssh_clients.get(request.target_host)
        if not target_client or not target_client.connected:
            return {
                "success": False,
                "message": f"Target host '{request.target_host}' is not connected"
            }
        target_ip = target_client.connection_details.ip_address
    
    # Generate traffic based on the selected tool
    if request.tool == "scapy":
        return generate_scapy_traffic(client, target_ip, request)
    elif request.tool == "hping3":
        return generate_hping3_traffic(client, target_ip, request)
    elif request.tool == "iperf3":
        # Check if both IPv4 and IPv6 are selected
        ip_version = None
        if request.iperf3_options and "ip_version" in request.iperf3_options:
            ip_version = request.iperf3_options["ip_version"]
        
        if ip_version == "both":
            logging.info("Running two simultaneous iperf3 sessions for IPv4 and IPv6")
            
            # Create a copy of the request for IPv4
            ipv4_request = request.copy()
            if "iperf3_options" not in ipv4_request.dict() or ipv4_request.iperf3_options is None:
                ipv4_request.iperf3_options = {}
            else:
                # Create a deep copy of the iperf3_options dictionary
                ipv4_request.iperf3_options = {**ipv4_request.iperf3_options}
            ipv4_request.iperf3_options["ip_version"] = "ipv4"
            
            # Create a copy of the request for IPv6
            ipv6_request = request.copy()
            if "iperf3_options" not in ipv6_request.dict() or ipv6_request.iperf3_options is None:
                ipv6_request.iperf3_options = {}
            else:
                # Create a deep copy of the iperf3_options dictionary
                ipv6_request.iperf3_options = {**ipv6_request.iperf3_options}
            ipv6_request.iperf3_options["ip_version"] = "ipv6"
            
            # Run IPv4 session
            logging.info("Starting IPv4 iperf3 session")
            ipv4_result = generate_iperf3_traffic(client, target_ip, ipv4_request)
            
            # Ensure server cleanup between sessions
            if target_client:
                server_port = request.iperf3_options.get("server", {}).get("port", "5201")
                cleanup_cmd = f"pkill -f 'iperf3.*-s.*-p {server_port}' || true"
                logging.info(f"Cleaning up IPv4 server before starting IPv6 session: {cleanup_cmd}")
                target_client.execute_command(cleanup_cmd)
                # Wait a moment for cleanup to complete
                import time
                time.sleep(2)
            
            # Run IPv6 session
            logging.info("Starting IPv6 iperf3 session")
            ipv6_result = generate_iperf3_traffic(client, target_ip, ipv6_request)
            
            # Combine results
            combined_output = "===== IPv4 SESSION =====\n"
            combined_output += ipv4_result.get("output", "No output from IPv4 session") + "\n\n"
            combined_output += "===== IPv6 SESSION =====\n"
            combined_output += ipv6_result.get("output", "No output from IPv6 session")
            
            combined_command = "IPv4: " + ipv4_result.get("command", "N/A") + "\n"
            combined_command += "IPv6: " + ipv6_result.get("command", "N/A")
            
            # Determine overall success
            success = ipv4_result.get("success", False) or ipv6_result.get("success", False)
            
            return {
                "success": success,
                "message": "Completed iperf3 traffic generation for both IPv4 and IPv6",
                "output": combined_output,
                "command": combined_command,
                "ipv4_result": ipv4_result,
                "ipv6_result": ipv6_result
            }
        else:
            # Run single session with specified IP version
            return generate_iperf3_traffic(client, target_ip, request)
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
    # Log hping3 traffic generation details
    logging.info(f"===== HPING3 TRAFFIC GENERATION DETAILS =====")
    logging.info(f"Source host: {request.source_host}")
    logging.info(f"Target host: {request.target_host}")
    logging.info(f"Interface specified: {request.interface}")
    
    # Log source SSH client details
    source_details = client.connection_details
    logging.info(f"Source SSH connection: {source_details.ip_address}:{source_details.port} (user: {source_details.username})")
    
    # Extract IP addresses for both source and target hosts
    source_selected_ipv4 = getattr(request, f"{request.source_host}_selected_ipv4", None)
    source_selected_ipv6 = getattr(request, f"{request.source_host}_selected_ipv6", None)
    target_selected_ipv4 = getattr(request, f"{request.target_host}_selected_ipv4", None)
    target_selected_ipv6 = getattr(request, f"{request.target_host}_selected_ipv6", None)
    
    # Get IP version from hping3_options
    ip_version = None
    if request.hping3_options and "ip_version" in request.hping3_options:
        ip_version = request.hping3_options["ip_version"]
    else:
        ip_version = "ipv4"  # Default to IPv4 if not specified
    
    logging.info(f"IP version selection: {ip_version}")
    
    # Handle "both" IP version by running two separate sessions
    if ip_version == "both":
        logging.info("Running two simultaneous hping3 sessions for IPv4 and IPv6")
        
        # Create a copy of the request for IPv4
        ipv4_request = request.copy()
        if "hping3_options" not in ipv4_request.dict() or ipv4_request.hping3_options is None:
            ipv4_request.hping3_options = {}
        else:
            # Create a deep copy of the hping3_options dictionary
            ipv4_request.hping3_options = {**ipv4_request.hping3_options}
        ipv4_request.hping3_options["ip_version"] = "ipv4"
        
        # Create a copy of the request for IPv6
        ipv6_request = request.copy()
        if "hping3_options" not in ipv6_request.dict() or ipv6_request.hping3_options is None:
            ipv6_request.hping3_options = {}
        else:
            # Create a deep copy of the hping3_options dictionary
            ipv6_request.hping3_options = {**ipv6_request.hping3_options}
        ipv6_request.hping3_options["ip_version"] = "ipv6"
        
        # Run IPv4 session
        logging.info("Starting IPv4 hping3 session")
        ipv4_result = generate_hping3_traffic(client, target_ip, ipv4_request)
        
        # Run IPv6 session
        logging.info("Starting IPv6 hping3 session")
        ipv6_result = generate_hping3_traffic(client, target_ip, ipv6_request)
        
        # Combine results
        combined_output = "===== IPv4 SESSION =====\n" + ipv4_result.get("output", "") + "\n\n" + "===== IPv6 SESSION =====\n" + ipv6_result.get("output", "")
        combined_command = "IPv4: " + ipv4_result.get("command", "N/A") + "\nIPv6: " + ipv6_result.get("command", "N/A")
        return {"success": True, "message": "Combined IPv4 and IPv6 sessions", "output": combined_output, "command": combined_command}
    
    # Check if required IP addresses are selected based on IP version
    if ip_version == "ipv4" and not source_selected_ipv4:
        return {
            "success": False,
            "message": f"No IPv4 address selected for {request.source_host}. Please select an IPv4 address from the dropdown."
        }
    elif ip_version == "ipv6" and not source_selected_ipv6:
        return {
            "success": False,
            "message": f"No IPv6 address selected for {request.source_host}. Please select an IPv6 address from the dropdown."
        }
    
    if ip_version == "ipv4" and not target_selected_ipv4:
        return {
            "success": False,
            "message": f"No IPv4 address selected for {request.target_host}. Please select an IPv4 address from the dropdown."
        }
    elif ip_version == "ipv6" and not target_selected_ipv6:
        return {
            "success": False,
            "message": f"No IPv6 address selected for {request.target_host}. Please select an IPv6 address from the dropdown."
        }
    
    # Check if custom target IP is specified
    custom_target = request.hping3_options.get("custom_target", "").strip()
    if custom_target:
        logging.info(f"Using custom target IP/hostname: {custom_target}")
        target_interface_ip = custom_target
        # Still use automatic source IP selection based on IP version
        if ip_version == "ipv4":
            source_interface_ip = source_selected_ipv4
        elif ip_version == "ipv6":
            source_interface_ip = source_selected_ipv6
    else:
        # Get IP version and determine which addresses to use
        if ip_version == "ipv4":
            logging.info(f"Using {request.source_host}'s selected IPv4 address: {source_selected_ipv4}")
            logging.info(f"Using {request.target_host}'s selected IPv4 address: {target_selected_ipv4}")
            target_interface_ip = target_selected_ipv4
            source_interface_ip = source_selected_ipv4
        elif ip_version == "ipv6":
            logging.info(f"Using {request.source_host}'s selected IPv6 address: {source_selected_ipv6}")
            logging.info(f"Using {request.target_host}'s selected IPv6 address: {target_selected_ipv6}")
            target_interface_ip = target_selected_ipv6
            source_interface_ip = source_selected_ipv6
    
    # Default options
    options = {
        "count": 10,
        "interval": "u1000",
        "destport": 80,
        "data_size": 0,
        "mode": "tcp",
        "ttl": 64,
        "verbose": False,
        "fast": False,
        "faster": False,
        "flood": False,
        "numeric": False,
        "quiet": False,
        "debug": False,
        "beep": False,
    }
    
    # Override with user-specified options
    if request.hping3_options:
        options.update(request.hping3_options)
    
    # Log all selected HPING3 options for debugging and visibility
    logging.info(f"===== HPING3 OPTIONS =====")
    for key, value in options.items():
        logging.info(f"{key}: {value}")
    logging.info(f"===== END HPING3 OPTIONS =====")
    
    # Build the hping3 command
    cmd_parts = ["hping3"]
    
    # Get the mode from options
    mode = options.get("mode", "tcp")
    
    # Add mode-specific flags (do not add default TCP -S here; handle after TCP flags computation)
    if mode == "tcp":
        pass
    elif mode == "rawip":
        cmd_parts.append("-0")  # Raw IP mode
    elif mode == "icmp":
        cmd_parts.append("-1")  # ICMP mode
    elif mode == "udp":
        cmd_parts.append("-2")
    elif mode == "scan":
        cmd_parts.append("-8")
    elif mode == "listen":
        cmd_parts.append("-9")
    # TCP is default if no mode specified
    
    # Add IPv4/IPv6 force flags based on IP version
    if ip_version == "ipv6":
        cmd_parts.append("-6")  # Force IPv6 if available (some versions of hping3)
    
    # Add basic options
    count = options.get("count", "10")
    if count and int(count) > 0:
        cmd_parts.append(f"-c {count}")
    
    # Add interval unless flood mode
    if not options.get("flood", False):
        interval = options.get("interval", "u1000")
        if interval:
            cmd_parts.append(f"-i {interval}")
    
    # Add timing options
    if options.get("fast", False):
        cmd_parts.append("--fast")
    elif options.get("faster", False):
        cmd_parts.append("--faster")
    elif options.get("flood", False):
        cmd_parts.append("--flood")
    
    # Add data size
    data_size = options.get("data_size", "0")
    if data_size and int(data_size) > 0:
        cmd_parts.append(f"-d {data_size}")
    
    # Add destination port
    destport = options.get("destport", "80")
    if destport:
        cmd_parts.append(f"-p {destport}")
    
    # Add output options
    if options.get("numeric", False):
        cmd_parts.append("-n")
    if options.get("quiet", False):
        cmd_parts.append("-q")
    if options.get("verbose", False):
        cmd_parts.append("-V")
    if options.get("debug", False):
        cmd_parts.append("-D")
    if options.get("beep", False):
        cmd_parts.append("--beep")
    
    # Add IP options
    ttl = options.get("ttl", "64")
    if ttl and ttl != "64":
        cmd_parts.append(f"-t {ttl}")
    
    id_val = options.get("id", "")
    if id_val:
        cmd_parts.append(f"-N {id_val}")
    
    fragoff = options.get("fragoff", "0")
    if fragoff and fragoff != "0":
        cmd_parts.append(f"-g {fragoff}")
    
    mtu = options.get("mtu", "")
    if mtu:
        cmd_parts.append(f"-m {mtu}")
    
    tos = options.get("tos", "")
    if tos:
        cmd_parts.append(f"-o {tos}")
    
    ipproto = options.get("ipproto", "")
    if ipproto:
        cmd_parts.append(f"-H {ipproto}")
    
    spoof = options.get("spoof", "")
    if spoof:
        cmd_parts.append(f"-a {spoof}")
    else:
        # Use automatic source IP selection
        if source_interface_ip:
            cmd_parts.append(f"-a {source_interface_ip}")
    
    # Add IP flags
    if options.get("winid", False):
        cmd_parts.append("-W")
    if options.get("rel", False):
        cmd_parts.append("-r")
    if options.get("frag", False):
        cmd_parts.append("-f")
    if options.get("morefrag", False):
        cmd_parts.append("-x")
    if options.get("dontfrag", False):
        cmd_parts.append("-y")
    if options.get("rand_dest", False):
        cmd_parts.append("--rand-dest")
    if options.get("rand_source", False):
        cmd_parts.append("--rand-source")
    if options.get("rroute", False):
        cmd_parts.append("-G")
    
    # Add ICMP options
    if mode == "icmp":
        icmp_type = options.get("icmp_type", "8")
        if icmp_type:
            cmd_parts.append(f"-C {icmp_type}")
        
        icmp_code = options.get("icmp_code", "0")
        if icmp_code and icmp_code != "0":
            cmd_parts.append(f"-K {icmp_code}")
        
        if options.get("force_icmp", False):
            cmd_parts.append("--force-icmp")
        
        if options.get("icmp_ts", False):
            cmd_parts.append("--icmp-ts")
        
        if options.get("icmp_addr", False):
            cmd_parts.append("--icmp-addr")
        
        icmp_gw = options.get("icmp_gw", "")
        if icmp_gw:
            cmd_parts.append(f"--icmp-gw {icmp_gw}")
    
    # Add UDP/TCP options
    baseport = options.get("baseport", "")
    if baseport:
        cmd_parts.append(f"-s {baseport}")
    
    win = options.get("win", "64")
    if win and win != "64":
        cmd_parts.append(f"-w {win}")
    
    tcpoff = options.get("tcpoff", "")
    if tcpoff:
        cmd_parts.append(f"-O {tcpoff}")
    
    setseq = options.get("setseq", "")
    if setseq:
        cmd_parts.append(f"-M {setseq}")
    
    setack = options.get("setack", "")
    if setack:
        cmd_parts.append(f"-L {setack}")
    
    tcp_mss = options.get("tcp_mss", "")
    if tcp_mss:
        cmd_parts.append(f"--tcp-mss {tcp_mss}")
    
    # Add TCP/UDP flags
    if options.get("keep", False):
        cmd_parts.append("-k")
    if options.get("seqnum", False):
        cmd_parts.append("-Q")
    if options.get("badcksum", False):
        cmd_parts.append("-b")
    if options.get("tcp_timestamp", False):
        cmd_parts.append("--tcp-timestamp")
    
    # Add TCP flags
    tcp_flags = []
    if options.get("flag_syn", False):
        tcp_flags.append("-S")
    if options.get("flag_ack", False):
        tcp_flags.append("-A")
    if options.get("flag_fin", False):
        tcp_flags.append("-F")
    if options.get("flag_rst", False):
        tcp_flags.append("-R")
    if options.get("flag_push", False):
        tcp_flags.append("-P")
    if options.get("flag_urg", False):
        tcp_flags.append("-U")
    if options.get("flag_xmas", False):
        tcp_flags.append("-X")
    if options.get("flag_ymas", False):
        tcp_flags.append("-Y")
    
    # Add TCP flags to command (if in TCP mode). If none selected, default to SYN (-S)
    if mode == "tcp":
        if tcp_flags:
            cmd_parts.extend(tcp_flags)
        else:
            cmd_parts.append("-S")
    
    # Add target IP
    cmd_parts.append(target_interface_ip)
    
    # Join the command parts
    command = " ".join(cmd_parts)
    
    logging.info(f"Executing hping3 command: {command}")
    
    # Execute the command with sudo (password read via stdin)
    success, stdout, stderr = client.execute_command(command, use_sudo=True)
    
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
    # Log SSH connection details
    logging.info(f"===== IPERF3 TRAFFIC GENERATION DETAILS =====")
    logging.info(f"Source host: {request.source_host}")
    logging.info(f"Target host: {request.target_host}")
    
    # Log source SSH client details
    source_details = client.connection_details
    logging.info(f"Source SSH connection: {source_details.ip_address}:{source_details.port} (user: {source_details.username})")
    
    # Log target SSH client details if available
    if request.target_host in ssh_clients and ssh_clients[request.target_host]:
        target_details = ssh_clients[request.target_host].connection_details
        logging.info(f"Target SSH connection: {target_details.ip_address}:{target_details.port} (user: {target_details.username})")
    
    # Log interface details
    logging.info(f"Interface specified: {request.interface}")
    
    # Extract IP addresses for both source and target hosts
    source_selected_ipv4 = getattr(request, f"{request.source_host}_selected_ipv4", None)
    source_selected_ipv6 = getattr(request, f"{request.source_host}_selected_ipv6", None)
    target_selected_ipv4 = getattr(request, f"{request.target_host}_selected_ipv4", None)
    target_selected_ipv6 = getattr(request, f"{request.target_host}_selected_ipv6", None)
    
    # Get IP version from iperf3_options
    ip_version = None
    if request.iperf3_options and "ip_version" in request.iperf3_options:
        ip_version = request.iperf3_options["ip_version"]
    else:
        ip_version = "ipv4"  # Default to IPv4 if not specified
    
    # Check if required IP addresses are selected for source host based on IP version
    if ip_version == "ipv4" and not source_selected_ipv4:
        return {
            "success": False,
            "message": f"No IPv4 address selected for {request.source_host}. Please select an IPv4 address from the dropdown."
        }
    elif ip_version == "ipv6" and not source_selected_ipv6:
        return {
            "success": False,
            "message": f"No IPv6 address selected for {request.source_host}. Please select an IPv6 address from the dropdown."
        }
    elif ip_version == "both" and (not source_selected_ipv4 or not source_selected_ipv6):
        missing = []
        if not source_selected_ipv4:
            missing.append("IPv4")
        if not source_selected_ipv6:
            missing.append("IPv6")
        return {
            "success": False,
            "message": f"Missing {' and '.join(missing)} address(es) for {request.source_host}. Please select both IPv4 and IPv6 addresses when using 'both' IP version mode."
        }
    
    # Check if required IP addresses are selected for target host based on IP version
    if ip_version == "ipv4" and not target_selected_ipv4:
        return {
            "success": False,
            "message": f"No IPv4 address selected for {request.target_host}. Please select an IPv4 address from the dropdown."
        }
    elif ip_version == "ipv6" and not target_selected_ipv6:
        return {
            "success": False,
            "message": f"No IPv6 address selected for {request.target_host}. Please select an IPv6 address from the dropdown."
        }
    elif ip_version == "both" and (not target_selected_ipv4 or not target_selected_ipv6):
        missing = []
        if not target_selected_ipv4:
            missing.append("IPv4")
        if not target_selected_ipv6:
            missing.append("IPv6")
        return {
            "success": False,
            "message": f"Missing {' and '.join(missing)} address(es) for {request.target_host}. Please select both IPv4 and IPv6 addresses when using 'both' IP version mode."
        }
    
    # Log the selected IP addresses
    if source_selected_ipv4:
        logging.info(f"Using {request.source_host}'s selected IPv4 address: {source_selected_ipv4}")
    
    if source_selected_ipv6:
        logging.info(f"Using {request.source_host}'s selected IPv6 address: {source_selected_ipv6}")
        
    if target_selected_ipv4:
        logging.info(f"Using {request.target_host}'s selected IPv4 address: {target_selected_ipv4}")
    
    if target_selected_ipv6:
        logging.info(f"Using {request.target_host}'s selected IPv6 address: {target_selected_ipv6}")

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
            # Get server options
            server_options = {}
            if request.iperf3_options and "server" in request.iperf3_options:
                server_options = request.iperf3_options["server"]
            
            # Build server command
            server_port = server_options.get("port", "5201")
            server_cmd_parts = ["nohup iperf3 -s"]
            
            # Add port option
            server_cmd_parts.append("-p {}".format(server_port))
            
            # Get IP version from iperf3_options
            ip_version = None
            if request.iperf3_options and "ip_version" in request.iperf3_options:
                ip_version = request.iperf3_options["ip_version"]
            else:
                ip_version = "ipv4"  # Default to IPv4 if not specified
                
            # Add binding option based on IP version
            if ip_version == "ipv4":
                server_cmd_parts.append("-B {}".format(target_selected_ipv4))
                server_cmd_parts.append("-4")  # Force IPv4 mode
                logging.info(f"Binding server to IPv4 address: {target_selected_ipv4}")
            elif ip_version == "ipv6":
                server_cmd_parts.append("-B {}".format(target_selected_ipv6))
                server_cmd_parts.append("-6")  # Force IPv6 mode
                logging.info(f"Binding server to IPv6 address: {target_selected_ipv6}")
            elif ip_version == "both":
                # For "both", prefer IPv4 but fall back to IPv6 if needed
                # Note: For the server, we'll bind to IPv4 for the first session
                # The second IPv6 session will be started separately
                server_cmd_parts.append("-B {}".format(target_selected_ipv4))
                server_cmd_parts.append("-4")  # Force IPv4 mode
                logging.info(f"Binding server to IPv4 address for 'both' mode: {target_selected_ipv4}")
            
            # Add one-off option if specified
            if server_options.get("one_off", False):
                server_cmd_parts.append("--one-off")
                
            # Add daemon option if specified
            if server_options.get("daemon", False):
                server_cmd_parts.append("--daemon")
                
            # Add UDP 64-bit counters if specified
            if server_options.get("udp_64bit", False):
                server_cmd_parts.append("--udp-counters-64bit")
                
            # Add JSON output if specified
            if server_options.get("json", False):
                server_cmd_parts.append("--json")
                
            # Add debug option if specified
            if server_options.get("debug", False):
                server_cmd_parts.append("--debug")
                
            # Add forceflush option if specified
            if server_options.get("forceflush", False):
                server_cmd_parts.append("--forceflush")
                
            # Add logfile option if specified
            if server_options.get("logfile", ""):
                server_cmd_parts.append("--logfile {}".format(server_options["logfile"]))
                
            # Add pidfile option if specified
            if server_options.get("pidfile", ""):
                server_cmd_parts.append("--pidfile {}".format(server_options["pidfile"]))
                
            # Add idle-timeout option if specified
            if server_options.get("idle_timeout", ""):
                server_cmd_parts.append("--idle-timeout {}".format(server_options["idle_timeout"]))
            
            # Get server_stderr and run in background
            server_cmd_parts.append("> /tmp/iperf3-server.log 2>&1 &")
            
            # First, make sure no previous iperf3 server is running on this port
            cleanup_cmd = f"pkill -f 'iperf3.*-s.*-p {server_port}' || true"
            target_client.execute_command(cleanup_cmd)
            logging.info(f"{RED_BEGIN}Executing cleanup command: {cleanup_cmd}{RED_END}")

            # Log iperf3 server options if applicable
            if request.iperf3_options and "server" in request.iperf3_options and target_client:
                logging.info(f"===== IPERF3 SERVER OPTIONS =====")
                for key, value in request.iperf3_options["server"].items():
                    logging.info(f"{key}: {value}")
                logging.info(f"===== END IPERF3 SERVER OPTIONS =====")

            # Join server command parts
            server_cmd = " ".join(server_cmd_parts)
            logging.info(f"Server command: {server_cmd}")

            # Start the server
            logging.info(f"{RED_BEGIN}Executing server command: {server_cmd}{RED_END}")
            server_success, server_stdout, server_stderr = target_client.execute_command(server_cmd)
            logging.info(f"Server stdout: {server_stdout.strip() if server_stdout else ''}")
            if not server_success:
                return {
                    "success": False,
                    "message": f"Failed to start iperf3 server: {server_std}",
                    "command": server_cmd
                }
            
            # Verify server is running
            verify_cmd = "pgrep -f 'iperf3.*-s.*-p {}'".format(server_port)
            success, stdout, _ = target_client.execute_command(verify_cmd)
            if not success or not stdout.strip():
                return {
                    "success": False,
                    "message": "Failed to start iperf3 server: Server process not found after startup",
                    "command": server_cmd
                }
            else:
                server_pid = stdout.strip()
                logging.info(f"iperf3 server is running with PID: {server_pid}")
            
                
            # Wait for server to initialize and be ready to accept connections
            import time
            time.sleep(3)  # Increase wait time to ensure server is fully ready
        
        # Step 2: Build client command
        # Get client options
        client_options = {}
        if request.iperf3_options and "client" in request.iperf3_options:
            client_options = request.iperf3_options["client"]
        
        # Use target's selected IP address based on IP version preference
        target_interface_ip = None
        
        # If target host is client or server (not a custom IP), use the selected IP addresses
        if request.target_host in ["client", "server"]:
            # We already validated that the required IP addresses are selected based on IP version
            # So we can just use the appropriate IP address directly
            if ip_version == "ipv4":
                target_interface_ip = target_selected_ipv4
                logging.info(f"Using target IPv4 address: {target_interface_ip}")
            elif ip_version == "ipv6":
                target_interface_ip = target_selected_ipv6
                logging.info(f"Using target IPv6 address: {target_interface_ip}")
            elif ip_version == "both":
                # For "both" IP version, we'll handle the second session separately
                # For now, just set up the IPv4 target for the first session
                target_interface_ip = target_selected_ipv4
                logging.info(f"Using target IPv4 address for first session: {target_interface_ip}")
        else:
            # If target is a custom IP address, use it directly
            target_interface_ip = request.target_host
            logging.info(f"Using custom target IP address: {target_interface_ip}")
        
        # Start building client command
        client_cmd_parts = ["iperf3 -c {}".format(target_interface_ip)]
        
        # Add binding option based on IP version
        if ip_version == "ipv4":
            client_cmd_parts.append("-B {}".format(source_selected_ipv4))
            client_cmd_parts.append("-4")  # Force IPv4 mode
            logging.info(f"Binding client to IPv4 address: {source_selected_ipv4}")
        elif ip_version == "ipv6":
            client_cmd_parts.append("-B {}".format(source_selected_ipv6))
            client_cmd_parts.append("-6")  # Force IPv6 mode
            logging.info(f"Binding client to IPv6 address: {source_selected_ipv6}")
        elif ip_version == "both":
            # For "both", use IPv4 for the first session
            client_cmd_parts.append("-B {}".format(source_selected_ipv4))
            client_cmd_parts.append("-4")  # Force IPv4 mode
            logging.info(f"Binding client to IPv4 address for first session: {source_selected_ipv4}")
        
        # Add port
        client_port = client_options.get("port", "5201")
        client_cmd_parts.append("-p {}".format(client_port))
        
        # Add time or bytes based on duration type
        duration_type = client_options.get("duration_type", "time")
        if duration_type == "time":
            time_value = client_options.get("time", "10")
            client_cmd_parts.append("-t {}".format(time_value))
        elif duration_type == "bytes":
            bytes_value = client_options.get("bytes", "1024")
            client_cmd_parts.append("-n {}".format(bytes_value))
        elif duration_type == "blocks":
            blocks_value = client_options.get("blocks", "1024")
            client_cmd_parts.append("-k {}".format(blocks_value))
        
        # Add protocol and bandwidth
        protocol = client_options.get("protocol", "tcp")
        if protocol == "udp":
            client_cmd_parts.append("-u")
            # UDP always needs bandwidth
            bandwidth = client_options.get("bandwidth", "1M")
            client_cmd_parts.append("-b {}".format(bandwidth))
        else:  # TCP
            # For TCP, bandwidth is optional (to limit rate)
            bandwidth = client_options.get("bandwidth", "")
            if bandwidth:
                client_cmd_parts.append("-b {}".format(bandwidth))
        
        # Add parallel connections
        parallel = client_options.get("parallel", "1")
        if parallel and int(parallel) > 1:
            client_cmd_parts.append("-P {}".format(parallel))
        
        # Add window size
        window = client_options.get("window", "")
        if window:
            client_cmd_parts.append("-w {}".format(window))
        
        # Add MSS
        mss = client_options.get("mss", "")
        if mss:
            client_cmd_parts.append("-M {}".format(mss))
        
        # Add buffer length
        buffer_len = client_options.get("len", "")
        if buffer_len:
            client_cmd_parts.append("-l {}".format(buffer_len))
        
        # Add nodelay option
        if client_options.get("nodelay", False):
            client_cmd_parts.append("-N")
        
        # Add reverse option
        if client_options.get("reverse", False):
            client_cmd_parts.append("-R")
            
        # Add bidirectional option
        if client_options.get("bidir", False):
            client_cmd_parts.append("--bidir")
            
        # Add congestion control algorithm
        congestion = client_options.get("congestion", "")
        if congestion:
            client_cmd_parts.append("--congestion {}".format(congestion))
            
        # Add zerocopy option
        if client_options.get("zerocopy", False):
            client_cmd_parts.append("-Z")
            
        # Add IPv6 flow label
        flowlabel = client_options.get("flowlabel", "")
        if flowlabel:
            client_cmd_parts.append("-L {}".format(flowlabel))
            
        # Add don't fragment option (UDP over IPv4 only)
        if client_options.get("dont_fragment", False) and protocol == "udp" and ip_version == "ipv4":
            client_cmd_parts.append("--dont-fragment")
            
        # Add SCTP protocol option
        if client_options.get("sctp", False):
            client_cmd_parts.append("--sctp")
        
        # # Add UDP options
        # if protocol == "udp":
        #     # UDP buffer length
        #     udp_len = client_options.get("udp_len", "")
        #     if udp_len:
        #         client_cmd_parts.append("--length {}".format(udp_len))
            
        #     # TOS
        #     tos = client_options.get("tos", "")
        #     if tos:
        #         client_cmd_parts.append("--tos {}".format(tos))
            
        #     # Trip times
        #     if client_options.get("trip_times", False):
        #         client_cmd_parts.append("--trip-times")
            
        #     # 64-bit counters
        #     if client_options.get("udp_64bit", False):
        #         client_cmd_parts.append("--udp-counters-64bit")
        
        # Add advanced options
        # Omit seconds
        omit = client_options.get("omit", "")
        if omit:
            client_cmd_parts.append("--omit {}".format(omit))
        
        # Timeout
        timeout = client_options.get("timeout", "")
        if timeout:
            client_cmd_parts.append("--connect-timeout {}".format(timeout))
        
        # JSON output
        if client_options.get("json", False):
            client_cmd_parts.append("-J")
        
        # Get server output
        if client_options.get("get_server_output", False):
            client_cmd_parts.append("--get-server-output")
        
        # Log iperf3 client options
        logging.info(f"===== IPERF3 CLIENT OPTIONS =====")
        for key, value in client_options.items():
            logging.info(f"{key}: {value}")
        logging.info(f"===== END IPERF3 CLIENT OPTIONS =====")

        # Join the command parts
        client_command = " ".join(client_cmd_parts)
        logging.info(f"Client command: {client_command}")
        
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
            logging.info(f"{RED_BEGIN}Executing client command: {client_command}")
            success, stdout, stderr = client.execute_command(client_command)
            
            # Log execution results
            if success:
                logging.info(f"iperf3 client execution successful")
            else:
                logging.error(f"iperf3 client execution failed: {stderr}")
                
            # Check for specific error conditions that warrant a retry
            if not success and ("Bad file descriptor" in stderr or "Connection refused" in stderr):
                retry_count += 1
                logging.warning(f"iperf3 client connection failed with '{stderr.strip()}', retrying ({retry_count}/{max_retries+1})")
                if retry_count <= max_retries:
                    # Restart the server if we're going to retry
                    if target_client:
                        # Kill any existing server
                        server_port = server_options.get("port", "5201")
                        cleanup_cmd = f"pkill -f 'iperf3.*-s.*-p {server_port}' || true"
                        target_client.execute_command(cleanup_cmd)
                        
                        # Start a new server
                        logging.info("Restarting iperf3 server...")
                        # Rebuild server command using the same options as the initial server command
                        server_cmd_parts = ["nohup iperf3 -s"]
                        
                        # Add port
                        server_port = server_options.get("port", "5201")
                        server_cmd_parts.append("-p {}".format(server_port))
                        
                        # Add protocol
                        protocol = client_options.get("protocol", "tcp")
                        if protocol == "udp":
                            server_cmd_parts.append("-u")
                        
                        # Add binding option based on IP version
                        if ip_version == "ipv4" and target_selected_ipv4:
                            server_cmd_parts.append("-B {}".format(target_selected_ipv4))
                            server_cmd_parts.append("-4")  # Force IPv4 mode
                        elif ip_version == "ipv6" and target_selected_ipv6:
                            server_cmd_parts.append("-B {}".format(target_selected_ipv6))
                            server_cmd_parts.append("-6")  # Force IPv6 mode
                        elif ip_version == "both" and target_selected_ipv4:
                            # For "both", use IPv4 for the first session
                            server_cmd_parts.append("-B {}".format(target_selected_ipv4))
                            server_cmd_parts.append("-4")  # Force IPv4 mode
                        
                        # Add one-off option if specified
                        if server_options.get("one_off", True):
                            server_cmd_parts.append("--one-off")
                        
                        # Add other server options
                        if server_options.get("daemon", False):
                            server_cmd_parts.append("-D")
                        
                        # Add server output redirection
                        server_cmd_parts.append("> /tmp/iperf3_server.log 2>&1 &")
                        
                        # Join the command parts
                        server_cmd = " ".join(server_cmd_parts)
                        logging.info(f"Restarting server with command: {server_cmd}")
                        target_client.execute_command(server_cmd)
                        
                        # Wait a bit longer for the server to be ready
                        time.sleep(3)
            else:
                # Either success or a different error that doesn't warrant retry
                break
        
        # Step 4: Clean up server process if needed
        if target_client and success:
            # Kill the server process
            server_port = server_options.get("port", "5201")
            cleanup_cmd = f"pkill -f 'iperf3.*-s.*-p {server_port}' || true"
            logging.info(f"{RED_BEGIN}Executing cleanup command: {cleanup_cmd}{RED_END}")
            target_client.execute_command(cleanup_cmd)
        
        # Prepare IP address information for command output
        source_ip_info = ""
        if ip_version == "ipv4" and source_selected_ipv4:
            source_ip_info = f"(IP: {source_selected_ipv4})"
        elif ip_version == "ipv6" and source_selected_ipv6:
            source_ip_info = f"(IP: {source_selected_ipv6})"
        elif ip_version == "both" and source_selected_ipv4:
            source_ip_info = f"(IP: {source_selected_ipv4})"
            
        target_ip_info = f"(IP: {target_interface_ip})" if target_interface_ip else ""
        
        # Return the results
        if success:
            # Include server output if available
            full_output = stdout
            if target_client:
                try:
                    # Try to get server output from log file
                    _, server_output, _ = target_client.execute_command("cat /tmp/iperf3_server.log 2>/dev/null || echo 'No server log available'")
                    if server_output and server_output.strip():
                        full_output = f"=== SERVER OUTPUT ===\n{server_output.strip()}\n\n=== CLIENT OUTPUT ===\n{stdout}"
                        logging.info("Successfully retrieved server output")
                    else:
                        logging.warning("No server output available")
                except Exception as e:
                    logging.error(f"Failed to retrieve server output: {str(e)}")
            
            return {
                "success": True,
                "message": "iperf3 traffic generation completed successfully",
                "output": full_output,
                "command": f"Server: {server_cmd if target_client else 'N/A'} {target_ip_info}; Client: {client_command} {source_ip_info}"
            }
        else:
            return {
                "success": False,
                "message": f"iperf3 failed: {stderr}",
                "command": f"Server: {server_cmd if target_client else 'N/A'} {target_ip_info}; Client: {client_command} {source_ip_info}"
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
