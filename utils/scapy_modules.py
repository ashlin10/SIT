#!/usr/bin/env python3
"""
Scapy Traffic Generator Modules
This module contains functions for SSH connections and traffic generation using Scapy.
"""

import os
import sys
import time
import logging
import paramiko
import subprocess
import socket
import ipaddress
from typing import Dict, List, Tuple, Optional, Union, Any

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

class SSHClient:
    """
    SSH Client class for connecting to remote hosts and executing commands
    with automatic key trust handling.
    """
    def __init__(self, hostname: str, port: int, username: str, password: str):
        """
        Initialize SSH client with connection parameters
        
        Args:
            hostname: SSH server hostname or IP address
            port: SSH server port
            username: SSH username
            password: SSH password
        """
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.client = None
        self.connected = False
        
    def connect(self) -> Tuple[bool, str]:
        """
        Connect to SSH server with automatic key trust
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            self.connected = True
            logger.info(f"Successfully connected to {self.hostname}:{self.port}")
            return True, f"Successfully connected to {self.hostname}:{self.port}"
        except paramiko.AuthenticationException:
            logger.error(f"Authentication failed for {self.username}@{self.hostname}:{self.port}")
            return False, f"Authentication failed for {self.username}@{self.hostname}:{self.port}"
        except paramiko.SSHException as e:
            logger.error(f"SSH error: {str(e)}")
            return False, f"SSH error: {str(e)}"
        except socket.timeout:
            logger.error(f"Connection timed out for {self.hostname}:{self.port}")
            return False, f"Connection timed out for {self.hostname}:{self.port}"
        except Exception as e:
            logger.error(f"Failed to connect to {self.hostname}:{self.port}: {str(e)}")
            return False, f"Failed to connect to {self.hostname}:{self.port}: {str(e)}"
    
    def disconnect(self) -> None:
        """Close SSH connection if open"""
        if self.client and self.connected:
            self.client.close()
            self.connected = False
            logger.info(f"Disconnected from {self.hostname}:{self.port}")
    
    def execute_command(self, command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Execute command on remote host
        
        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (success: bool, stdout: str, stderr: str)
        """
        if not self.client or not self.connected:
            return False, "", "Not connected to SSH server"
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_status = stdout.channel.recv_exit_status()
            stdout_str = stdout.read().decode('utf-8')
            stderr_str = stderr.read().decode('utf-8')
            
            if exit_status == 0:
                logger.info(f"Command executed successfully: {command}")
                return True, stdout_str, stderr_str
            else:
                logger.error(f"Command failed with exit status {exit_status}: {command}")
                return False, stdout_str, stderr_str
        except Exception as e:
            logger.error(f"Failed to execute command: {str(e)}")
            return False, "", str(e)
    
    def check_scapy_installed(self) -> Tuple[bool, str, str]:
        """
        Check if Scapy is installed on the remote host and get version
        
        Returns:
            Tuple of (installed: bool, message: str, version: str)
        """
        success, stdout, stderr = self.execute_command("python3 -c 'import scapy' 2>/dev/null && echo 'Scapy installed' || echo 'Scapy not installed'")
        
        if not success:
            return False, f"Failed to check Scapy installation: {stderr}", ""
        
        if "Scapy installed" in stdout:
            # Get Scapy version
            version_cmd = "python3 -c 'import scapy; print(scapy.__version__)'" 
            success, version_stdout, version_stderr = self.execute_command(version_cmd)
            version = version_stdout.strip() if success else "Unknown"
            return True, f"Scapy is installed (version {version})", version
        else:
            return False, "Scapy is not installed. Click Install to install it.", ""
    
    def install_scapy(self) -> Tuple[bool, str]:
        """
        Install Scapy on the remote host
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Check if pip3 is installed
        success, stdout, stderr = self.execute_command("which pip3")
        if not success or not stdout.strip():
            return False, "pip3 is not installed. Please install it first."
        
        # Install Scapy using pip3
        success, stdout, stderr = self.execute_command("sudo -S pip3 install scapy", timeout=120)
        if not success:
            return False, f"Failed to install Scapy: {stderr}"
        
        # Verify installation
        installed, message, version = self.check_scapy_installed()
        if installed:
            return True, f"Scapy installed successfully (version {version})"
        else:
            return False, "Failed to verify Scapy installation"
    
    def get_network_interfaces(self) -> Tuple[bool, List[Dict[str, Any]], str]:
        """
        Get list of network interfaces and their IP addresses
        
        Returns:
            Tuple of (success: bool, interfaces: List[Dict], error: str)
        """
        # Use ip command to get interfaces
        success, stdout, stderr = self.execute_command("ip -j addr show")
        if not success:
            # Try alternative method if ip command with JSON output fails
            success, stdout, stderr = self.execute_command("ifconfig -a")
            if not success:
                return False, [], f"Failed to get network interfaces: {stderr}"
            
            # Parse ifconfig output
            interfaces = []
            current_interface = None
            for line in stdout.splitlines():
                if line and not line.startswith(" "):
                    # New interface
                    if current_interface:
                        interfaces.append(current_interface)
                    
                    interface_name = line.split(":")[0].split(" ")[0]
                    current_interface = {
                        "name": interface_name,
                        "ipv4": [],
                        "ipv6": []
                    }
                elif current_interface and "inet " in line:
                    # IPv4 address
                    parts = line.strip().split()
                    ipv4 = parts[1].split("/")[0] if "/" in parts[1] else parts[1]
                    current_interface["ipv4"].append(ipv4)
                elif current_interface and "inet6" in line:
                    # IPv6 address
                    parts = line.strip().split()
                    ipv6 = parts[1].split("/")[0] if "/" in parts[1] else parts[1]
                    current_interface["ipv6"].append(ipv6)
            
            # Add the last interface
            if current_interface:
                interfaces.append(current_interface)
            
            return True, interfaces, ""
        
        try:
            # Parse JSON output from ip command
            import json
            interfaces_data = json.loads(stdout)
            interfaces = []
            
            for iface in interfaces_data:
                interface = {
                    "name": iface.get("ifname", ""),
                    "ipv4": [],
                    "ipv6": []
                }
                
                # Extract IP addresses
                for addr_info in iface.get("addr_info", []):
                    family = addr_info.get("family")
                    if family == "inet":
                        interface["ipv4"].append(addr_info.get("local", ""))
                    elif family == "inet6":
                        interface["ipv6"].append(addr_info.get("local", ""))
                
                interfaces.append(interface)
            
            return True, interfaces, ""
        except Exception as e:
            return False, [], f"Failed to parse interface data: {str(e)}"


class ScapyTrafficGenerator:
    """
    Class for generating network traffic using Scapy on remote hosts
    """
    def __init__(self, client_ssh: SSHClient, server_ssh: SSHClient, 
                 client_interface: str = None, server_interface: str = None,
                 client_ipv4: str = None, server_ipv4: str = None,
                 client_ipv6: str = None, server_ipv6: str = None):
        """
        Initialize traffic generator with SSH clients for client and server
        
        Args:
            client_ssh: SSHClient instance for the client machine
            server_ssh: SSHClient instance for the server machine
            client_interface: Network interface to use on client (optional)
            server_interface: Network interface to use on server (optional)
            client_ipv4: IPv4 address to use on client (optional)
            server_ipv4: IPv4 address to use on server (optional)
            client_ipv6: IPv6 address to use on client (optional)
            server_ipv6: IPv6 address to use on server (optional)
        """
        self.client_ssh = client_ssh
        self.server_ssh = server_ssh
        self.client_interface = client_interface
        self.server_interface = server_interface
        self.client_ipv4 = client_ipv4
        self.server_ipv4 = server_ipv4
        self.client_ipv6 = client_ipv6
        self.server_ipv6 = server_ipv6
        self.running_processes = []
        self.process_output = {'client': [], 'server': []}
        self.process_running = False
    
    def start_background_process(self, command: str, host_type: str = 'client') -> bool:
        """
        Start a background process on the client or server
        
        Args:
            command: Command to execute
            host_type: 'client' or 'server'
            
        Returns:
            bool: True if process started successfully
        """
        ssh_client = self.client_ssh if host_type == 'client' else self.server_ssh
        
        if not ssh_client.connected:
            logger.error(f"Cannot start background process: {host_type} not connected")
            return False
        
        try:
            # Create a unique identifier for the process
            timestamp = int(time.time())
            process_id = f"{host_type}_{timestamp}"
            
            # Start the command in the background with nohup and redirect output to a file
            output_file = f"/tmp/scapy_output_{process_id}.log"
            
            # Create the output file with a header first to ensure it exists and has proper permissions
            header = f"=== Scapy Traffic Generator - {host_type.upper()} ===\n"
            header += f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            header += f"Command: {command}\n"
            header += "=== Output begins below ===\n\n"
            ssh_client.execute_command(f"echo '{header}' > {output_file} && chmod 666 {output_file}")
            
            # Check if the command needs sudo
            needs_sudo = "sudo" in command or "tcpdump" in command
            
            if needs_sudo:
                # Create a temporary script approach to avoid quoting issues
                script_name = f"/tmp/scapy_cmd_{timestamp}.sh"
                
                # Create a script with the command
                script_content = f"#!/bin/bash\n{command} >> {output_file} 2>&1 & echo $!\n"
                create_script_cmd = f"cat > {script_name} << 'EOL'\n{script_content}\nEOL\n"
                ssh_client.execute_command(create_script_cmd)
                
                # Make the script executable
                ssh_client.execute_command(f"chmod +x {script_name}")
                
                # Get SSH password from connection info based on host_type
                if host_type == 'client':
                    password = self.client_ssh.password
                else:  # server
                    password = self.server_ssh.password
                
                # Execute the script with sudo
                bg_command = f"echo {password} | sudo -S {script_name} > /tmp/pid_{timestamp}.txt"
                logger.debug(f"Executing script: {script_name}")
                
                # Execute the command and capture the result
                success, stdout, stderr = ssh_client.execute_command(bg_command)
                
                # Remove the temporary script
                ssh_client.execute_command(f"rm -f {script_name}")
                
                # Log the result for debugging
                if not success:
                    logger.error(f"Failed to execute sudo command: {stderr}")
                    # Add error to output file
                    ssh_client.execute_command(f"echo 'ERROR executing command: {stderr}' >> {output_file}")
                
                # Get the PID from the temporary file
                pid_cmd = f"cat /tmp/pid_{timestamp}.txt 2>/dev/null || echo 'failed'"
                pid_success, pid_stdout, _ = ssh_client.execute_command(pid_cmd)
                pid = pid_stdout.strip()
                
                # Clean up the temporary file
                ssh_client.execute_command(f"rm -f /tmp/pid_{timestamp}.txt")
                
                # If we couldn't get the PID directly, try to find it by process name
                if not pid_success or pid == 'failed' or not pid:
                    if command.startswith('tcpdump'):
                        # Find the most recent tcpdump process
                        find_cmd = "ps aux | grep tcpdump | grep -v grep | head -n1 | awk '{print $2}'"
                        _, find_stdout, _ = ssh_client.execute_command(find_cmd)
                        pid = find_stdout.strip()
            else:
                # For non-sudo commands, we can use the standard approach
                
                # Escape any single quotes in the command to avoid nested quote issues
                escaped_command = command.replace("'", "'\"'\"'")
                
                # Log the original and escaped commands for debugging
                logger.debug(f"Original command: {command}")
                logger.debug(f"Escaped command: {escaped_command}")
                
                bg_command = f"nohup bash -c '{escaped_command} >> {output_file} 2>&1 & echo $!'"
                logger.debug(f"Full background command: {bg_command}")
                
                success, stdout, stderr = ssh_client.execute_command(bg_command)
                
                # Log the result for debugging
                if not success:
                    logger.error(f"Failed to execute command: {stderr}")
                    # Add error to output file
                    ssh_client.execute_command(f"echo 'ERROR executing command: {stderr}' >> {output_file}")
                
                pid = stdout.strip()
            
            if not pid:
                logger.error(f"Failed to get PID for background process on {host_type}")
                # Add a message to the output file
                ssh_client.execute_command(f"echo 'ERROR: Failed to start process properly' >> {output_file}")
                return False
            
            # Verify the process started by checking its existence
            verify_cmd = f"ps -p {pid} -o pid="
            verify_success, verify_stdout, _ = ssh_client.execute_command(verify_cmd)
            
            if not verify_success or not verify_stdout.strip():
                # Try with sudo for processes that might be running as root
                sudo_verify_cmd = f"sudo ps -p {pid} -o pid="
                sudo_verify_success, sudo_verify_stdout, _ = ssh_client.execute_command(sudo_verify_cmd)
                
                if not sudo_verify_success or not sudo_verify_stdout.strip():
                    logger.warning(f"Process {pid} on {host_type} may not have started correctly")
                    ssh_client.execute_command(f"echo 'WARNING: Process may not have started correctly' >> {output_file}")
                    # Continue anyway as the process might still be starting up
            
            # Store the process information
            self.running_processes.append({
                'host_type': host_type,
                'pid': pid,
                'output_file': output_file,
                'start_time': time.time(),
                'command': command
            })
            
            # Add a success message to the output file
            ssh_client.execute_command(f"echo 'Process started with PID {pid}' >> {output_file}")
            
            logger.info(f"Started background process on {host_type} with PID {pid}")
            self.process_running = True
            return True
            
        except Exception as e:
            logger.error(f"Error starting background process on {host_type}: {str(e)}")
            # Try to write the error to the output file if it exists
            try:
                if 'output_file' in locals():
                    ssh_client.execute_command(f"echo 'ERROR: {str(e)}' >> {output_file}")
            except:
                pass
            return False

    def get_process_output(self, host_type: str = 'client') -> str:
        """
        Get the output from the background process

        Args:
            host_type: 'client' or 'server'

        Returns:
            str: Output from the process
        """
        ssh_client = self.client_ssh if host_type == 'client' else self.server_ssh

        if not ssh_client.connected:
            return f"Error: {host_type} not connected"

        # Find the latest process for this host type
        process = None
        for p in reversed(self.running_processes):
            if p['host_type'] == host_type:
                process = p
                break

        if not process:
            return f"Connecting to {host_type}..."

        try:
            # Check if the process is still running
            is_running = self.is_process_running(host_type)
            
            # Get information about the command being executed
            command_info = process.get('command', 'Unknown command')
            output_file = process.get('output_file', '')
            
            # Log detailed information for debugging
            logger.debug(f"{host_type} process status: running={is_running}, command={command_info}, output_file={output_file}")

            # Get the output file size first to check if it exists and has content
            size_command = f"stat -c '%s' {output_file} 2>/dev/null || echo '0'"
            size_success, size_stdout, _ = ssh_client.execute_command(size_command)
            file_size = int(size_stdout.strip() or '0')
            logger.debug(f"{host_type} output file size: {file_size} bytes")
            
            # If file doesn't exist or is empty
            if not size_success or file_size == 0:
                if is_running:
                    return f"Process started on {host_type}, waiting for output..."
                else:
                    return f"Process on {host_type} has completed but produced no output."

            # Get the last modification time of the output file
            mod_time_command = f"stat -c '%Y' {output_file} 2>/dev/null || echo '0'"
            _, mod_time_stdout, _ = ssh_client.execute_command(mod_time_command)
            try:
                mod_time = int(mod_time_stdout.strip() or '0')
                current_time = int(time.time())
                time_since_update = current_time - mod_time
                logger.debug(f"{host_type} output file last modified {time_since_update} seconds ago")
            except ValueError:
                time_since_update = 0

            # Determine how much output to retrieve based on file size and update time
            truncated = False
            if file_size > 500000:  # ~500KB
                # For very large files, just get the last 100KB
                command = f"tail -c 100000 {output_file} 2>/dev/null || echo 'Error reading large output file'"
                truncated = True
                logger.debug(f"{host_type} output file is very large ({file_size} bytes), retrieving last 100KB")
            elif file_size > 200000:  # ~200KB
                # For large files, get the last 75KB
                command = f"tail -c 75000 {output_file} 2>/dev/null || echo 'Error reading output file'"
                truncated = True
                logger.debug(f"{host_type} output file is large ({file_size} bytes), retrieving last 75KB")
            else:
                # For smaller files, get the entire content
                command = f"cat {output_file} 2>/dev/null || echo 'Waiting for output...'"
                logger.debug(f"{host_type} retrieving full output file ({file_size} bytes)")
                
            success, stdout, stderr = ssh_client.execute_command(command)

            # If command failed
            if not success:
                error_msg = stderr if stderr else "Unknown error reading output file"
                logger.error(f"Failed to read {host_type} output file: {error_msg}")
                if is_running:
                    return f"Process is running on {host_type} but output cannot be read: {error_msg}"
                else:
                    return f"Process on {host_type} has completed or was terminated. Error reading output: {error_msg}"

            # Store the output
            new_output = stdout

            # Return only the new output since last check if not truncated
            if len(self.process_output[host_type]) > 0 and not truncated:
                last_output = ''.join(self.process_output[host_type])
                if new_output.startswith(last_output):
                    new_output = new_output[len(last_output):]
                    logger.debug(f"{host_type} returning {len(new_output)} bytes of new output")
                else:
                    # If the output doesn't start with the previous output, it might have been truncated or file was rewritten
                    logger.debug(f"{host_type} output file content changed completely, returning full content")
                    self.process_output[host_type] = []
            elif truncated:
                # Add a note about truncation
                new_output = f"\n[...Output truncated - showing last part of {file_size} bytes...\n\n" + new_output
                logger.debug(f"{host_type} returning truncated output ({len(new_output)} bytes)")
                # Reset the output history since we're only showing a part
                self.process_output[host_type] = []

            if new_output:
                self.process_output[host_type].append(new_output)
                return new_output

            # If no new output but process is running
            if is_running:
                # If the file hasn't been updated in a while, mention it
                if time_since_update > 10:  # No updates for more than 10 seconds
                    return f"Process on {host_type} is still running but no new output for {time_since_update} seconds."
                return ""  # No message if recently updated but no new content
            else:
                # Process has completed
                if not self.process_running:
                    return f"Process on {host_type} was stopped by user."
                else:
                    # Check if there was an error code
                    if 'pid' in process:
                        exit_code_cmd = f"cat /tmp/exit_code_{process['pid']} 2>/dev/null || echo 'unknown'"
                        _, exit_code_stdout, _ = ssh_client.execute_command(exit_code_cmd)
                        exit_code = exit_code_stdout.strip()
                        if exit_code and exit_code != 'unknown' and exit_code != '0':
                            return f"Process on {host_type} has completed with exit code {exit_code}."
                    
                    return f"Process on {host_type} has completed successfully."

        except Exception as e:
            logger.error(f"Error getting process output for {host_type}: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return f"Error getting output: {str(e)}"

    def stop_all_processes(self) -> bool:
        """
        Stop all running background processes

        Returns:
            bool: True if all processes were stopped successfully
        """
        if not self.running_processes:
            return True
        
        success = True
        
        for process in self.running_processes:
            host_type = process['host_type']
            pid = process['pid']
            ssh_client = self.client_ssh if host_type == 'client' else self.server_ssh
            
            if not ssh_client.connected:
                logger.warning(f"Cannot stop process on {host_type}: not connected")
                success = False
                continue
            
            try:
                # First try to get the command that was running (to identify tcpdump processes)
                cmd_check = f"ps -p {pid} -o command="
                _, cmd_stdout, _ = ssh_client.execute_command(cmd_check)
                
                # Try to kill the process normally first
                kill_command = f"kill -9 {pid} 2>/dev/null || true"
                ssh_client.execute_command(kill_command)
                
                # If it was a tcpdump process, we might need sudo to kill it
                if 'tcpdump' in cmd_stdout:
                    sudo_kill = f"sudo kill -9 {pid} 2>/dev/null || true"
                    ssh_client.execute_command(sudo_kill)
                    
                    # Also kill any other tcpdump processes that might be running
                    ssh_client.execute_command("sudo pkill -9 tcpdump 2>/dev/null || true")
                
                # Add a message to the output file that the process was stopped
                if os.path.basename(process['output_file']).startswith('scapy_output'):
                    ssh_client.execute_command(f"echo '\nProcess was stopped at {time.strftime('%Y-%m-%d %H:%M:%S')}' >> {process['output_file']} 2>/dev/null || true")
                
                # Don't remove the output file immediately so we can still see the output
                # We'll just mark it for cleanup later
                logger.info(f"Stopped process {pid} on {host_type}")
                
            except Exception as e:
                logger.error(f"Error stopping process {pid} on {host_type}: {str(e)}")
                success = False
        
        # Mark processes as stopped but don't clear the list yet so we can still access output files
        self.process_running = False
        
        return success
    
    def is_process_running(self, host_type: str = 'client') -> bool:
        """
        Check if a process is running on the specified host
        
        Args:
            host_type: 'client' or 'server'
            
        Returns:
            bool: True if a process is running
        """
        for process in self.running_processes:
            if process['host_type'] == host_type:
                ssh_client = self.client_ssh if host_type == 'client' else self.server_ssh
                
                if not ssh_client.connected:
                    logger.warning(f"Cannot check process status on {host_type}: SSH not connected")
                    return False
                
                try:
                    # First check with regular ps
                    check_command = f"ps -p {process['pid']} -o pid="
                    success, stdout, stderr = ssh_client.execute_command(check_command)
                    
                    if success and stdout.strip():
                        logger.debug(f"Process {process['pid']} found running on {host_type}")
                        return True
                    
                    # If not found, it might be running as root/sudo
                    # Try with sudo ps to see all processes
                    sudo_check = f"sudo ps -p {process['pid']} -o pid="
                    sudo_success, sudo_stdout, _ = ssh_client.execute_command(sudo_check)
                    
                    if sudo_success and sudo_stdout.strip():
                        logger.debug(f"Process {process['pid']} found running as sudo on {host_type}")
                        return True
                    
                    # Check for any tcpdump processes if this is a server process
                    # This helps catch cases where the PID might have changed
                    if host_type == 'server':
                        tcpdump_check = f"ps aux | grep tcpdump | grep -v grep | wc -l"
                        tcpdump_success, tcpdump_stdout, _ = ssh_client.execute_command(tcpdump_check)
                        
                        if tcpdump_success and tcpdump_stdout.strip() and int(tcpdump_stdout.strip()) > 0:
                            logger.debug(f"Found tcpdump process running on {host_type}")
                            return True
                        
                        # Also check with sudo
                        sudo_tcpdump_check = f"sudo ps aux | grep tcpdump | grep -v grep | wc -l"
                        sudo_tcpdump_success, sudo_tcpdump_stdout, _ = ssh_client.execute_command(sudo_tcpdump_check)
                        
                        if sudo_tcpdump_success and sudo_tcpdump_stdout.strip() and int(sudo_tcpdump_stdout.strip()) > 0:
                            logger.debug(f"Found tcpdump process running as sudo on {host_type}")
                            return True
                    
                    # Also check if the output file exists and is growing
                    file_check = f"[ -f {process['output_file']} ] && echo 'exists'"
                    file_success, file_stdout, _ = ssh_client.execute_command(file_check)
                    
                    if file_success and 'exists' in file_stdout:
                        # File exists, check if it was modified recently (last 30 seconds)
                        # Use find with -mmin for better compatibility
                        time_check = f"find {process['output_file']} -mmin -0.5 2>/dev/null | wc -l"
                        time_success, time_stdout, _ = ssh_client.execute_command(time_check)
                        
                        if time_success and time_stdout.strip() and int(time_stdout.strip()) > 0:
                            logger.debug(f"Output file for {host_type} was recently modified")
                            return True
                except Exception as e:
                    logger.error(f"Error checking process status on {host_type}: {str(e)}")
        
        return False
        
    def build_icmp_command(self, count: int = 10, interval: float = 0.1, icmp_type: int = 8, 
                          icmp_code: int = 0, use_ipv6: bool = False) -> str:
        """
        Build a command to generate ICMP traffic
        
        Args:
            count: Number of packets to send
            interval: Interval between packets in seconds
            icmp_type: ICMP type
            icmp_code: ICMP code
            use_ipv6: Whether to use IPv6
            
        Returns:
            str: Command to generate ICMP traffic
        """
        target_ip = self.server_ipv6 if use_ipv6 else self.server_ipv4
        source_ip = self.client_ipv6 if use_ipv6 else self.client_ipv4
        
        if not target_ip or not source_ip:
            raise ValueError(f"{'IPv6' if use_ipv6 else 'IPv4'} addresses not configured")
        
        ip_version = "IPv6" if use_ipv6 else "IP"
        icmp_version = "ICMPv6" if use_ipv6 else "ICMP"
        
        # Build the Python script for Scapy
        script = f"""
        from scapy.all import *
        import time
        import sys
        
        # Configure Scapy to be more verbose
        conf.verb = 2
        
        # Print startup information
        print(f"Starting {'IPv6' if {use_ipv6} else 'IPv4'} ICMP traffic generation")
        print(f"Source IP: '{source_ip}'")
        print(f"Target IP: '{target_ip}'")
        print(f"ICMP Type: {icmp_type}, Code: {icmp_code}")
        print(f"Sending {count} packets with {interval}s interval\n")
        
        # Set source and destination IPs
        src_ip = '{source_ip}'
        dst_ip = '{target_ip}'
        
        # Ensure stdout is line-buffered for real-time output
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(line_buffering=True)
        
        # Create the packet
        for i in range({count}):
            try:
                # Build the packet with payload for better visibility
                payload = f"ICMP Echo {{i+1}}/{count} - Timestamp: {{time.time()}}"
                packet = {ip_version}(src=src_ip, dst=dst_ip)/{icmp_version}(type={icmp_type}, code={icmp_code})/Raw(load=payload)
                
                # Print packet details
                print(f"\n[Packet {{i+1}}/{count}] Details:")
                print(f"  Source: {{packet.src}}")
                print(f"  Destination: {{packet.dst}}")
                print(f"  Protocol: {icmp_version} Type={icmp_type}, Code={icmp_code}")
                print(f"  Payload Length: {{len(payload)}} bytes")
                
                # Send the packet and capture the result
                result = send(packet, verbose=2, return_packets=True)
                
                # Wait before sending the next packet
                time.sleep({interval})
                
                # Print progress
                print(f'Sent ICMP packet {{i+1}}/{count} to {{dst_ip}} successfully')
            except Exception as e:
                print(f"Error sending packet {{i+1}}: {{str(e)}}")
        
        print('\nICMP traffic generation completed')
        """
        
        # Escape the script for shell execution
        escaped_script = script.replace("'", "'\''")
        
        # Build the command to execute the script
        command = f"python3 -c '{escaped_script}'"
        
        return command
    
    def build_tcp_command(self, count: int = 10, interval: float = 0.1, src_port: int = 1024, 
                         dst_port: int = 80, flags: str = "S", use_ipv6: bool = False) -> str:
        """
        Build a command to generate TCP traffic
        
        Args:
            count: Number of packets to send
            interval: Interval between packets in seconds
            src_port: Source port
            dst_port: Destination port
            flags: TCP flags (S=SYN, A=ACK, F=FIN, R=RST, P=PSH)
            use_ipv6: Whether to use IPv6
            
        Returns:
            str: Command to generate TCP traffic
        """
        target_ip = self.server_ipv6 if use_ipv6 else self.server_ipv4
        source_ip = self.client_ipv6 if use_ipv6 else self.client_ipv4
        
        if not target_ip or not source_ip:
            raise ValueError(f"{'IPv6' if use_ipv6 else 'IPv4'} addresses not configured")
        
        ip_version = "IPv6" if use_ipv6 else "IP"
        
        # Map flag characters to flag names for better readability in the script
        flag_mapping = {
            'S': 'S',  # SYN
            'A': 'A',  # ACK
            'F': 'F',  # FIN
            'R': 'R',  # RST
            'P': 'P',  # PSH
        }
        
        # Convert the flags string to the format Scapy expects
        tcp_flags = ""
        for flag in flags:
            if flag.upper() in flag_mapping:
                tcp_flags += flag_mapping[flag.upper()]
        
        # Build the Python script for Scapy
        script = f"""
        from scapy.all import *
        import time
        
        # Set source and destination IPs
        src_ip = '{source_ip}'
        dst_ip = '{target_ip}'
        
        # Create the packet
        for i in range({count}):
            # Build the packet
            packet = {ip_version}(src=src_ip, dst=dst_ip)/TCP(sport={src_port}, dport={dst_port}, flags='{tcp_flags}')
            
            # Send the packet
            send(packet, verbose=1)
            
            # Wait before sending the next packet
            time.sleep({interval})
            
            # Print progress
            print(f'Sent TCP packet {{i+1}}/{count} to {{dst_ip}}:{dst_port}')
        
        print('TCP traffic generation completed')
        """
        
        # Escape the script for shell execution
        escaped_script = script.replace("'", "'\''")
        
        # Build the command to execute the script
        command = f"python3 -c '{escaped_script}'"
        
        return command
    
    def build_udp_command(self, count: int = 10, interval: float = 0.1, src_port: int = 1024, 
                         dst_port: int = 53, payload_size: int = 64, use_ipv6: bool = False) -> str:
        """
        Build a command to generate UDP traffic
        
        Args:
            count: Number of packets to send
            interval: Interval between packets in seconds
            src_port: Source port
            dst_port: Destination port
            payload_size: Size of the payload in bytes
            use_ipv6: Whether to use IPv6
            
        Returns:
            str: Command to generate UDP traffic
        """
        target_ip = self.server_ipv6 if use_ipv6 else self.server_ipv4
        source_ip = self.client_ipv6 if use_ipv6 else self.client_ipv4
        
        if not target_ip or not source_ip:
            raise ValueError(f"{'IPv6' if use_ipv6 else 'IPv4'} addresses not configured")
        
        ip_version = "IPv6" if use_ipv6 else "IP"
        
        # Build the Python script for Scapy
        script = f"""
        from scapy.all import *
        import time
        import random
        
        # Set source and destination IPs
        src_ip = '{source_ip}'
        dst_ip = '{target_ip}'
        
        # Create the packet
        for i in range({count}):
            # Generate random payload
            payload = bytes([random.randint(0, 255) for _ in range({payload_size})])
            
            # Build the packet
            packet = {ip_version}(src=src_ip, dst=dst_ip)/UDP(sport={src_port}, dport={dst_port})/Raw(load=payload)
            
            # Send the packet
            send(packet, verbose=1)
            
            # Wait before sending the next packet
            time.sleep({interval})
            
            # Print progress
            print(f'Sent UDP packet {{i+1}}/{count} to {{dst_ip}}:{dst_port}')
        
        print('UDP traffic generation completed')
        """
        
        # Escape the script for shell execution
        escaped_script = script.replace("'", "'\''")
        
        # Build the command to execute the script
        command = f"python3 -c '{escaped_script}'"
        
        return command
    
    def build_arp_command(self, count: int = 10, interval: float = 0.1, op_type: str = "who-has") -> str:
        """
        Build a command to generate ARP traffic
        
        Args:
            count: Number of packets to send
            interval: Interval between packets in seconds
            op_type: ARP operation type ('who-has' or 'is-at')
            
        Returns:
            str: Command to generate ARP traffic
        """
        target_ip = self.server_ipv4  # ARP is IPv4 only
        source_ip = self.client_ipv4
        
        if not target_ip or not source_ip:
            raise ValueError("IPv4 addresses not configured")
        
        # Map operation type to ARP op code
        op_code = 1 if op_type.lower() == "who-has" else 2  # 1=who-has, 2=is-at
        
        # Build the Python script for Scapy
        script = f"""
        from scapy.all import *
        import time
        
        # Set source and destination IPs
        src_ip = '{source_ip}'
        dst_ip = '{target_ip}'
        
        # Get the interface for the source IP
        iface = None
        for i in get_if_list():
            if src_ip in [addr[0] for addr in [get_if_addr(i)] if addr]:
                iface = i
                break
        
        if not iface:
            print(f'No interface found for IP {{src_ip}}')
            exit(1)
        
        # Get the MAC address for the interface
        src_mac = get_if_hwaddr(iface)
        
        # Create the packet
        for i in range({count}):
            # Build the packet
            packet = Ether(src=src_mac)/ARP(op={op_code}, psrc=src_ip, pdst=dst_ip)
            
            # Send the packet
            sendp(packet, iface=iface, verbose=1)
            
            # Wait before sending the next packet
            time.sleep({interval})
            
            # Print progress
            print(f'Sent ARP packet {{i+1}}/{count} to {{dst_ip}}')
        
        print('ARP traffic generation completed')
        """
        
        # Escape the script for shell execution
        escaped_script = script.replace("'", "'\''")
        
        # Build the command to execute the script
        command = f"python3 -c '{escaped_script}'"
        
        return command
    
    def build_fuzzing_command(self, count: int = 10, interval: float = 0.1, layer: str = "IP", 
                            field: str = "", strategy: str = "random", use_ipv6: bool = False) -> str:
        """
        Build a command to generate fuzzing traffic
        
        Args:
            count: Number of packets to send
            interval: Interval between packets in seconds
            layer: Layer to fuzz (IP, TCP, UDP, ICMP)
            field: Field to fuzz (leave empty to fuzz all fields)
            strategy: Fuzzing strategy (random, increment, decrement)
            use_ipv6: Whether to use IPv6
            
        Returns:
            str: Command to generate fuzzing traffic
        """
        target_ip = self.server_ipv6 if use_ipv6 else self.server_ipv4
        source_ip = self.client_ipv6 if use_ipv6 else self.client_ipv4
        
        if not target_ip or not source_ip:
            raise ValueError(f"{'IPv6' if use_ipv6 else 'IPv4'} addresses not configured")
        
        # Adjust layer name based on IPv6 usage
        if layer == "IP" and use_ipv6:
            layer = "IPv6"
        elif layer == "ICMP" and use_ipv6:
            layer = "ICMPv6"
        
        # Build the Python script for Scapy
        script = f"""
        from scapy.all import *
        import time
        import random
        
        # Set source and destination IPs
        src_ip = '{source_ip}'
        dst_ip = '{target_ip}'
        
        # Define the base packet
        if '{layer}' == 'IP':
            base_packet = IP(src=src_ip, dst=dst_ip)
        elif '{layer}' == 'IPv6':
            base_packet = IPv6(src=src_ip, dst=dst_ip)
        elif '{layer}' == 'TCP':
            base_packet = IP(src=src_ip, dst=dst_ip)/TCP()
            if '{use_ipv6}' == 'True':
                base_packet = IPv6(src=src_ip, dst=dst_ip)/TCP()
        elif '{layer}' == 'UDP':
            base_packet = IP(src=src_ip, dst=dst_ip)/UDP()
            if '{use_ipv6}' == 'True':
                base_packet = IPv6(src=src_ip, dst=dst_ip)/UDP()
        elif '{layer}' == 'ICMP':
            base_packet = IP(src=src_ip, dst=dst_ip)/ICMP()
        elif '{layer}' == 'ICMPv6':
            base_packet = IPv6(src=src_ip, dst=dst_ip)/ICMPv6EchoRequest()
        else:
            print(f'Unsupported layer: {layer}')
            exit(1)
        
        # Get the layer object to fuzz
        if '{layer}' in ['IP', 'IPv6']:
            fuzz_layer = base_packet
        else:
            fuzz_layer = base_packet.getlayer(1)  # Get the second layer (TCP, UDP, ICMP)
        
        # Get all fields in the layer
        fields = fuzz_layer.fields_desc
        field_names = [field.name for field in fields]
        
        # Filter fields if a specific field is requested
        if '{field}' and '{field}' in field_names:
            fields_to_fuzz = ['{field}']
        else:
            fields_to_fuzz = field_names
        
        print(f'Fuzzing fields: {{fields_to_fuzz}}')
        
        # Create and send fuzzed packets
        for i in range({count}):
            # Create a copy of the base packet
            packet = base_packet.copy()
            fuzz_layer = packet if '{layer}' in ['IP', 'IPv6'] else packet.getlayer(1)
            
            # Fuzz the selected fields
            for field_name in fields_to_fuzz:
                field_obj = next((f for f in fields if f.name == field_name), None)
                if field_obj:
                    # Get the field's default value and type
                    default_val = field_obj.default
                    if hasattr(field_obj, 'fmt') and field_obj.fmt:
                        fmt = field_obj.fmt
                        if fmt[1] in 'BHIQ':  # unsigned int types
                            field_type = 'int'
                        elif fmt[1] in 'bhiq':  # signed int types
                            field_type = 'int'
                        else:
                            field_type = 'bytes'
                    else:
                        field_type = 'unknown'
                    
                    # Apply fuzzing strategy
                    if '{strategy}' == 'random':
                        if field_type == 'int':
                            # Random value within reasonable bounds
                            fuzz_val = random.randint(0, 65535)
                        else:
                            # Random bytes
                            fuzz_val = bytes([random.randint(0, 255) for _ in range(random.randint(1, 10))])
                    elif '{strategy}' == 'increment':
                        if field_type == 'int' and isinstance(default_val, int):
                            fuzz_val = default_val + i + 1
                        else:
                            # Can't increment non-int, use random
                            fuzz_val = bytes([random.randint(0, 255) for _ in range(random.randint(1, 10))])
                    elif '{strategy}' == 'decrement':
                        if field_type == 'int' and isinstance(default_val, int):
                            fuzz_val = max(0, default_val - i - 1)
                        else:
                            # Can't decrement non-int, use random
                            fuzz_val = bytes([random.randint(0, 255) for _ in range(random.randint(1, 10))])
                    
                    # Set the fuzzed value
                    try:
                        setattr(fuzz_layer, field_name, fuzz_val)
                        print(f'Fuzzed {{field_name}} = {{fuzz_val}}')
                    except Exception as e:
                        print(f'Error fuzzing {{field_name}}: {{e}}')
            
            # Send the packet
            send(packet, verbose=1)
            
            # Wait before sending the next packet
            time.sleep({interval})
            
            # Print progress
            print(f'Sent fuzzed packet {{i+1}}/{count} to {{dst_ip}}')
        
        print('Fuzzing traffic generation completed')
        """
        
        # Escape the script for shell execution
        escaped_script = script.replace("'", "'\''")
        
        # Build the command to execute the script
        command = f"python3 -c '{escaped_script}'"
        
        return command
    
    def check_connectivity(self) -> Tuple[bool, str]:
        """
        Check connectivity between client and server
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Get client IP
        success, stdout, stderr = self.client_ssh.execute_command("hostname -I | awk '{print $1}'")
        if not success or not stdout.strip():
            return False, f"Failed to get client IP address: {stderr}"
        client_ip = stdout.strip()
        
        # Get server IP
        success, stdout, stderr = self.server_ssh.execute_command("hostname -I | awk '{print $1}'")
        if not success or not stdout.strip():
            return False, f"Failed to get server IP address: {stderr}"
        server_ip = stdout.strip()
        
        # Check ping from client to server
        success, stdout, stderr = self.client_ssh.execute_command(f"ping -c 3 {server_ip}")
        if not success or "0 received" in stdout:
            return False, f"Client cannot ping server ({server_ip})"
        
        # Check ping from server to client
        success, stdout, stderr = self.server_ssh.execute_command(f"ping -c 3 {client_ip}")
        if not success or "0 received" in stdout:
            return False, f"Server cannot ping client ({client_ip})"
        
        return True, f"Connectivity check passed between {client_ip} and {server_ip}"
    
    def generate_icmp_traffic(self, count: int = 10) -> Tuple[bool, str]:
        """
        Generate ICMP traffic from client to server
        
        Args:
            count: Number of ICMP packets to send
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Get server IP if not specified
        server_ip = self.server_ip
        if not server_ip:
            success, stdout, stderr = self.server_ssh.execute_command("hostname -I | awk '{print $1}'")
            if not success or not stdout.strip():
                return False, f"Failed to get server IP address: {stderr}"
            server_ip = stdout.strip()
        
        # Prepare interface option if specified
        iface_option = f", iface='{self.client_interface}'" if self.client_interface else ""
        
        # Generate ICMP traffic using Scapy
        scapy_command = f"""python3 -c "
from scapy.all import IP, ICMP, send
for i in range({count}):
    send(IP(dst='{server_ip}')/ICMP(), verbose=0{iface_option})
    print(f'Sent ICMP packet {{i+1}}/{count} to {server_ip}')
"
"""
        success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
        if not success:
            return False, f"Failed to generate ICMP traffic: {stderr}"
        
        return True, f"Successfully sent {count} ICMP packets to {server_ip}"
    
    def generate_tcp_traffic(self, port: int = 80, count: int = 10) -> Tuple[bool, str]:
        """
        Generate TCP traffic from client to server
        
        Args:
            port: TCP port to target
            count: Number of TCP packets to send
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Get server IP if not specified
        server_ip = self.server_ip
        if not server_ip:
            success, stdout, stderr = self.server_ssh.execute_command("hostname -I | awk '{print $1}'")
            if not success or not stdout.strip():
                return False, f"Failed to get server IP address: {stderr}"
            server_ip = stdout.strip()
        
        # Prepare interface option if specified
        iface_option = f", iface='{self.client_interface}'" if self.client_interface else ""
        
        # Generate TCP traffic using Scapy
        scapy_command = f"""python3 -c "
from scapy.all import IP, TCP, send
for i in range({count}):
    send(IP(dst='{server_ip}')/TCP(dport={port}, flags='S'), verbose=0{iface_option})
    print(f'Sent TCP SYN packet {{i+1}}/{count} to {server_ip}:{port}')
"
"""
        success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
        if not success:
            return False, f"Failed to generate TCP traffic: {stderr}"
        
        return True, f"Successfully sent {count} TCP packets to {server_ip}:{port}"
    
    def generate_udp_traffic(self, port: int = 53, count: int = 10, sport: int = None, payload_size: int = 0, use_ipv4: bool = True, use_ipv6: bool = False) -> Tuple[bool, str]:
        """
        Generate UDP traffic from client to server
        
        Args:
            port: UDP port to target
            count: Number of UDP packets to send
            sport: Source port (optional)
            payload_size: Size of payload in bytes
            use_ipv4: Whether to use IPv4
            use_ipv6: Whether to use IPv6
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        results = []
        
        # Prepare interface option if specified
        iface_option = f", iface='{self.client_interface}'" if self.client_interface else ""
        
        # Prepare source port option if specified
        sport_option = f", sport={sport}" if sport else ""
        
        # Generate payload if size is specified
        payload_option = ""
        if payload_size > 0:
            payload_option = f"/Raw(load='X'*{payload_size})"
        
        # Generate IPv4 traffic if requested
        if use_ipv4 and self.server_ipv4:
            scapy_command = f"""python3 -c "
            from scapy.all import IP, UDP, Raw, send
            for i in range({count}):
                send(IP(dst='{self.server_ipv4}')/UDP(dport={port}{sport_option}){payload_option}, verbose=0{iface_option})
                print(f'Sent IPv4 UDP packet {{i+1}}/{count} to {self.server_ipv4}:{port}')
            "
            """
            success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
            if not success:
                results.append(f"Failed to generate IPv4 UDP traffic: {stderr}")
            else:
                results.append(f"Successfully sent {count} IPv4 UDP packets to {self.server_ipv4}:{port}")
        
        # Generate IPv6 traffic if requested
        if use_ipv6 and self.server_ipv6:
            scapy_command = f"""python3 -c "
            from scapy.all import IPv6, UDP, Raw, send
            for i in range({count}):
                send(IPv6(dst='{self.server_ipv6}')/UDP(dport={port}{sport_option}){payload_option}, verbose=0{iface_option})
                print(f'Sent IPv6 UDP packet {{i+1}}/{count} to {self.server_ipv6}:{port}')
            "
            """
            success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
            if not success:
                results.append(f"Failed to generate IPv6 UDP traffic: {stderr}")
            else:
                results.append(f"Successfully sent {count} IPv6 UDP packets to {self.server_ipv6}:{port}")
        
        if not results:
            return False, "No traffic was generated. Check IP addresses and IP version settings."
        
        return len([r for r in results if r.startswith("Successfully")]) > 0, "\n".join(results)
    
    def generate_arp_traffic(self, op: int = 1, count: int = 10) -> Tuple[bool, str]:
        """
        Generate ARP traffic from client to server
        
        Args:
            op: ARP operation (1=who-has, 2=is-at)
            count: Number of ARP packets to send
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.server_ipv4:
            return False, "ARP requires IPv4 address for the server"
        
        # Prepare interface option if specified
        iface_option = f", iface='{self.client_interface}'" if self.client_interface else ""
        
        # Generate ARP traffic using Scapy
        scapy_command = f"""python3 -c "
        from scapy.all import ARP, Ether, sendp
        for i in range({count}):
            sendp(Ether()/ARP(op={op}, pdst='{self.server_ipv4}'), verbose=0{iface_option})
            print(f'Sent ARP packet {{i+1}}/{count} to {self.server_ipv4} (op={op})')
        "
        """
        success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
        if not success:
            return False, f"Failed to generate ARP traffic: {stderr}"
        
        op_name = "who-has" if op == 1 else "is-at" if op == 2 else f"op={op}"
        return True, f"Successfully sent {count} ARP {op_name} packets to {self.server_ipv4}"
    
    def generate_icmp_traffic(self, count: int = 10, icmp_type: int = 8, icmp_code: int = 0, use_ipv4: bool = True, use_ipv6: bool = False) -> Tuple[bool, str]:
        """
        Generate ICMP traffic from client to server
        
        Args:
            count: Number of ICMP packets to send
            icmp_type: ICMP type (8=echo request)
            icmp_code: ICMP code
            use_ipv4: Whether to use IPv4
            use_ipv6: Whether to use IPv6
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        results = []
        
        # Prepare interface option if specified
        iface_option = f", iface='{self.client_interface}'" if self.client_interface else ""
        
        # Generate IPv4 ICMP traffic if requested
        if use_ipv4 and self.server_ipv4:
            scapy_command = f"""python3 -c "
            from scapy.all import IP, ICMP, send
            for i in range({count}):
                send(IP(dst='{self.server_ipv4}')/ICMP(type={icmp_type}, code={icmp_code}), verbose=0{iface_option})
                print(f'Sent IPv4 ICMP packet {{i+1}}/{count} to {self.server_ipv4} (type={icmp_type}, code={icmp_code})')
            "
            """
            success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
            if not success:
                results.append(f"Failed to generate IPv4 ICMP traffic: {stderr}")
            else:
                results.append(f"Successfully sent {count} IPv4 ICMP packets to {self.server_ipv4}")
        
        # Generate IPv6 ICMPv6 traffic if requested
        if use_ipv6 and self.server_ipv6:
            scapy_command = f"""python3 -c "
            from scapy.all import IPv6, ICMPv6EchoRequest, send
            for i in range({count}):
                send(IPv6(dst='{self.server_ipv6}')/ICMPv6EchoRequest(), verbose=0{iface_option})
                print(f'Sent IPv6 ICMPv6 echo request packet {{i+1}}/{count} to {self.server_ipv6}')
            "
            """
            success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
            if not success:
                results.append(f"Failed to generate IPv6 ICMPv6 traffic: {stderr}")
            else:
                results.append(f"Successfully sent {count} IPv6 ICMPv6 packets to {self.server_ipv6}")
        
        if not results:
            return False, "No traffic was generated. Check IP addresses and IP version settings."
        
        return len([r for r in results if r.startswith("Successfully")]) > 0, "\n".join(results)
    
    def generate_tcp_traffic(self, port: int = 80, count: int = 10, sport: int = None, flags: Dict[str, bool] = None, use_ipv4: bool = True, use_ipv6: bool = False) -> Tuple[bool, str]:
        """
        Generate TCP traffic from client to server
        
        Args:
            port: TCP port to target
            count: Number of TCP packets to send
            sport: Source port (optional)
            flags: Dictionary of TCP flags to set (e.g. {'S': True, 'A': False})
            use_ipv4: Whether to use IPv4
            use_ipv6: Whether to use IPv6
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        results = []
        
        # Prepare interface option if specified
        iface_option = f", iface='{self.client_interface}'" if self.client_interface else ""
        
        # Prepare source port option if specified
        sport_option = f", sport={sport}" if sport else ""
        
        # Prepare flags option if specified
        flags_str = ""
        if flags:
            flag_chars = ""
            for flag, enabled in flags.items():
                if enabled:
                    flag_chars += flag
            if flag_chars:
                flags_str = f", flags='{flag_chars}'"
        
        # Generate IPv4 traffic if requested
        if use_ipv4 and self.server_ipv4:
            scapy_command = f"""python3 -c "
            from scapy.all import IP, TCP, send
            for i in range({count}):
                send(IP(dst='{self.server_ipv4}')/TCP(dport={port}{sport_option}{flags_str}), verbose=0{iface_option})
                print(f'Sent IPv4 TCP packet {{i+1}}/{count} to {self.server_ipv4}:{port}')
            "
            """
            success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
            if not success:
                results.append(f"Failed to generate IPv4 TCP traffic: {stderr}")
            else:
                results.append(f"Successfully sent {count} IPv4 TCP packets to {self.server_ipv4}:{port}")
        
        # Generate IPv6 traffic if requested
        if use_ipv6 and self.server_ipv6:
            scapy_command = f"""python3 -c "
            from scapy.all import IPv6, TCP, send
            for i in range({count}):
                send(IPv6(dst='{self.server_ipv6}')/TCP(dport={port}{sport_option}{flags_str}), verbose=0{iface_option})
                print(f'Sent IPv6 TCP packet {{i+1}}/{count} to {self.server_ipv6}:{port}')
            "
            """
            success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
            if not success:
                results.append(f"Failed to generate IPv6 TCP traffic: {stderr}")
            else:
                results.append(f"Successfully sent {count} IPv6 TCP packets to {self.server_ipv6}:{port}")
        
        if not results:
            return False, "No traffic was generated. Check IP addresses and IP version settings."
        
        return len([r for r in results if r.startswith("Successfully")]) > 0, "\n".join(results)
    
    def generate_fuzzing_traffic(self, layer: str, field: str, strategy: str, count: int = 10, use_ipv4: bool = True, use_ipv6: bool = False) -> Tuple[bool, str]:
        """
        Generate fuzzing traffic from client to server
        
        Args:
            layer: Protocol layer to fuzz (ip, tcp, udp, icmp)
            field: Field within the layer to fuzz
            strategy: Fuzzing strategy (random, incremental, boundary, overflow)
            count: Number of packets to send
            use_ipv4: Whether to use IPv4
            use_ipv6: Whether to use IPv6
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        results = []
        
        # Prepare interface option if specified
        iface_option = f", iface='{self.client_interface}'" if self.client_interface else ""
        
        # Prepare fuzzing strategy
        if strategy == "random":
            fuzz_code = f"fuzz({field})"
        elif strategy == "incremental":
            fuzz_code = f"i % 256"
        elif strategy == "boundary":
            fuzz_code = f"[0, 1, 255, 256, 65535, 4294967295][i % 6]"
        elif strategy == "overflow":
            fuzz_code = f"'A' * (i + 1)"
        else:
            fuzz_code = f"RandNum(0, 65535)"
        
        # Generate IPv4 fuzzing if requested
        if use_ipv4 and self.server_ipv4:
            # Create appropriate fuzzing command based on layer
            if layer == "ip":
                scapy_command = f"""python3 -c "
                from scapy.all import IP, TCP, send, RandNum
                for i in range({count}):
                    pkt = IP(dst='{self.server_ipv4}')
                    pkt.{field} = {fuzz_code}
                    send(pkt/TCP(dport=80), verbose=0{iface_option})
                    print(f'Sent IPv4 fuzzing packet {{i+1}}/{count} to {self.server_ipv4} (fuzzing IP.{field})')
                "
                """
            elif layer == "tcp":
                scapy_command = f"""python3 -c "
                from scapy.all import IP, TCP, send, RandNum
                for i in range({count}):
                    pkt = TCP(dport=80)
                    pkt.{field} = {fuzz_code}
                    send(IP(dst='{self.server_ipv4}')/pkt, verbose=0{iface_option})
                    print(f'Sent IPv4 fuzzing packet {{i+1}}/{count} to {self.server_ipv4} (fuzzing TCP.{field})')
                "
                """
            elif layer == "udp":
                scapy_command = f"""python3 -c "
                from scapy.all import IP, UDP, send, RandNum
                for i in range({count}):
                    pkt = UDP(dport=53)
                    pkt.{field} = {fuzz_code}
                    send(IP(dst='{self.server_ipv4}')/pkt, verbose=0{iface_option})
                    print(f'Sent IPv4 fuzzing packet {{i+1}}/{count} to {self.server_ipv4} (fuzzing UDP.{field})')
                "
                """
            elif layer == "icmp":
                scapy_command = f"""python3 -c "
                from scapy.all import IP, ICMP, send, RandNum
                for i in range({count}):
                    pkt = ICMP()
                    pkt.{field} = {fuzz_code}
                    send(IP(dst='{self.server_ipv4}')/pkt, verbose=0{iface_option})
                    print(f'Sent IPv4 fuzzing packet {{i+1}}/{count} to {self.server_ipv4} (fuzzing ICMP.{field})')
                "
                """
            
            success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
            if not success:
                results.append(f"Failed to generate IPv4 fuzzing traffic: {stderr}")
            else:
                results.append(f"Successfully sent {count} IPv4 fuzzing packets to {self.server_ipv4}")
        
        # Generate IPv6 fuzzing if requested and supported for the layer
        if use_ipv6 and self.server_ipv6 and layer in ["tcp", "udp"]:
            # Create appropriate fuzzing command based on layer
            if layer == "tcp":
                scapy_command = f"""python3 -c "
                from scapy.all import IPv6, TCP, send, RandNum
                for i in range({count}):
                    pkt = TCP(dport=80)
                    pkt.{field} = {fuzz_code}
                    send(IPv6(dst='{self.server_ipv6}')/pkt, verbose=0{iface_option})
                    print(f'Sent IPv6 fuzzing packet {{i+1}}/{count} to {self.server_ipv6} (fuzzing TCP.{field})')
                "
                """
            elif layer == "udp":
                scapy_command = f"""python3 -c "
                from scapy.all import IPv6, UDP, send, RandNum
                for i in range({count}):
                    pkt = UDP(dport=53)
                    pkt.{field} = {fuzz_code}
                    send(IPv6(dst='{self.server_ipv6}')/pkt, verbose=0{iface_option})
                    print(f'Sent IPv6 fuzzing packet {{i+1}}/{count} to {self.server_ipv6} (fuzzing UDP.{field})')
                "
                """
            
            success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
            if not success:
                results.append(f"Failed to generate IPv6 fuzzing traffic: {stderr}")
            else:
                results.append(f"Successfully sent {count} IPv6 fuzzing packets to {self.server_ipv6}")
        
        if not results:
            return False, "No traffic was generated. Check IP addresses and IP version settings."
        
        return len([r for r in results if r.startswith("Successfully")]) > 0, "\n".join(results)
