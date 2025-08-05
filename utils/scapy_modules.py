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
import socket
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
    
    def check_scapy_installed(self) -> Tuple[bool, str]:
        """
        Check if Scapy is installed on the remote host
        
        Returns:
            Tuple of (installed: bool, message: str)
        """
        success, stdout, stderr = self.execute_command("python3 -c 'import scapy' 2>/dev/null && echo 'Scapy installed' || echo 'Scapy not installed'")
        
        if not success:
            return False, f"Failed to check Scapy installation: {stderr}"
        
        if "Scapy installed" in stdout:
            return True, "Scapy is installed"
        else:
            return False, "Scapy is not installed. Please install it using: sudo pip3 install scapy"


class ScapyTrafficGenerator:
    """
    Class for generating network traffic using Scapy on remote hosts
    """
    def __init__(self, client_ssh: SSHClient, server_ssh: SSHClient):
        """
        Initialize traffic generator with SSH clients for client and server
        
        Args:
            client_ssh: SSHClient instance for the client machine
            server_ssh: SSHClient instance for the server machine
        """
        self.client_ssh = client_ssh
        self.server_ssh = server_ssh
    
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
        # Get server IP
        success, stdout, stderr = self.server_ssh.execute_command("hostname -I | awk '{print $1}'")
        if not success or not stdout.strip():
            return False, f"Failed to get server IP address: {stderr}"
        server_ip = stdout.strip()
        
        # Generate ICMP traffic using Scapy
        scapy_command = f"""python3 -c "
from scapy.all import IP, ICMP, send
for i in range({count}):
    send(IP(dst='{server_ip}')/ICMP(), verbose=0)
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
        # Get server IP
        success, stdout, stderr = self.server_ssh.execute_command("hostname -I | awk '{print $1}'")
        if not success or not stdout.strip():
            return False, f"Failed to get server IP address: {stderr}"
        server_ip = stdout.strip()
        
        # Generate TCP traffic using Scapy
        scapy_command = f"""python3 -c "
from scapy.all import IP, TCP, send
for i in range({count}):
    send(IP(dst='{server_ip}')/TCP(dport={port}, flags='S'), verbose=0)
    print(f'Sent TCP SYN packet {{i+1}}/{count} to {server_ip}:{port}')
"
"""
        success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
        if not success:
            return False, f"Failed to generate TCP traffic: {stderr}"
        
        return True, f"Successfully sent {count} TCP packets to {server_ip}:{port}"
    
    def generate_udp_traffic(self, port: int = 53, count: int = 10) -> Tuple[bool, str]:
        """
        Generate UDP traffic from client to server
        
        Args:
            port: UDP port to target
            count: Number of UDP packets to send
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Get server IP
        success, stdout, stderr = self.server_ssh.execute_command("hostname -I | awk '{print $1}'")
        if not success or not stdout.strip():
            return False, f"Failed to get server IP address: {stderr}"
        server_ip = stdout.strip()
        
        # Generate UDP traffic using Scapy
        scapy_command = f"""python3 -c "
from scapy.all import IP, UDP, send
for i in range({count}):
    send(IP(dst='{server_ip}')/UDP(dport={port}), verbose=0)
    print(f'Sent UDP packet {{i+1}}/{count} to {server_ip}:{port}')
"
"""
        success, stdout, stderr = self.client_ssh.execute_command(scapy_command)
        if not success:
            return False, f"Failed to generate UDP traffic: {stderr}"
        
        return True, f"Successfully sent {count} UDP packets to {server_ip}:{port}"
