#!/usr/bin/env python3
"""
Scapy Traffic Generator
This script generates network traffic between Ubuntu client and server using Scapy.
"""

import os
import sys
import time
import logging
import argparse
from typing import Dict, List, Tuple, Optional, Union, Any

# Import modules from utils
from utils.scapy_modules import SSHClient, ScapyTrafficGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('scapy_traffic_generator.log')
    ]
)
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Scapy Traffic Generator')
    
    # SSH connection parameters
    parser.add_argument('--client-ip', required=True, help='Client SSH IP address')
    parser.add_argument('--client-port', type=int, default=22, help='Client SSH port (default: 22)')
    parser.add_argument('--client-user', required=True, help='Client SSH username')
    parser.add_argument('--client-pass', required=True, help='Client SSH password')
    
    parser.add_argument('--server-ip', required=True, help='Server SSH IP address')
    parser.add_argument('--server-port', type=int, default=22, help='Server SSH port (default: 22)')
    parser.add_argument('--server-user', required=True, help='Server SSH username')
    parser.add_argument('--server-pass', required=True, help='Server SSH password')
    
    # Traffic generation parameters
    parser.add_argument('--traffic-type', choices=['icmp', 'tcp', 'udp', 'all'], default='icmp',
                        help='Type of traffic to generate (default: icmp)')
    parser.add_argument('--count', type=int, default=10, help='Number of packets to send (default: 10)')
    parser.add_argument('--port', type=int, default=80, help='Port for TCP/UDP traffic (default: 80)')
    
    # Action to perform
    parser.add_argument('--action', choices=['connect', 'check', 'generate'], default='connect',
                        help='Action to perform (default: connect)')
    
    return parser.parse_args()

def test_ssh_connection(host_type: str, ip: str, port: int, username: str, password: str) -> Tuple[bool, str, Optional[SSHClient]]:
    """
    Test SSH connection to a host
    
    Args:
        host_type: Type of host ('client' or 'server')
        ip: SSH server IP address
        port: SSH server port
        username: SSH username
        password: SSH password
        
    Returns:
        Tuple of (success: bool, message: str, ssh_client: Optional[SSHClient])
    """
    logger.info(f"Testing SSH connection to {host_type} ({ip}:{port})")
    
    ssh_client = SSHClient(ip, port, username, password)
    success, message = ssh_client.connect()
    
    if success:
        # Check if Scapy is installed
        scapy_installed, scapy_message = ssh_client.check_scapy_installed()
        if not scapy_installed:
            logger.warning(f"Scapy not installed on {host_type}: {scapy_message}")
            return False, scapy_message, ssh_client
        
        logger.info(f"Successfully connected to {host_type} ({ip}:{port})")
        return True, f"Successfully connected to {host_type} ({ip}:{port})", ssh_client
    else:
        logger.error(f"Failed to connect to {host_type} ({ip}:{port}): {message}")
        return False, message, None

def main():
    """Main function"""
    args = parse_arguments()
    
    # Test SSH connections
    client_success, client_message, client_ssh = test_ssh_connection(
        'client', args.client_ip, args.client_port, args.client_user, args.client_pass
    )
    
    server_success, server_message, server_ssh = test_ssh_connection(
        'server', args.server_ip, args.server_port, args.server_user, args.server_pass
    )
    
    # Check if both connections were successful
    if not client_success or not server_success:
        logger.error("Failed to connect to client or server")
        if client_ssh:
            client_ssh.disconnect()
        if server_ssh:
            server_ssh.disconnect()
        return 1
    
    # Create traffic generator
    traffic_gen = ScapyTrafficGenerator(client_ssh, server_ssh)
    
    try:
        # Perform requested action
        if args.action == 'connect':
            logger.info("SSH connections successful")
            print("SSH connections successful to both client and server")
        
        elif args.action == 'check':
            # Check connectivity between client and server
            success, message = traffic_gen.check_connectivity()
            if success:
                logger.info(message)
                print(message)
            else:
                logger.error(message)
                print(f"Error: {message}")
                return 1
        
        elif args.action == 'generate':
            # Generate traffic based on type
            if args.traffic_type == 'icmp' or args.traffic_type == 'all':
                success, message = traffic_gen.generate_icmp_traffic(args.count)
                logger.info(message if success else f"Error: {message}")
                print(message if success else f"Error: {message}")
                
            if args.traffic_type == 'tcp' or args.traffic_type == 'all':
                success, message = traffic_gen.generate_tcp_traffic(args.port, args.count)
                logger.info(message if success else f"Error: {message}")
                print(message if success else f"Error: {message}")
                
            if args.traffic_type == 'udp' or args.traffic_type == 'all':
                success, message = traffic_gen.generate_udp_traffic(args.port, args.count)
                logger.info(message if success else f"Error: {message}")
                print(message if success else f"Error: {message}")
    
    finally:
        # Clean up connections
        if client_ssh:
            client_ssh.disconnect()
        if server_ssh:
            server_ssh.disconnect()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
