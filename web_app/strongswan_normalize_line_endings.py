#!/usr/bin/env python3
"""
Helper script to fix line ending issues in strongSwan config files.
This script connects to a strongSwan server, lists all .conf files,
normalizes their line endings to Unix style (LF), and saves them back.

Usage:
python strongswan_normalize_line_endings.py <server_ip> <port> <username> <password>
"""

import sys
import os
from paramiko import SSHClient, AutoAddPolicy
import logging
import getpass

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def normalize_line_endings(server_ip, port, username, password):
    """
    Connect to strongSwan server and normalize line endings in all config files.
    """
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        logger.info(f"Connecting to {server_ip}:{port} as {username}")
        ssh.connect(
            hostname=server_ip,
            port=port,
            username=username,
            password=password,
            timeout=15,
            allow_agent=False,
            look_for_keys=False
        )
        
        # List all config files in /etc/swanctl/conf.d/
        stdin, stdout, stderr = ssh.exec_command('sudo -S ls -1 /etc/swanctl/conf.d/ | grep -E "\.conf$"', get_pty=True)
        stdin.write(password + '\n')
        stdin.flush()
        
        files = stdout.read().decode('utf-8').splitlines()
        logger.info(f"Found {len(files)} config files")
        
        if not files:
            logger.info("No config files found")
            ssh.close()
            return
        
        # Process each file
        sftp = ssh.open_sftp()
        processed = 0
        
        for filename in files:
            try:
                logger.info(f"Processing {filename}")
                
                # Create temp path
                temp_path = f"/tmp/normalize_{filename}"
                
                # Read original file
                stdin, stdout, stderr = ssh.exec_command(f'sudo -S cat /etc/swanctl/conf.d/{filename}', get_pty=True)
                stdin.write(password + '\n')
                stdin.flush()
                
                content = stdout.read().decode('utf-8', errors='replace')
                
                # Normalize line endings
                normalized = content.replace('\r\n', '\n').replace('\r', '\n')
                
                # Check if any changes needed
                if content == normalized:
                    logger.info(f"  No line ending issues found in {filename}")
                    continue
                
                # Write to temp file
                with sftp.file(temp_path, 'w') as f:
                    f.write(normalized)
                
                # Move to destination
                move_cmd = f'sudo -S mv "{temp_path}" "/etc/swanctl/conf.d/{filename}" && sudo -S chown root:root "/etc/swanctl/conf.d/{filename}" && sudo -S chmod 644 "/etc/swanctl/conf.d/{filename}"'
                stdin, stdout, stderr = ssh.exec_command(move_cmd, timeout=30, get_pty=True)
                stdin.write(password + '\n')
                stdin.flush()
                
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    error = stderr.read().decode('utf-8', errors='replace')
                    logger.error(f"  Failed to save file: {error}")
                    continue
                
                logger.info(f"  Fixed line endings in {filename}")
                processed += 1
                
            except Exception as e:
                logger.error(f"  Error processing {filename}: {str(e)}")
        
        sftp.close()
        ssh.close()
        
        logger.info(f"Finished processing {processed} files")
        
    except Exception as e:
        logger.error(f"Connection error: {str(e)}")
        ssh.close()
        return

def main():
    if len(sys.argv) < 3:
        print("Usage: python strongswan_normalize_line_endings.py <server_ip> [<port>] [<username>]")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    username = sys.argv[3] if len(sys.argv) > 3 else input("Username: ")
    password = getpass.getpass("Password: ")
    
    normalize_line_endings(server_ip, port, username, password)

if __name__ == "__main__":
    main()
