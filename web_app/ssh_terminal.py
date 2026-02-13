import asyncio
import websockets
import paramiko
import threading
import json
import base64
import re
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Store active SSH sessions
active_sessions = {}

class SSHTerminal:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.client = None
        self.channel = None
        self.ws = None
        self.running = False
        self.read_task = None
        
    async def connect(self):
        """Establish SSH connection"""
        try:
            logger.info(f"Creating SSH client for {self.host}:{self.port}")
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10
            )
            
            logger.info("Connection successful, creating shell")
            self.channel = self.client.invoke_shell(term='xterm')
            self.channel.settimeout(0)
            self.running = True
            logger.info("SSH connection and shell established")
            return True
        except Exception as e:
            logger.error(f"SSH connection error: {str(e)}")
            return {"error": str(e)}
            
    async def start_session(self, websocket):
        """Start the SSH session with WebSocket connection"""
        self.ws = websocket
        
        # Start reading from SSH in a separate task
        self.read_task = asyncio.create_task(self.read_ssh_output())
        
        try:
            # Process incoming WebSocket messages
            async for message in websocket:
                if not self.running:
                    break
                    
                try:
                    data = json.loads(message)
                    if data.get("type") == "resize":
                        cols = data.get("cols", 80)
                        rows = data.get("rows", 24)
                        self.channel.resize_pty(width=cols, height=rows)
                    elif data.get("type") == "input":
                        input_data = data.get("data", "")
                        self.channel.send(input_data)
                except Exception as e:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "data": str(e)
                    }))
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.close_session()
    
    async def read_ssh_output(self):
        """Read data from SSH channel and send to WebSocket"""
        try:
            while self.running and self.channel and self.ws:
                try:
                    if self.channel.recv_ready():
                        data = self.channel.recv(4096).decode('utf-8', errors='replace')
                        if data:
                            await self.ws.send(json.dumps({
                                "type": "output",
                                "data": data
                            }))
                    else:
                        # Check if channel is closed
                        if self.channel.exit_status_ready():
                            break
                        await asyncio.sleep(0.05)
                except Exception as e:
                    await self.ws.send(json.dumps({
                        "type": "error",
                        "data": str(e)
                    }))
                    break
        except Exception as e:
            if self.ws and self.ws.open:
                await self.ws.send(json.dumps({
                    "type": "error", 
                    "data": f"SSH read error: {str(e)}"
                }))
        finally:
            if self.running:
                await self.close_session()
    
    async def close_session(self):
        """Close the SSH session"""
        self.running = False
        
        # Cancel read task if running
        if self.read_task and not self.read_task.done():
            self.read_task.cancel()
            try:
                await self.read_task
            except asyncio.CancelledError:
                pass
            
        # Close SSH connection
        if self.channel:
            self.channel.close()
        if self.client:
            self.client.close()
            
        # Send close message to websocket
        if self.ws and self.ws.open:
            await self.ws.send(json.dumps({
                "type": "close",
                "data": "Connection closed"
            }))

async def ssh_websocket_handler(websocket):
    """WebSocket handler for SSH terminal sessions"""
    session_id = None
    
    try:
        logger.info("SSH WebSocket handler started")
        # Wait for initial connection message
        logger.info("Waiting for initial connection message")
        message = await websocket.recv()
        logger.info(f"Received initial message: {message[:100]}...")
        data = json.loads(message)
        
        if data.get("type") != "connect":
            await websocket.send(json.dumps({
                "type": "error",
                "data": "Expected connect message"
            }))
            return
            
        # Get connection parameters
        host = data.get("host")
        port = data.get("port", 22)
        username = data.get("username")
        password = data.get("password")
        session_id = data.get("sessionId")
        
        logger.info(f"Connection parameters: host={host}, port={port}, username={username}, session_id={session_id}")
        
        if not all([host, username, password, session_id]):
            error_msg = f"Missing connection parameters: host={bool(host)}, username={bool(username)}, password={bool(password)}, session_id={bool(session_id)}"
            logger.error(error_msg)
            await websocket.send(json.dumps({
                "type": "error",
                "data": error_msg
            }))
            return
        
        # Create and start SSH session
        logger.info(f"Creating SSH terminal for {host}:{port}")
        ssh_terminal = SSHTerminal(host, port, username, password)
        
        logger.info("Attempting SSH connection")
        result = await ssh_terminal.connect()
        
        if isinstance(result, dict) and "error" in result:
            logger.error(f"SSH connection error: {result['error']}")
            await websocket.send(json.dumps({
                "type": "error",
                "data": result["error"]
            }))
            return
        
        logger.info("SSH connection established successfully")
            
        # Store active session
        active_sessions[session_id] = ssh_terminal
        
        # Send connected message
        await websocket.send(json.dumps({
            "type": "connected"
        }))
        
        # Start session processing
        await ssh_terminal.start_session(websocket)
        
    except Exception as e:
        if websocket.open:
            await websocket.send(json.dumps({
                "type": "error",
                "data": str(e)
            }))
    finally:
        # Clean up session
        if session_id and session_id in active_sessions:
            del active_sessions[session_id]
