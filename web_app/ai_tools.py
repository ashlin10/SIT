"""
AI Tools Module - strongSwan Configuration File Operations

This module defines tools that the AI can use to manage strongSwan configuration files.
All operations are audited and require appropriate permissions.
"""

import os
import re
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timezone
from paramiko import SSHClient, AutoAddPolicy

logger = logging.getLogger(__name__)

# ============================================================================
# Tool Definitions for OpenAI-style Function Calling
# ============================================================================

STRONGSWAN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_config_files",
            "description": "List all strongSwan configuration files in /etc/swanctl/conf.d/",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_config_file",
            "description": "Read the contents of a specific strongSwan configuration file",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Name of the configuration file (must end with .conf)"
                    }
                },
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "validate_config_syntax",
            "description": "Validate the syntax of swanctl.conf configuration content before saving. Returns validation result with any errors found.",
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The configuration content to validate"
                    }
                },
                "required": ["content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_config_file",
            "description": "Save content to a strongSwan configuration file. Creates new file or overwrites existing. IMPORTANT: Always validate syntax first and get user confirmation for overwrites.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Name of the configuration file (must end with .conf)"
                    },
                    "content": {
                        "type": "string",
                        "description": "The configuration content to save"
                    },
                    "user_confirmed": {
                        "type": "boolean",
                        "description": "Whether the user has explicitly confirmed this action"
                    }
                },
                "required": ["filename", "content", "user_confirmed"]
            }
        }
    },
    {
        "type": "function", 
        "function": {
            "name": "delete_config_file",
            "description": "Delete a strongSwan configuration file. DESTRUCTIVE ACTION - requires explicit user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Name of the configuration file to delete"
                    },
                    "user_confirmed": {
                        "type": "boolean",
                        "description": "Whether the user has explicitly confirmed this deletion"
                    }
                },
                "required": ["filename", "user_confirmed"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "edit_config_file",
            "description": "Edit a strongSwan configuration file by performing find-and-replace operations. Can replace all occurrences of a string. Always reads the current file, performs replacements, validates, and saves.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Name of the configuration file to edit (must end with .conf)"
                    },
                    "find": {
                        "type": "string",
                        "description": "The text string to find in the file"
                    },
                    "replace": {
                        "type": "string",
                        "description": "The text string to replace it with"
                    },
                    "replace_all": {
                        "type": "boolean",
                        "description": "If true, replace ALL occurrences. If false, replace only the first occurrence. Defaults to true."
                    },
                    "user_confirmed": {
                        "type": "boolean",
                        "description": "Whether the user has explicitly confirmed this edit"
                    }
                },
                "required": ["filename", "find", "replace", "user_confirmed"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "reload_strongswan_config",
            "description": "Reload strongSwan configuration by running 'swanctl --load-all'. Use after saving configuration changes.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
]

# ============================================================================
# Netplan Tool Definitions
# ============================================================================

NETPLAN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_netplan_files",
            "description": "List all netplan configuration files in /etc/netplan/",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_netplan_file",
            "description": "Read the contents of a specific netplan configuration file",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Name of the netplan file (must end with .yaml or .yml)"}
                },
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_netplan_file",
            "description": "Save content to a netplan configuration file. Creates new or overwrites existing. Requires user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Name of the netplan file (must end with .yaml or .yml)"},
                    "content": {"type": "string", "description": "The YAML configuration content to save"},
                    "user_confirmed": {"type": "boolean", "description": "Whether the user has explicitly confirmed this action"}
                },
                "required": ["filename", "content", "user_confirmed"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "delete_netplan_file",
            "description": "Delete a netplan configuration file. DESTRUCTIVE - requires explicit user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "Name of the netplan file to delete"},
                    "user_confirmed": {"type": "boolean", "description": "Whether the user has explicitly confirmed this deletion"}
                },
                "required": ["filename", "user_confirmed"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "netplan_apply",
            "description": "Execute 'netplan apply' on the connected server to apply netplan configuration changes.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "show_routes",
            "description": "Execute 'route -n' on the connected server to display the current routing table.",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    }
]

# ============================================================================
# Traffic Control Tool Definitions
# ============================================================================

TC_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "tc_show",
            "description": "Show current non-default traffic control (tc) rules on all interfaces (excludes fq_codel, noqueue, mq).",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tc_apply",
            "description": "Execute one or more tc commands on the connected server. Each line must start with 'tc '. Supports multi-line input. Requires user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The tc command(s) to execute. Multiple commands can be separated by newlines. Each must start with 'tc '."},
                    "user_confirmed": {"type": "boolean", "description": "Whether the user has explicitly confirmed this action"}
                },
                "required": ["command", "user_confirmed"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "tc_remove_all",
            "description": "Remove ALL traffic control rules from ALL interfaces, resetting to defaults. DESTRUCTIVE - requires explicit user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "user_confirmed": {"type": "boolean", "description": "Whether the user has explicitly confirmed this action"}
                },
                "required": ["user_confirmed"]
            }
        }
    }
]

# ============================================================================
# General Command Execution Tool
# ============================================================================

GENERAL_CMD_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "execute_command",
            "description": "Execute any shell command on the connected strongSwan server. Use this for read-only commands (ip link show, cat, ls, ifconfig, etc.) without confirmation. For commands that modify state (write, delete, restart, etc.), require user confirmation first.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to execute on the server"},
                    "is_read_only": {"type": "boolean", "description": "True if the command only reads data and does not modify anything. False if it writes/modifies/deletes."},
                    "user_confirmed": {"type": "boolean", "description": "Required to be true for non-read-only commands. Ignored for read-only commands."}
                },
                "required": ["command", "is_read_only"]
            }
        }
    }
]

# ============================================================================
# Tunnel Traffic Tool Definitions
# ============================================================================

TUNNEL_TRAFFIC_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_tunnel_traffic_files",
            "description": "List all files in /var/tmp/tunnel_traffic on the local (strongSwan) or remote server.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side": {"type": "string", "enum": ["local", "remote"], "description": "Which server: 'local' (strongSwan) or 'remote'"}
                },
                "required": ["side"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_tunnel_traffic_file",
            "description": "Read the contents of a file in /var/tmp/tunnel_traffic.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side": {"type": "string", "enum": ["local", "remote"]},
                    "filename": {"type": "string", "description": "Name of the file to read"}
                },
                "required": ["side", "filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_tunnel_traffic_file",
            "description": "Save/create a file in /var/tmp/tunnel_traffic. .sh files are automatically made executable. Requires user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side": {"type": "string", "enum": ["local", "remote"]},
                    "filename": {"type": "string", "description": "Name of the file to save"},
                    "content": {"type": "string", "description": "File content"},
                    "user_confirmed": {"type": "boolean"}
                },
                "required": ["side", "filename", "content", "user_confirmed"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "delete_tunnel_traffic_file",
            "description": "Delete a file from /var/tmp/tunnel_traffic. DESTRUCTIVE - requires user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side": {"type": "string", "enum": ["local", "remote"]},
                    "filename": {"type": "string"},
                    "user_confirmed": {"type": "boolean"}
                },
                "required": ["side", "filename", "user_confirmed"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "execute_tunnel_traffic_script",
            "description": "Execute a .sh script from /var/tmp/tunnel_traffic as a background process. Returns the PID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side": {"type": "string", "enum": ["local", "remote"]},
                    "filename": {"type": "string", "description": "Name of the .sh script to execute"}
                },
                "required": ["side", "filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "kill_tunnel_traffic_script",
            "description": "Kill a running script process by PID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "side": {"type": "string", "enum": ["local", "remote"]},
                    "pid": {"type": "integer", "description": "Process ID to kill"}
                },
                "required": ["side", "pid"]
            }
        }
    }
]

# ============================================================================
# Tunnel Disconnect Report Analysis Tool
# ============================================================================

MONITORING_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_disconnect_report",
            "description": "Read the tunnel disconnect monitoring report from /var/log/tunnel-disconnect-syslog.log on the connected server. Returns the full report content including interval summaries, local logs, and remote logs for tunnel disconnection events.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_disconnect_report",
            "description": "Analyze the tunnel disconnect report to determine why tunnels disconnected. Reads the report, parses disconnect events and associated logs, and returns a structured analysis. Use this when the user asks why tunnels went down or wants a disconnect analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tunnel_filter": {
                        "type": "string",
                        "description": "Optional filter: an IP address, tunnel name, or username to focus the analysis on specific tunnels."
                    }
                },
                "required": []
            }
        }
    }
]


# ============================================================================
# Configuration Syntax Validator
# ============================================================================

class SwanctlConfigValidator:
    """
    Validates swanctl.conf syntax.
    Checks for common errors and proper structure.
    """
    
    # Valid top-level sections
    VALID_SECTIONS = {'connections', 'secrets', 'pools', 'authorities'}
    
    # Valid connection subsections
    CONNECTION_SUBSECTIONS = {'local', 'remote', 'children'}
    
    # Common connection options
    CONNECTION_OPTIONS = {
        'version', 'local_addrs', 'remote_addrs', 'local_port', 'remote_port',
        'proposals', 'vips', 'aggressive', 'pull', 'dscp', 'encap', 'mobike',
        'dpd_delay', 'dpd_timeout', 'fragmentation', 'childless', 'send_certreq',
        'send_cert', 'ocsp', 'ppk_id', 'ppk_required', 'keyingtries', 'unique',
        'reauth_time', 'rekey_time', 'over_time', 'rand_time', 'pools',
        'if_id_in', 'if_id_out', 'mediation', 'mediated_by', 'mediation_peer'
    }
    
    # Local/remote auth options
    AUTH_OPTIONS = {
        'round', 'certs', 'pubkeys', 'auth', 'id', 'eap_id', 'aaa_id', 'xauth_id',
        'groups', 'cert_policy', 'cacerts', 'ca_id', 'revocation'
    }
    
    # Child SA options
    CHILD_OPTIONS = {
        'ah_proposals', 'esp_proposals', 'sha256_96', 'local_ts', 'remote_ts',
        'rekey_time', 'life_time', 'rand_time', 'rekey_bytes', 'life_bytes',
        'rand_bytes', 'rekey_packets', 'life_packets', 'rand_packets', 'updown',
        'hostaccess', 'mode', 'policies', 'policies_fwd_out', 'dpd_action',
        'ipcomp', 'inactivity', 'reqid', 'priority', 'interface', 'mark_in',
        'mark_in_sa', 'mark_out', 'set_mark_in', 'set_mark_out', 'if_id_in',
        'if_id_out', 'label', 'label_mode', 'tfc_padding', 'replay_window',
        'per_cpu_sas', 'hw_offload', 'copy_df', 'copy_ecn', 'copy_dscp',
        'start_action', 'close_action'
    }
    
    def validate(self, content: str) -> Dict[str, Any]:
        """
        Validate swanctl.conf content.
        
        Returns:
            Dict with 'valid' boolean and 'errors' list
        """
        errors = []
        warnings = []
        
        if not content or not content.strip():
            return {"valid": False, "errors": ["Configuration content is empty"]}
        
        lines = content.split('\n')
        
        # Track brace matching
        brace_stack = []
        current_section = None
        line_num = 0
        
        for line in lines:
            line_num += 1
            stripped = line.strip()
            
            # Skip comments and empty lines
            if not stripped or stripped.startswith('#'):
                continue
            
            # Check for opening braces
            if '{' in stripped:
                # Extract section name before brace
                section_match = re.match(r'^(\w+[\w\-<>]*)\s*\{', stripped)
                if section_match:
                    section_name = section_match.group(1)
                    brace_stack.append((section_name, line_num))
                    
                    # Validate top-level sections
                    if len(brace_stack) == 1:
                        if section_name not in self.VALID_SECTIONS:
                            errors.append(f"Line {line_num}: Unknown top-level section '{section_name}'. Valid sections: {', '.join(self.VALID_SECTIONS)}")
                        current_section = section_name
                elif '{' in stripped and not stripped.endswith('}'):
                    brace_stack.append(('anonymous', line_num))
            
            # Check for closing braces
            if '}' in stripped:
                close_count = stripped.count('}')
                open_count = stripped.count('{')
                net_closes = close_count - open_count
                
                for _ in range(net_closes):
                    if brace_stack:
                        brace_stack.pop()
                    else:
                        errors.append(f"Line {line_num}: Unmatched closing brace '}}'"  )
            
            # Check for assignment syntax (key = value)
            if '=' in stripped and not stripped.startswith('#'):
                # Basic key-value validation
                parts = stripped.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    
                    # Warn about empty values (not always an error)
                    if not value:
                        warnings.append(f"Line {line_num}: Empty value for key '{key}'")
        
        # Check for unclosed braces
        if brace_stack:
            for section, open_line in brace_stack:
                errors.append(f"Line {open_line}: Unclosed section '{section}' - missing '}}'"  )
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }


# ============================================================================
# Tool Executor
# ============================================================================

class StrongSwanToolExecutor:
    """
    Executes AI tool calls for strongSwan configuration management.
    Requires an active SSH connection context.
    """
    
    def __init__(self):
        self.validator = SwanctlConfigValidator()
        self.audit_log: List[Dict[str, Any]] = []
    
    def _log_action(self, action: str, username: str, details: Dict[str, Any], success: bool):
        """Log tool action for audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "username": username,
            "details": details,
            "success": success
        }
        self.audit_log.append(entry)
        logger.info(f"AI Tool Action: {action} by {username} - {'SUCCESS' if success else 'FAILED'}")
    
    async def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        connection_info: Dict[str, Any],
        username: str
    ) -> Dict[str, Any]:
        """
        Execute a tool call.
        
        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments
            connection_info: SSH connection details (ip, port, username, password)
            username: User requesting the action
            
        Returns:
            Tool execution result
        """
        try:
            if tool_name == "list_config_files":
                return await self._list_config_files(connection_info, username)
            elif tool_name == "read_config_file":
                return await self._read_config_file(arguments, connection_info, username)
            elif tool_name == "validate_config_syntax":
                return self._validate_config_syntax(arguments, username)
            elif tool_name == "save_config_file":
                return await self._save_config_file(arguments, connection_info, username)
            elif tool_name == "delete_config_file":
                return await self._delete_config_file(arguments, connection_info, username)
            elif tool_name == "edit_config_file":
                return await self._edit_config_file(arguments, connection_info, username)
            elif tool_name == "reload_strongswan_config":
                return await self._reload_config(connection_info, username)
            # Netplan tools
            elif tool_name == "list_netplan_files":
                return await self._list_netplan_files(connection_info, username)
            elif tool_name == "read_netplan_file":
                return await self._read_netplan_file(arguments, connection_info, username)
            elif tool_name == "save_netplan_file":
                return await self._save_netplan_file(arguments, connection_info, username)
            elif tool_name == "delete_netplan_file":
                return await self._delete_netplan_file(arguments, connection_info, username)
            elif tool_name == "netplan_apply":
                return await self._netplan_apply(connection_info, username)
            elif tool_name == "show_routes":
                return await self._show_routes(connection_info, username)
            # Traffic Control tools
            elif tool_name == "tc_show":
                return await self._tc_show(connection_info, username)
            elif tool_name == "tc_apply":
                return await self._tc_apply(arguments, connection_info, username)
            elif tool_name == "tc_remove_all":
                return await self._tc_remove_all(arguments, connection_info, username)
            # General command execution
            elif tool_name == "execute_command":
                return await self._execute_command(arguments, connection_info, username)
            # Tunnel Traffic tools
            elif tool_name == "list_tunnel_traffic_files":
                return await self._list_tt_files(arguments, connection_info, username)
            elif tool_name == "read_tunnel_traffic_file":
                return await self._read_tt_file(arguments, connection_info, username)
            elif tool_name == "save_tunnel_traffic_file":
                return await self._save_tt_file(arguments, connection_info, username)
            elif tool_name == "delete_tunnel_traffic_file":
                return await self._delete_tt_file(arguments, connection_info, username)
            elif tool_name == "execute_tunnel_traffic_script":
                return await self._execute_tt_script(arguments, connection_info, username)
            elif tool_name == "kill_tunnel_traffic_script":
                return await self._kill_tt_script(arguments, connection_info, username)
            # Monitoring / Report tools
            elif tool_name == "read_disconnect_report":
                return await self._read_disconnect_report(connection_info, username)
            elif tool_name == "analyze_disconnect_report":
                return await self._analyze_disconnect_report(arguments, connection_info, username)
            else:
                return {"success": False, "error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            logger.error(f"Tool execution error ({tool_name}): {e}")
            return {"success": False, "error": str(e)}
    
    async def _list_config_files(self, conn_info: Dict, username: str) -> Dict[str, Any]:
        """List configuration files."""
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
            
            list_cmd = "ls -la /etc/swanctl/conf.d/*.conf 2>/dev/null || ls -la /etc/swanctl/conf.d/ 2>/dev/null"
            stdin, stdout, stderr = ssh.exec_command(list_cmd, timeout=15)
            output = stdout.read().decode('utf-8', errors='replace')
            
            files = []
            for line in output.strip().split('\n'):
                if not line or line.startswith('total'):
                    continue
                parts = line.split()
                if len(parts) >= 9:
                    filepath = parts[-1]
                    filename = os.path.basename(filepath)
                    if filename.endswith('.conf'):
                        size = int(parts[4]) if parts[4].isdigit() else 0
                        files.append({"name": filename, "size": size})
            
            ssh.close()
            self._log_action("list_config_files", username, {"file_count": len(files)}, True)
            
            return {
                "success": True,
                "files": files,
                "message": f"Found {len(files)} configuration file(s)"
            }
        except Exception as e:
            ssh.close() if ssh else None
            self._log_action("list_config_files", username, {"error": str(e)}, False)
            return {"success": False, "error": str(e)}
    
    async def _read_config_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        """Read a configuration file."""
        filename = args.get("filename", "")
        
        # Security validation
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename - path traversal not allowed"}
        if not filename.endswith('.conf'):
            return {"success": False, "error": "Filename must end with .conf"}
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
            
            cat_cmd = f'sudo -S cat "/etc/swanctl/conf.d/{filename}"'
            stdin, stdout, stderr = ssh.exec_command(cat_cmd, timeout=30, get_pty=True)
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            
            content = stdout.read().decode('utf-8', errors='replace')
            # Clean sudo artifacts from output
            lines = content.split('\n')
            clean_lines = [l for l in lines if not l.startswith('[sudo]') and not l.startswith('sudo:') and conn_info['password'] not in l]
            content = '\n'.join(clean_lines).strip()
            
            ssh.close()
            self._log_action("read_config_file", username, {"filename": filename}, True)
            
            return {
                "success": True,
                "filename": filename,
                "content": content
            }
        except Exception as e:
            ssh.close() if ssh else None
            self._log_action("read_config_file", username, {"filename": filename, "error": str(e)}, False)
            return {"success": False, "error": str(e)}
    
    def _validate_config_syntax(self, args: Dict, username: str) -> Dict[str, Any]:
        """Validate configuration syntax."""
        content = args.get("content", "")
        
        result = self.validator.validate(content)
        self._log_action("validate_config_syntax", username, {"valid": result["valid"]}, True)
        
        return {
            "success": True,
            "valid": result["valid"],
            "errors": result.get("errors", []),
            "warnings": result.get("warnings", [])
        }
    
    async def _save_config_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        """Save a configuration file."""
        filename = args.get("filename", "")
        content = args.get("content", "")
        user_confirmed = args.get("user_confirmed", False)
        
        # Security validation
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename - path traversal not allowed"}
        if not filename.endswith('.conf'):
            return {"success": False, "error": "Filename must end with .conf"}
        
        # Require user confirmation
        if not user_confirmed:
            return {
                "success": False,
                "error": "User confirmation required. Please confirm you want to save this file.",
                "requires_confirmation": True
            }
        
        # Validate syntax first
        validation = self.validator.validate(content)
        if not validation["valid"]:
            return {
                "success": False,
                "error": "Configuration syntax validation failed",
                "validation_errors": validation["errors"]
            }
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Use SFTP to write to temp file, then sudo mv
            sftp = ssh.open_sftp()
            temp_path = f"/tmp/swanctl_ai_{filename}"
            
            # Normalize line endings to Unix style (LF only)
            normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')
            
            with sftp.file(temp_path, 'w') as f:
                f.write(normalized_content)
            sftp.close()
            
            # Move with sudo
            move_cmd = f'sudo -S mv "{temp_path}" "/etc/swanctl/conf.d/{filename}" && sudo -S chown root:root "/etc/swanctl/conf.d/{filename}" && sudo -S chmod 644 "/etc/swanctl/conf.d/{filename}"'
            stdin, stdout, stderr = ssh.exec_command(move_cmd, timeout=30, get_pty=True)
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            
            exit_status = stdout.channel.recv_exit_status()
            ssh.close()
            
            if exit_status != 0:
                self._log_action("save_config_file", username, {"filename": filename, "error": "Move failed"}, False)
                return {"success": False, "error": "Failed to save file - permission denied"}
            
            self._log_action("save_config_file", username, {"filename": filename, "size": len(content)}, True)
            
            return {
                "success": True,
                "message": f"Configuration file '{filename}' saved successfully",
                "filename": filename
            }
        except Exception as e:
            ssh.close() if ssh else None
            self._log_action("save_config_file", username, {"filename": filename, "error": str(e)}, False)
            return {"success": False, "error": str(e)}
    
    async def _edit_config_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        """Edit a configuration file with find-and-replace."""
        filename = args.get("filename", "")
        find_str = args.get("find", "")
        replace_str = args.get("replace", "")
        replace_all = args.get("replace_all", True)
        user_confirmed = args.get("user_confirmed", False)
        
        # Security validation
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename - path traversal not allowed"}
        if not filename.endswith('.conf'):
            return {"success": False, "error": "Filename must end with .conf"}
        if not find_str:
            return {"success": False, "error": "'find' parameter is required"}
        
        # Require user confirmation
        if not user_confirmed:
            return {
                "success": False,
                "error": f"User confirmation required to edit '{filename}'. Please confirm.",
                "requires_confirmation": True
            }
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Read current file content
            cat_cmd = f'sudo -S cat "/etc/swanctl/conf.d/{filename}"'
            stdin, stdout, stderr = ssh.exec_command(cat_cmd, timeout=30, get_pty=True)
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            
            content = stdout.read().decode('utf-8', errors='replace')
            # Clean sudo artifacts
            lines = content.split('\n')
            clean_lines = [l for l in lines if not l.startswith('[sudo]') and not l.startswith('sudo:') and conn_info['password'] not in l]
            content = '\n'.join(clean_lines).strip()
            
            if not content:
                ssh.close()
                return {"success": False, "error": f"File '{filename}' is empty or could not be read"}
            
            # Count occurrences
            count = content.count(find_str)
            if count == 0:
                ssh.close()
                return {"success": False, "error": f"String '{find_str}' not found in '{filename}'"}
            
            # Perform replacement
            if replace_all:
                new_content = content.replace(find_str, replace_str)
                replaced_count = count
            else:
                new_content = content.replace(find_str, replace_str, 1)
                replaced_count = 1
            
            # Validate the modified content
            validation = self.validator.validate(new_content)
            if not validation["valid"]:
                ssh.close()
                return {
                    "success": False,
                    "error": "Modified configuration has syntax errors",
                    "validation_errors": validation["errors"]
                }
            
            # Write modified content
            sftp = ssh.open_sftp()
            temp_path = f"/tmp/swanctl_ai_{filename}"
            
            with sftp.file(temp_path, 'w') as f:
                f.write(new_content)
            sftp.close()
            
            # Move with sudo
            move_cmd = f'sudo -S mv "{temp_path}" "/etc/swanctl/conf.d/{filename}" && sudo -S chown root:root "/etc/swanctl/conf.d/{filename}" && sudo -S chmod 644 "/etc/swanctl/conf.d/{filename}"'
            stdin, stdout, stderr = ssh.exec_command(move_cmd, timeout=30, get_pty=True)
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            
            exit_status = stdout.channel.recv_exit_status()
            ssh.close()
            
            if exit_status != 0:
                self._log_action("edit_config_file", username, {"filename": filename, "error": "Save failed"}, False)
                return {"success": False, "error": "Failed to save edited file - permission denied"}
            
            self._log_action("edit_config_file", username, {
                "filename": filename, "find": find_str, "replace": replace_str,
                "replacements": replaced_count
            }, True)
            
            return {
                "success": True,
                "message": f"Successfully replaced {replaced_count} occurrence(s) of '{find_str}' with '{replace_str}' in '{filename}'",
                "filename": filename,
                "replacements": replaced_count
            }
        except Exception as e:
            ssh.close() if ssh else None
            self._log_action("edit_config_file", username, {"filename": filename, "error": str(e)}, False)
            return {"success": False, "error": str(e)}

    async def _delete_config_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        """Delete a configuration file."""
        filename = args.get("filename", "")
        user_confirmed = args.get("user_confirmed", False)
        
        # Security validation
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename - path traversal not allowed"}
        if not filename.endswith('.conf'):
            return {"success": False, "error": "Filename must end with .conf"}
        
        # REQUIRE explicit confirmation for deletion
        if not user_confirmed:
            return {
                "success": False,
                "error": f"⚠️ DESTRUCTIVE ACTION: You are about to delete '{filename}'. This cannot be undone. Please explicitly confirm this deletion.",
                "requires_confirmation": True,
                "action": "delete",
                "filename": filename
            }
        
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
            
            delete_cmd = f'sudo -S rm "/etc/swanctl/conf.d/{filename}"'
            stdin, stdout, stderr = ssh.exec_command(delete_cmd, timeout=30, get_pty=True)
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            
            exit_status = stdout.channel.recv_exit_status()
            ssh.close()
            
            if exit_status != 0:
                self._log_action("delete_config_file", username, {"filename": filename, "error": "Delete failed"}, False)
                return {"success": False, "error": "Failed to delete file"}
            
            self._log_action("delete_config_file", username, {"filename": filename}, True)
            
            return {
                "success": True,
                "message": f"Configuration file '{filename}' deleted successfully"
            }
        except Exception as e:
            ssh.close() if ssh else None
            self._log_action("delete_config_file", username, {"filename": filename, "error": str(e)}, False)
            return {"success": False, "error": str(e)}
    
    async def _reload_config(self, conn_info: Dict, username: str) -> Dict[str, Any]:
        """Reload strongSwan configuration."""
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            ssh.connect(
                hostname=conn_info['ip'],
                port=conn_info['port'],
                username=conn_info['username'],
                password=conn_info['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False
            )
            
            reload_cmd = 'sudo -S swanctl --load-all'
            stdin, stdout, stderr = ssh.exec_command(reload_cmd, timeout=60, get_pty=True)
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            
            output = stdout.read().decode('utf-8', errors='replace')
            error = stderr.read().decode('utf-8', errors='replace')
            exit_status = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            # Clean output
            lines = output.split('\n')
            clean_lines = [l for l in lines if not l.startswith('[sudo]') and not l.startswith('sudo:') and conn_info['password'] not in l]
            clean_output = '\n'.join(clean_lines).strip()
            
            self._log_action("reload_strongswan_config", username, {"exit_status": exit_status}, exit_status == 0)
            
            return {
                "success": exit_status == 0,
                "output": clean_output,
                "message": "Configuration reloaded successfully" if exit_status == 0 else "Reload failed"
            }
        except Exception as e:
            ssh.close() if ssh else None
            self._log_action("reload_strongswan_config", username, {"error": str(e)}, False)
            return {"success": False, "error": str(e)}

    # ========================================================================
    # SSH Helper
    # ========================================================================
    def _ssh_open(self, conn_info: Dict):
        """Open SSH connection and return client."""
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(
            hostname=conn_info['ip'], port=conn_info['port'],
            username=conn_info['username'], password=conn_info['password'],
            timeout=15, allow_agent=False, look_for_keys=False
        )
        return ssh

    def _ssh_sudo(self, ssh, cmd, password, timeout=30):
        """Run sudo command, return cleaned output and exit status."""
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout, get_pty=True)
        stdin.write(password + '\n')
        stdin.flush()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        exit_status = stdout.channel.recv_exit_status()
        lines = output.split('\n')
        clean = [l for l in lines if not l.startswith('[sudo]') and not l.startswith('sudo:') and password not in l]
        return '\n'.join(clean).strip(), error, exit_status

    # ========================================================================
    # Netplan Executor Methods
    # ========================================================================
    async def _list_netplan_files(self, conn_info: Dict, username: str) -> Dict[str, Any]:
        ssh = self._ssh_open(conn_info)
        try:
            stdin, stdout, stderr = ssh.exec_command(
                "ls -la /etc/netplan/*.yaml /etc/netplan/*.yml /etc/netplan/.*.yaml /etc/netplan/.*.yml 2>/dev/null || ls -la /etc/netplan/ 2>/dev/null",
                timeout=15)
            output = stdout.read().decode('utf-8', errors='replace')
            ssh.close()
            files = []
            seen = set()
            for line in output.strip().split('\n'):
                if not line or line.startswith('total'):
                    continue
                parts = line.split()
                if len(parts) >= 9:
                    filename = os.path.basename(parts[-1])
                    if (filename.endswith('.yaml') or filename.endswith('.yml')) and filename not in seen:
                        seen.add(filename)
                        size = int(parts[4]) if parts[4].isdigit() else 0
                        files.append({"name": filename, "size": size})
            self._log_action("list_netplan_files", username, {"count": len(files)}, True)
            return {"success": True, "files": files, "message": f"Found {len(files)} netplan file(s)"}
        except Exception as e:
            ssh.close() if ssh else None
            self._log_action("list_netplan_files", username, {"error": str(e)}, False)
            return {"success": False, "error": str(e)}

    async def _read_netplan_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        filename = args.get("filename", "")
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename"}
        if not filename.endswith('.yaml') and not filename.endswith('.yml'):
            return {"success": False, "error": "Filename must end with .yaml or .yml"}
        ssh = self._ssh_open(conn_info)
        try:
            output, error, _ = self._ssh_sudo(ssh, f'sudo -S cat "/etc/netplan/{filename}"', conn_info['password'])
            ssh.close()
            self._log_action("read_netplan_file", username, {"filename": filename}, True)
            return {"success": True, "filename": filename, "content": output}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _save_netplan_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        filename = args.get("filename", "")
        content = args.get("content", "")
        user_confirmed = args.get("user_confirmed", False)
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename"}
        if not filename.endswith('.yaml') and not filename.endswith('.yml'):
            return {"success": False, "error": "Filename must end with .yaml or .yml"}
        if not user_confirmed:
            return {"success": False, "error": "User confirmation required.", "requires_confirmation": True}
        ssh = self._ssh_open(conn_info)
        try:
            sftp = ssh.open_sftp()
            temp_path = f"/tmp/netplan_ai_{filename}"
            normalized = content.replace('\r\n', '\n').replace('\r', '\n')
            with sftp.file(temp_path, 'w') as f:
                f.write(normalized)
            sftp.close()
            move_cmd = f'sudo -S mv "{temp_path}" "/etc/netplan/{filename}" && sudo -S chown root:root "/etc/netplan/{filename}" && sudo -S chmod 600 "/etc/netplan/{filename}"'
            _, error, exit_status = self._ssh_sudo(ssh, move_cmd, conn_info['password'])
            ssh.close()
            if exit_status != 0:
                self._log_action("save_netplan_file", username, {"filename": filename, "error": "Move failed"}, False)
                return {"success": False, "error": "Failed to save file - permission denied"}
            self._log_action("save_netplan_file", username, {"filename": filename}, True)
            return {"success": True, "message": f"Netplan file '{filename}' saved successfully"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _delete_netplan_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        filename = args.get("filename", "")
        user_confirmed = args.get("user_confirmed", False)
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename"}
        if not user_confirmed:
            return {"success": False, "error": f"User confirmation required to delete '{filename}'.", "requires_confirmation": True}
        ssh = self._ssh_open(conn_info)
        try:
            _, error, exit_status = self._ssh_sudo(ssh, f'sudo -S rm "/etc/netplan/{filename}"', conn_info['password'])
            ssh.close()
            if exit_status != 0:
                return {"success": False, "error": "Failed to delete file"}
            self._log_action("delete_netplan_file", username, {"filename": filename}, True)
            return {"success": True, "message": f"Netplan file '{filename}' deleted successfully"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _netplan_apply(self, conn_info: Dict, username: str) -> Dict[str, Any]:
        ssh = self._ssh_open(conn_info)
        try:
            output, error, exit_status = self._ssh_sudo(ssh, 'sudo -S netplan apply 2>&1', conn_info['password'], timeout=60)
            ssh.close()
            self._log_action("netplan_apply", username, {"exit_status": exit_status}, exit_status == 0)
            return {
                "success": exit_status == 0,
                "output": output or error or "(no output)",
                "message": "Netplan applied successfully" if exit_status == 0 else "Netplan apply failed"
            }
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _show_routes(self, conn_info: Dict, username: str) -> Dict[str, Any]:
        ssh = self._ssh_open(conn_info)
        try:
            output, error, exit_status = self._ssh_sudo(ssh, 'route -n 2>&1', conn_info['password'])
            ssh.close()
            self._log_action("show_routes", username, {}, True)
            return {"success": True, "output": output or error or "(no output)"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    # ========================================================================
    # Traffic Control Executor Methods
    # ========================================================================
    async def _tc_show(self, conn_info: Dict, username: str) -> Dict[str, Any]:
        ssh = self._ssh_open(conn_info)
        try:
            output, error, _ = self._ssh_sudo(ssh, 'sudo -S bash -c \'tc qdisc show | grep -Ev "fq_codel|noqueue|mq"\' 2>&1', conn_info['password'])
            ssh.close()
            self._log_action("tc_show", username, {}, True)
            return {"success": True, "output": output or "(no non-default tc rules found)"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _tc_apply(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        raw_input = args.get("command", "").strip()
        user_confirmed = args.get("user_confirmed", False)
        commands = [c.strip() for c in raw_input.split('\n') if c.strip()]
        if not commands:
            return {"success": False, "error": "No commands provided"}
        for cmd in commands:
            if not cmd.startswith('tc '):
                return {"success": False, "error": f"Every line must start with 'tc ': {cmd}"}
            for bad in [';', '&&', '||', '|', '`', '$(', '>', '<']:
                if bad in cmd:
                    return {"success": False, "error": f"Invalid character in command: {bad}"}
        if not user_confirmed:
            return {"success": False, "error": "User confirmation required.", "requires_confirmation": True}
        ssh = self._ssh_open(conn_info)
        try:
            all_output = []
            all_success = True
            for cmd in commands:
                output, error, exit_status = self._ssh_sudo(ssh, f'sudo -S {cmd} 2>&1', conn_info['password'])
                result_line = f"$ {cmd}\n{output or error or '(ok)'}" if exit_status == 0 else f"$ {cmd}\nFAILED: {output or error}"
                all_output.append(result_line)
                if exit_status != 0:
                    all_success = False
            ssh.close()
            combined = '\n\n'.join(all_output)
            self._log_action("tc_apply", username, {"commands": commands, "success": all_success}, all_success)
            return {
                "success": all_success,
                "output": combined,
                "message": f"All {len(commands)} command(s) executed successfully" if all_success else "One or more commands failed"
            }
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _tc_remove_all(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        user_confirmed = args.get("user_confirmed", False)
        if not user_confirmed:
            return {"success": False, "error": "User confirmation required to remove ALL tc rules.", "requires_confirmation": True}
        ssh = self._ssh_open(conn_info)
        try:
            iface_out, _, _ = self._ssh_sudo(ssh, "ip -o link show | awk -F': ' '{print $2}' | grep -v lo", conn_info['password'])
            interfaces = [i.strip() for i in iface_out.split('\n') if i.strip()]
            removed = []
            for iface in interfaces[:20]:
                _, _, exit_status = self._ssh_sudo(ssh, f'sudo -S tc qdisc del dev {iface} root 2>&1', conn_info['password'])
                if exit_status == 0:
                    removed.append(iface)
            ssh.close()
            self._log_action("tc_remove_all", username, {"removed": removed}, True)
            return {
                "success": True,
                "output": f"Removed tc rules from {len(removed)} interface(s): {', '.join(removed)}" if removed else "No tc rules to remove"
            }
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    # ========================================================================
    # General Command Execution
    # ========================================================================
    async def _execute_command(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        command = args.get("command", "").strip()
        is_read_only = args.get("is_read_only", False)
        user_confirmed = args.get("user_confirmed", False)
        if not command:
            return {"success": False, "error": "No command provided"}
        if not is_read_only and not user_confirmed:
            return {"success": False, "error": "This command modifies the system. Please confirm you want to proceed.", "requires_confirmation": True}
        ssh = self._ssh_open(conn_info)
        try:
            output, error, exit_status = self._ssh_sudo(ssh, f'sudo -S bash -c \'{command}\' 2>&1', conn_info['password'], timeout=30)
            ssh.close()
            self._log_action("execute_command", username, {"command": command, "read_only": is_read_only, "exit_status": exit_status}, exit_status == 0)
            return {
                "success": exit_status == 0,
                "output": output or error or "(no output)",
                "exit_status": exit_status
            }
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    # ========================================================================
    # Tunnel Traffic Executor Methods
    # ========================================================================
    def _tt_get_conn(self, args, conn_info, username):
        """Get the right SSH connection info for local or remote side."""
        side = args.get("side", "local")
        if side == "local":
            return conn_info, side
        else:
            # For remote, we need the remote_tunnel_connections from app.py
            # Since AI tools run through the app endpoint, we import it dynamically
            from app import remote_tunnel_connections
            remote_conn = remote_tunnel_connections.get(username)
            if not remote_conn:
                return None, side
            return remote_conn, side

    async def _list_tt_files(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        tt_conn, side = self._tt_get_conn(args, conn_info, username)
        if not tt_conn:
            return {"success": False, "error": f"Not connected to {side} server"}
        ssh = self._ssh_open(tt_conn)
        try:
            TT_DIR = "/var/tmp/tunnel_traffic"
            self._ssh_sudo(ssh, f'sudo -S mkdir -p {TT_DIR}', tt_conn['password'])
            output, _, _ = self._ssh_sudo(ssh, f'sudo -S ls -la {TT_DIR}/ 2>/dev/null', tt_conn['password'])
            ssh.close()
            files = []
            for line in output.strip().split('\n'):
                if not line or line.startswith('total'):
                    continue
                parts = line.split()
                if len(parts) >= 9:
                    fn = parts[-1]
                    if fn in ('.', '..'):
                        continue
                    size = int(parts[4]) if parts[4].isdigit() else 0
                    files.append({"name": fn, "size": size})
            return {"success": True, "files": files, "side": side, "message": f"Found {len(files)} file(s) on {side}"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _read_tt_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        tt_conn, side = self._tt_get_conn(args, conn_info, username)
        if not tt_conn:
            return {"success": False, "error": f"Not connected to {side} server"}
        filename = args.get("filename", "")
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename"}
        ssh = self._ssh_open(tt_conn)
        try:
            output, _, _ = self._ssh_sudo(ssh, f'sudo -S cat "/var/tmp/tunnel_traffic/{filename}"', tt_conn['password'])
            ssh.close()
            return {"success": True, "filename": filename, "side": side, "content": output}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _save_tt_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        tt_conn, side = self._tt_get_conn(args, conn_info, username)
        if not tt_conn:
            return {"success": False, "error": f"Not connected to {side} server"}
        filename = args.get("filename", "")
        content = args.get("content", "")
        user_confirmed = args.get("user_confirmed", False)
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename"}
        if not user_confirmed:
            return {"success": False, "error": "User confirmation required.", "requires_confirmation": True}
        ssh = self._ssh_open(tt_conn)
        try:
            TT_DIR = "/var/tmp/tunnel_traffic"
            self._ssh_sudo(ssh, f'sudo -S mkdir -p {TT_DIR}', tt_conn['password'])
            sftp = ssh.open_sftp()
            temp_path = f"/tmp/tt_ai_{filename}"
            normalized = content.replace('\r\n', '\n').replace('\r', '\n')
            with sftp.file(temp_path, 'w') as f:
                f.write(normalized)
            sftp.close()
            self._ssh_sudo(ssh, f'sudo -S mv "{temp_path}" "{TT_DIR}/{filename}"', tt_conn['password'])
            if filename.endswith('.sh'):
                self._ssh_sudo(ssh, f'sudo -S chmod +x "{TT_DIR}/{filename}"', tt_conn['password'])
            ssh.close()
            self._log_action("save_tunnel_traffic_file", username, {"filename": filename, "side": side}, True)
            return {"success": True, "message": f"File '{filename}' saved on {side}"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _delete_tt_file(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        tt_conn, side = self._tt_get_conn(args, conn_info, username)
        if not tt_conn:
            return {"success": False, "error": f"Not connected to {side} server"}
        filename = args.get("filename", "")
        user_confirmed = args.get("user_confirmed", False)
        if '/' in filename or '\\' in filename or '..' in filename:
            return {"success": False, "error": "Invalid filename"}
        if not user_confirmed:
            return {"success": False, "error": f"User confirmation required to delete '{filename}'.", "requires_confirmation": True}
        ssh = self._ssh_open(tt_conn)
        try:
            _, _, exit_status = self._ssh_sudo(ssh, f'sudo -S rm "/var/tmp/tunnel_traffic/{filename}"', tt_conn['password'])
            ssh.close()
            self._log_action("delete_tunnel_traffic_file", username, {"filename": filename, "side": side}, exit_status == 0)
            return {"success": exit_status == 0, "message": f"File '{filename}' deleted from {side}" if exit_status == 0 else "Delete failed"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _execute_tt_script(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        tt_conn, side = self._tt_get_conn(args, conn_info, username)
        if not tt_conn:
            return {"success": False, "error": f"Not connected to {side} server"}
        filename = args.get("filename", "")
        if not filename.endswith('.sh') or '/' in filename or '..' in filename:
            return {"success": False, "error": "Only .sh files can be executed"}
        ssh = self._ssh_open(tt_conn)
        try:
            output, _, _ = self._ssh_sudo(
                ssh, f'sudo -S bash -c \'nohup bash "/var/tmp/tunnel_traffic/{filename}" > /tmp/tt_{filename}.log 2>&1 & echo $!\'',
                tt_conn['password'], timeout=10
            )
            ssh.close()
            pid = None
            for line in output.strip().split('\n'):
                if line.strip().isdigit():
                    pid = int(line.strip())
                    break
            self._log_action("execute_tunnel_traffic_script", username, {"filename": filename, "side": side, "pid": pid}, pid is not None)
            return {"success": pid is not None, "pid": pid, "message": f"Script started with PID {pid}" if pid else "Failed to start script"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    async def _kill_tt_script(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        tt_conn, side = self._tt_get_conn(args, conn_info, username)
        if not tt_conn:
            return {"success": False, "error": f"Not connected to {side} server"}
        pid = args.get("pid")
        if not pid:
            return {"success": False, "error": "PID required"}
        ssh = self._ssh_open(tt_conn)
        try:
            _, _, exit_status = self._ssh_sudo(ssh, f'sudo -S kill {pid} 2>&1', tt_conn['password'])
            ssh.close()
            self._log_action("kill_tunnel_traffic_script", username, {"pid": pid, "side": side}, exit_status == 0)
            return {"success": exit_status == 0, "pid": pid, "message": f"PID {pid} killed" if exit_status == 0 else f"Failed to kill PID {pid}"}
        except Exception as e:
            ssh.close() if ssh else None
            return {"success": False, "error": str(e)}

    # ============================================================================
    # Monitoring / Report Tools
    # ============================================================================

    async def _read_disconnect_report(self, conn_info: Dict, username: str) -> Dict[str, Any]:
        """Read the tunnel disconnect report from the server."""
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh.connect(
                hostname=conn_info['ip'], port=conn_info['port'],
                username=conn_info['username'], password=conn_info['password'],
                timeout=15, allow_agent=False, look_for_keys=False
            )
            # Read main report + rotated files without pty to avoid password echo
            cmd = "sudo -S bash -c 'for f in $(ls -v /var/log/tunnel-disconnect-syslog.log* 2>/dev/null); do if [[ $f == *.gz ]]; then zcat $f; else cat $f; fi; done'"
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
            stdin.write(conn_info['password'] + '\n')
            stdin.flush()
            content = stdout.read().decode('utf-8', errors='replace')
            ssh.close()

            # Strip sudo prompt lines and password echoes
            password = conn_info.get('password', '')
            lines = []
            for l in content.split('\n'):
                stripped = l.strip()
                if '[sudo]' in stripped or stripped == password:
                    continue
                lines.append(l)
            content = '\n'.join(lines).strip()

            if not content:
                self._log_action("read_disconnect_report", username, {}, True)
                return {"success": True, "content": "", "message": "Report file is empty or does not exist."}

            self._log_action("read_disconnect_report", username, {"size": len(content)}, True)
            return {"success": True, "content": content, "message": f"Report loaded ({len(content)} chars)"}
        except Exception as e:
            try:
                ssh.close()
            except Exception:
                pass
            self._log_action("read_disconnect_report", username, {"error": str(e)}, False)
            return {"success": False, "error": str(e)}

    async def _analyze_disconnect_report(self, args: Dict, conn_info: Dict, username: str) -> Dict[str, Any]:
        """Analyze the tunnel disconnect report and return structured analysis."""
        # First read the report
        report_result = await self._read_disconnect_report(conn_info, username)
        if not report_result.get("success"):
            return report_result
        
        content = report_result.get("content", "")
        if not content:
            return {"success": True, "analysis": "No disconnect report data found. The monitoring daemon may not have detected any tunnel disconnections yet.", "events": []}

        tunnel_filter = args.get("tunnel_filter", "").strip()

        # Parse all 750007 events from the report
        events = []
        current_interval = None
        for line in content.split('\n'):
            line_stripped = line.strip()
            if line_stripped.startswith("Interval:"):
                current_interval = line_stripped
            if "750007" in line_stripped:
                import re as _re
                m = _re.search(
                    r'Local:([^\s]+)\s+Remote:([^\s]+)\s+Username:([^\s]+)\s+.*?Reason:\s*(.*)',
                    line_stripped, _re.IGNORECASE
                )
                if m:
                    event = {
                        "local": m.group(1),
                        "remote": m.group(2),
                        "username": m.group(3),
                        "reason": m.group(4).strip(),
                        "interval": current_interval,
                        "raw": line_stripped
                    }
                    if tunnel_filter:
                        tf = tunnel_filter.lower()
                        if not any(tf in v.lower() for v in [event["local"], event["remote"], event["username"], event.get("reason", "")]):
                            continue
                    events.append(event)

        # Build summary
        reason_counts = {}
        for e in events:
            r = e["reason"] or "unknown"
            reason_counts[r] = reason_counts.get(r, 0) + 1

        unique_tunnels = set()
        for e in events:
            unique_tunnels.add(f"{e['local']} <-> {e['remote']}")

        analysis = {
            "total_disconnect_events": len(events),
            "unique_tunnels_affected": len(unique_tunnels),
            "tunnels": list(unique_tunnels),
            "reasons": reason_counts,
            "events": events[:50],
            "report_content": content[:8000]
        }

        self._log_action("analyze_disconnect_report", username, {
            "events": len(events), "filter": tunnel_filter
        }, True)

        return {"success": True, "analysis": analysis, "message": f"Found {len(events)} disconnect events across {len(unique_tunnels)} unique tunnels."}


# ============================================================================
# FMC Configuration Tool Definitions
# ============================================================================

FMC_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_fmc_schema",
            "description": "Look up FMC REST API schema information for a specific configuration type. Use this to understand required fields, data types, enums, and constraints before generating configurations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The configuration type or concept to look up (e.g. 'subinterfaces', 'ospfv2 policies', 'BGP general settings', 'security zones', 'host objects')"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "validate_fmc_config",
            "description": "Validate a generated FMC configuration YAML against the API schema. Returns validation errors if any fields are invalid or missing.",
            "parameters": {
                "type": "object",
                "properties": {
                    "config_yaml": {
                        "type": "string",
                        "description": "The YAML configuration string to validate"
                    }
                },
                "required": ["config_yaml"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "load_config_to_ui",
            "description": "Load a validated FMC configuration YAML into the Device Configuration section of the UI. The configuration will be parsed and displayed with counts for each type. Call this after generating and validating a configuration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "config_yaml": {
                        "type": "string",
                        "description": "The validated YAML configuration string to load into the Device Configuration section"
                    },
                    "filename": {
                        "type": "string",
                        "description": "A descriptive filename for the configuration (e.g. 'subinterfaces_config.yaml')"
                    }
                },
                "required": ["config_yaml", "filename"]
            }
        }
    }
]


class FMCToolExecutor:
    """Executor for FMC configuration AI tools."""

    def __init__(self):
        self._fmc_rag = None

    def _get_rag(self):
        if self._fmc_rag is None:
            from fmc_schema_rag import get_fmc_schema_rag
            self._fmc_rag = get_fmc_schema_rag()
        return self._fmc_rag

    def execute(self, tool_name: str, arguments: Dict[str, Any], username: str = "system") -> Dict[str, Any]:
        """Execute an FMC tool by name."""
        handler = {
            "lookup_fmc_schema": self._lookup_schema,
            "validate_fmc_config": self._validate_config,
            "load_config_to_ui": self._load_config_to_ui,
        }.get(tool_name)

        if not handler:
            return {"success": False, "error": f"Unknown FMC tool: {tool_name}"}

        try:
            # Pass username and all arguments to the handler
            return handler(username=username, **arguments)
        except Exception as e:
            logger.error(f"FMC tool '{tool_name}' error: {e}")
            return {"success": False, "error": str(e)}

    def _lookup_schema(self, query: str, username: str = "system") -> Dict[str, Any]:
        """Look up FMC schema information."""
        rag = self._get_rag()
        results = rag.search(query, top_k=6)
        if not results:
            return {"success": True, "result": "No matching schema information found for this query."}
        return {"success": True, "result": "\n\n---\n\n".join(results)}

    def _validate_config(self, config_yaml: str, username: str = "system") -> Dict[str, Any]:
        """Validate FMC config YAML against schema."""
        import yaml as yaml_lib
        try:
            config = yaml_lib.safe_load(config_yaml)
        except Exception as e:
            return {"success": False, "error": f"Invalid YAML: {e}"}

        if not isinstance(config, dict):
            return {"success": False, "error": "Configuration must be a YAML mapping (dictionary)"}

        rag = self._get_rag()
        errors = []
        warnings = []
        validated_types = []

        # Validate top-level interface arrays
        interface_keys = [
            "loopback_interfaces", "physical_interfaces", "etherchannel_interfaces",
            "subinterfaces", "vti_interfaces", "inline_sets", "bridge_group_interfaces"
        ]
        for key in interface_keys:
            items = config.get(key)
            if items:
                if not isinstance(items, list):
                    errors.append(f"'{key}' must be an array/list")
                else:
                    validated_types.append(f"{key}: {len(items)} items")
                    self._validate_items_against_schema(items, key, rag, errors, warnings)

        # Validate routing section
        routing = config.get("routing", {})
        if isinstance(routing, dict):
            routing_keys = [
                "bgp_general_settings", "bgp_policies", "bfd_policies",
                "ospfv2_policies", "ospfv2_interfaces", "ospfv3_policies",
                "ospfv3_interfaces", "eigrp_policies", "pbr_policies",
                "ipv4_static_routes", "ipv6_static_routes", "ecmp_zones", "vrfs"
            ]
            for key in routing_keys:
                items = routing.get(key)
                if items:
                    if not isinstance(items, list):
                        errors.append(f"'routing.{key}' must be an array/list")
                    else:
                        validated_types.append(f"routing.{key}: {len(items)} items")

        # Validate objects section
        objects = config.get("objects", {})
        if isinstance(objects, dict):
            # Nested object sections
            for section_key, sub_keys in {
                "interface": ["security_zones"],
                "network": ["hosts", "ranges", "networks", "fqdns", "groups"],
                "port": ["objects"],
            }.items():
                section = objects.get(section_key, {})
                if isinstance(section, dict):
                    for sk in sub_keys:
                        items = section.get(sk)
                        if items and isinstance(items, list):
                            validated_types.append(f"objects.{section_key}.{sk}: {len(items)} items")

            # Flat object lists
            flat_keys = [
                "bfd_templates", "as_path_lists", "key_chains", "sla_monitors", "route_maps"
            ]
            for key in flat_keys:
                items = objects.get(key)
                if items and isinstance(items, list):
                    validated_types.append(f"objects.{key}: {len(items)} items")

            # Nested object sub-sections
            for section_key, sub_keys in {
                "community_lists": ["community", "extended"],
                "prefix_lists": ["ipv4", "ipv6"],
                "access_lists": ["standard", "extended"],
                "address_pools": ["ipv4", "ipv6", "mac"],
            }.items():
                section = objects.get(section_key, {})
                if isinstance(section, dict):
                    for sk in sub_keys:
                        items = section.get(sk)
                        if items and isinstance(items, list):
                            validated_types.append(f"objects.{section_key}.{sk}: {len(items)} items")

        # Check for auth fields with placeholder values
        self._check_auth_placeholders(config, errors, path="")

        if not validated_types:
            errors.append("No recognized configuration types found in YAML")

        result = {
            "success": len(errors) == 0,
            "validated_types": validated_types,
            "errors": errors,
            "warnings": warnings,
        }
        if errors:
            result["message"] = f"Validation failed with {len(errors)} error(s)"
        else:
            result["message"] = f"Validation passed. {len(validated_types)} configuration type(s) found."
        return result

    def _validate_items_against_schema(self, items: list, config_type: str,
                                        rag, errors: list, warnings: list):
        """Basic field validation against schema for a list of config items."""
        from fmc_schema_rag import FMC_CONFIG_SCHEMA_MAP, AUTH_FIELDS
        schema_names = FMC_CONFIG_SCHEMA_MAP.get(config_type, [])
        if not schema_names:
            return

        for schema_name in schema_names:
            schema_json = rag.get_schema_json(schema_name)
            if schema_json and "properties" in schema_json:
                known_fields = set(schema_json["properties"].keys())
                required_fields = set(schema_json.get("required", []))
                for i, item in enumerate(items):
                    if not isinstance(item, dict):
                        continue
                    # Check for unknown fields
                    for field in item:
                        if field not in known_fields and field != "type":
                            warnings.append(f"{config_type}[{i}]: unknown field '{field}'")
                    # Check required fields
                    for rf in required_fields:
                        if rf not in item and rf != "id" and rf != "type":
                            errors.append(f"{config_type}[{i}]: missing required field '{rf}'")
                break

    def _check_auth_placeholders(self, obj: Any, errors: list, path: str):
        """Recursively check for placeholder values in auth fields."""
        from fmc_schema_rag import AUTH_FIELDS
        placeholders = {"changeme", "password123", "secret", "placeholder", "todo", "xxx", "CHANGE_ME"}
        if isinstance(obj, dict):
            for key, val in obj.items():
                curr_path = f"{path}.{key}" if path else key
                if key in AUTH_FIELDS and isinstance(val, str):
                    if val.lower().strip() in placeholders or val.startswith("<") or val.startswith("PLACEHOLDER"):
                        errors.append(f"'{curr_path}': contains a placeholder value. Authentication secrets must be provided by the user.")
                self._check_auth_placeholders(val, errors, curr_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._check_auth_placeholders(item, errors, f"{path}[{i}]")

    def _load_config_to_ui(self, config_yaml: str, filename: str, username: str = "system", user_confirmed: bool = False, **kwargs) -> Dict[str, Any]:
        """Prepare config data for loading into the UI. The actual UI loading happens on the frontend."""
        import yaml as yaml_lib
        try:
            config = yaml_lib.safe_load(config_yaml)
        except Exception as e:
            return {"success": False, "error": f"Invalid YAML: {e}"}

        if not isinstance(config, dict):
            return {"success": False, "error": "Configuration must be a YAML mapping"}

        # Count all config types (same logic as the upload endpoint)
        counts = self._count_config_items(config)

        return {
            "success": True,
            "action": "load_config",
            "config": config,
            "counts": counts,
            "filename": filename,
            "config_yaml": config_yaml,
            "message": f"Configuration '{filename}' ready to load into Device Configuration section."
        }

    def _count_config_items(self, config: dict) -> dict:
        """Count items in each config section."""
        def safe_len(obj, *keys):
            curr = obj
            for k in keys:
                if isinstance(curr, dict):
                    curr = curr.get(k)
                else:
                    return 0
            return len(curr) if isinstance(curr, list) else 0

        routing = config.get("routing", {}) or {}
        objects = config.get("objects", {}) or {}

        return {
            "loopback_interfaces": safe_len(config, "loopback_interfaces"),
            "physical_interfaces": safe_len(config, "physical_interfaces"),
            "etherchannel_interfaces": safe_len(config, "etherchannel_interfaces"),
            "subinterfaces": safe_len(config, "subinterfaces"),
            "vti_interfaces": safe_len(config, "vti_interfaces"),
            "inline_sets": safe_len(config, "inline_sets"),
            "bridge_group_interfaces": safe_len(config, "bridge_group_interfaces"),
            "routing_bgp_general_settings": safe_len(routing, "bgp_general_settings"),
            "routing_bgp_policies": safe_len(routing, "bgp_policies"),
            "routing_bfd_policies": safe_len(routing, "bfd_policies"),
            "routing_ospfv2_policies": safe_len(routing, "ospfv2_policies"),
            "routing_ospfv2_interfaces": safe_len(routing, "ospfv2_interfaces"),
            "routing_ospfv3_policies": safe_len(routing, "ospfv3_policies"),
            "routing_ospfv3_interfaces": safe_len(routing, "ospfv3_interfaces"),
            "routing_eigrp_policies": safe_len(routing, "eigrp_policies"),
            "routing_pbr_policies": safe_len(routing, "pbr_policies"),
            "routing_ipv4_static_routes": safe_len(routing, "ipv4_static_routes"),
            "routing_ipv6_static_routes": safe_len(routing, "ipv6_static_routes"),
            "routing_ecmp_zones": safe_len(routing, "ecmp_zones"),
            "routing_vrfs": safe_len(routing, "vrfs"),
            "objects_interface_security_zones": safe_len(objects, "interface", "security_zones"),
            "objects_network_hosts": safe_len(objects, "network", "hosts"),
            "objects_network_ranges": safe_len(objects, "network", "ranges"),
            "objects_network_networks": safe_len(objects, "network", "networks"),
            "objects_network_fqdns": safe_len(objects, "network", "fqdns"),
            "objects_network_groups": safe_len(objects, "network", "groups"),
            "objects_port_objects": safe_len(objects, "port", "objects"),
            "objects_bfd_templates": safe_len(objects, "bfd_templates"),
            "objects_as_path_lists": safe_len(objects, "as_path_lists"),
            "objects_key_chains": safe_len(objects, "key_chains"),
            "objects_sla_monitors": safe_len(objects, "sla_monitors"),
            "objects_community_lists_community": safe_len(objects, "community_lists", "community"),
            "objects_community_lists_extended": safe_len(objects, "community_lists", "extended"),
            "objects_prefix_lists_ipv4": safe_len(objects, "prefix_lists", "ipv4"),
            "objects_prefix_lists_ipv6": safe_len(objects, "prefix_lists", "ipv6"),
            "objects_access_lists_extended": safe_len(objects, "access_lists", "extended"),
            "objects_access_lists_standard": safe_len(objects, "access_lists", "standard"),
            "objects_route_maps": safe_len(objects, "route_maps"),
            "objects_address_pools_ipv4": safe_len(objects, "address_pools", "ipv4"),
            "objects_address_pools_ipv6": safe_len(objects, "address_pools", "ipv6"),
            "objects_address_pools_mac": safe_len(objects, "address_pools", "mac"),
        }


# ============================================================================
# VPN Topology Tool Definitions (part of FMC context)
# ============================================================================

VPN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "generate_vpn_topology",
            "description": (
                "Generate a VPN topology YAML file for the Create VPN Topology section. "
                "Supports topology types: HUB_AND_SPOKE, PEER_TO_PEER, FULL_MESH. "
                "Supports route-based and policy-based VPN. "
                "Each topology needs: name, routeBased (bool), ikeV1Enabled, ikeV2Enabled, topologyType, "
                "and endpoints with peerType (HUB/SPOKE/PEER), device info, interface, tunnelSourceInterface, connectionType. "
                "Extranet endpoints use extranetInfo (name, ipAddress, isDynamicIP) instead of device/interface. "
                "Also includes ikeSettings (auth type, pre-shared key), ipsecSettings, and advancedSettings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "topology_name": {
                        "type": "string",
                        "description": "Name for the VPN topology"
                    },
                    "topology_type": {
                        "type": "string",
                        "enum": ["HUB_AND_SPOKE", "PEER_TO_PEER", "FULL_MESH"],
                        "description": "The VPN topology type"
                    },
                    "route_based": {
                        "type": "boolean",
                        "description": "True for route-based VPN (uses VTI interfaces), false for policy-based"
                    },
                    "endpoints": {
                        "type": "array",
                        "description": "List of endpoint definitions. Each must have: peer_type (HUB/SPOKE/PEER), and either device_name (for managed FTD) or extranet_name+extranet_ip (for extranet peer).",
                        "items": {
                            "type": "object",
                            "properties": {
                                "peer_type": {
                                    "type": "string",
                                    "enum": ["HUB", "SPOKE", "PEER"],
                                    "description": "Role of this endpoint"
                                },
                                "device_name": {
                                    "type": "string",
                                    "description": "Name of the managed FTD device (omit for extranet)"
                                },
                                "extranet_name": {
                                    "type": "string",
                                    "description": "Name for an extranet peer (omit for managed device)"
                                },
                                "extranet_ip": {
                                    "type": "string",
                                    "description": "IP address of the extranet peer"
                                },
                                "interface_name": {
                                    "type": "string",
                                    "description": "VPN interface name (default: dvti for route-based)"
                                },
                                "interface_type": {
                                    "type": "string",
                                    "description": "Interface type (default: VTI for route-based)"
                                },
                                "tunnel_source_interface": {
                                    "type": "string",
                                    "description": "Tunnel source interface name (default: outside)"
                                },
                                "connection_type": {
                                    "type": "string",
                                    "enum": ["BIDIRECTIONAL", "ORIGINATE_ONLY", "ANSWER_ONLY"],
                                    "description": "Connection type (default: BIDIRECTIONAL for HUB/PEER, ORIGINATE_ONLY for SPOKE)"
                                }
                            },
                            "required": ["peer_type"]
                        }
                    },
                    "ike_auth_type": {
                        "type": "string",
                        "enum": ["MANUAL_PRE_SHARED_KEY", "CERTIFICATE"],
                        "description": "IKE authentication type (default: MANUAL_PRE_SHARED_KEY)"
                    },
                    "pre_shared_key": {
                        "type": "string",
                        "description": "Pre-shared key for IKE authentication. MUST be provided by the user, never use placeholders."
                    },
                    "ikev2_enabled": {
                        "type": "boolean",
                        "description": "Enable IKEv2 (default: true)"
                    },
                    "ikev1_enabled": {
                        "type": "boolean",
                        "description": "Enable IKEv1 (default: false)"
                    }
                },
                "required": ["topology_name", "topology_type", "route_based", "endpoints"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "load_vpn_topology_to_ui",
            "description": "Load a VPN topology YAML into the Create VPN Topology section of the UI. Call this after generating a VPN topology YAML.",
            "parameters": {
                "type": "object",
                "properties": {
                    "vpn_yaml": {
                        "type": "string",
                        "description": "The VPN topology YAML string to load"
                    },
                    "filename": {
                        "type": "string",
                        "description": "Descriptive filename (e.g. 'vpn-hub-spoke.yaml')"
                    }
                },
                "required": ["vpn_yaml", "filename"]
            }
        }
    }
]


class VPNToolExecutor:
    """Executor for VPN topology AI tools."""

    def execute(self, tool_name: str, arguments: Dict[str, Any], username: str = "system") -> Dict[str, Any]:
        handler = {
            "generate_vpn_topology": self._generate_topology,
            "load_vpn_topology_to_ui": self._load_vpn_to_ui,
        }.get(tool_name)

        if not handler:
            return {"success": False, "error": f"Unknown VPN tool: {tool_name}"}

        try:
            return handler(username=username, **arguments)
        except Exception as e:
            logger.error(f"VPN tool '{tool_name}' error: {e}")
            return {"success": False, "error": str(e)}

    def _generate_topology(self, topology_name: str, topology_type: str, route_based: bool,
                           endpoints: List[Dict[str, Any]],
                           ike_auth_type: str = "MANUAL_PRE_SHARED_KEY",
                           pre_shared_key: str = "cisco",
                           ikev2_enabled: bool = True, ikev1_enabled: bool = False,
                           username: str = "system", **kwargs) -> Dict[str, Any]:
        """Generate VPN topology YAML from structured parameters."""
        import yaml as yaml_lib

        # Build endpoints list
        ep_list = []
        for ep in endpoints:
            peer_type = (ep.get("peer_type") or "PEER").upper()
            is_extranet = bool(ep.get("extranet_name") or ep.get("extranet_ip"))

            entry: Dict[str, Any] = {
                "peerType": peer_type,
                "enableNatTraversal": True,
                "overrideRemoteVpnFilter": False,
                "protectedNetworks": {},
                "isLocalTunnelIdEnabled": False,
                "allowIncomingIKEv2Routes": True,
                "extranet": is_extranet,
                "dynamicRRIEnabled": False,
                "enableNATExempt": False,
            }

            if is_extranet:
                entry["extranetInfo"] = {
                    "name": ep.get("extranet_name", "EXTRANET"),
                    "ipAddress": ep.get("extranet_ip", "0.0.0.0"),
                    "isDynamicIP": False,
                }
                conn_type = ep.get("connection_type", "ORIGINATE_ONLY")
                entry["connectionType"] = conn_type
                entry["name"] = ep.get("extranet_name", "EXTRANET")
                entry["type"] = "EndPoint"
            else:
                device_name = ep.get("device_name", "FTD")
                iface_name = ep.get("interface_name", "dvti" if route_based else "outside")
                iface_type = ep.get("interface_type", "VTI" if route_based else "PhysicalInterface")
                tunnel_src = ep.get("tunnel_source_interface", "outside")

                if peer_type == "HUB":
                    entry["sendTunnelInterfaceIpToPeer"] = True

                entry["device"] = {"name": device_name, "type": "Device", "id": "<DEVICE_UUID>"}
                entry["interface"] = {"name": iface_name, "type": iface_type, "id": "<INTERFACE_UUID>"}
                entry["tunnelSourceInterface"] = {"name": tunnel_src, "type": "PhysicalInterface", "id": "<TUNNEL_SOURCE_UUID>"}

                default_conn = "BIDIRECTIONAL" if peer_type in ("HUB", "PEER") else "ORIGINATE_ONLY"
                entry["connectionType"] = ep.get("connection_type", default_conn)
                entry["name"] = device_name
                entry["type"] = "EndPoint"

            ep_list.append(entry)

        # Build the full topology structure
        topology = {
            "vpn_topologies": [{
                "name": topology_name,
                "routeBased": route_based,
                "ikeV1Enabled": ikev1_enabled,
                "ikeV2Enabled": ikev2_enabled,
                "topologyType": topology_type,
                "endpoints": ep_list,
                "ikeSettings": [{
                    "ikeV2Settings": {
                        "manualPreSharedKey": pre_shared_key,
                        "enforceHexBasedPreSharedKeyOnly": False,
                        "authenticationType": ike_auth_type,
                    },
                    "id": "<IKE_SETTINGS_UUID>",
                    "type": "IkeSetting",
                }],
                "ipsecSettings": [{
                    "tfcPackets": {"payloadBytes": 0, "timeoutSeconds": 0, "burstBytes": 0, "enabled": False},
                    "enableSaStrengthEnforcement": False,
                    "validateIncomingIcmpErrorMessage": False,
                    "perfectForwardSecrecy": {"enabled": False},
                    "ikeV2Mode": "TUNNEL",
                    "enableRRI": True,
                    "lifetimeSeconds": 28800,
                    "lifetimeKilobytes": 4608000,
                    "doNotFragmentPolicy": "NONE",
                    "cryptoMapType": "STATIC",
                    "id": "<IPSEC_SETTINGS_UUID>",
                    "type": "IPSecSetting",
                }],
                "advancedSettings": [{
                    "id": "<ADVANCED_SETTINGS_UUID>",
                    "type": "AdvancedSetting",
                    "advancedTunnelSetting": {
                        "vpnIdleTimeout": {"timeoutMinutes": 30, "enabled": True},
                        "certificateMapSettings": {
                            "useCertMapConfiguredInEndpointToDetermineTunnel": False,
                            "useCertificateOuToDetermineTunnel": True,
                            "useIkeIdentityOuToDetermineTunnel": True,
                            "usePeerIpAddressToDetermineTunnel": True,
                        },
                        "tunnelBFDSettings": {"enableBFD": False},
                        "enableSpokeToSpokeConnectivityThroughHub": False,
                        "bypassAccessControlTrafficForDecryptedTraffic": False,
                        "natKeepaliveMessageTraversal": {"enabled": True, "intervalSeconds": 20},
                        "enableSGTPropagationOverVTI": False,
                    },
                    "advancedIpsecSetting": {
                        "maximumTransmissionUnitAging": {"enabled": False},
                        "enableFragmentationBeforeEncryption": True,
                    },
                    "advancedIkeSetting": {
                        "ikeKeepaliveSettings": {"ikeKeepalive": "ENABLED", "threshold": 10, "retryInterval": 2},
                        "peerIdentityValidation": "REQUIRED",
                        "enableNotificationOnTunnelDisconnect": False,
                        "thresholdToChallengeIncomingCookies": 50,
                        "percentageOfSAsAllowedInNegotiation": 100,
                        "identitySentToPeer": "AUTO_OR_DN",
                        "enableAggressiveMode": False,
                        "cookieChallenge": "CUSTOM",
                    },
                }],
            }],
        }

        yaml_str = yaml_lib.dump(topology, default_flow_style=False, sort_keys=False, allow_unicode=True)

        return {
            "success": True,
            "vpn_yaml": yaml_str,
            "filename": f"vpn-{topology_name.lower().replace(' ', '-')}.yaml",
            "message": f"Generated VPN topology '{topology_name}' ({topology_type}, {'route-based' if route_based else 'policy-based'}) with {len(ep_list)} endpoint(s).",
        }

    def _load_vpn_to_ui(self, vpn_yaml: str, filename: str, username: str = "system", **kwargs) -> Dict[str, Any]:
        """Parse VPN YAML and return data for the frontend to load into the Create VPN Topology section."""
        import yaml as yaml_lib
        try:
            data = yaml_lib.safe_load(vpn_yaml)
        except Exception as e:
            return {"success": False, "error": f"Invalid YAML: {e}"}

        if not isinstance(data, dict):
            return {"success": False, "error": "VPN configuration must be a YAML mapping"}

        # Normalize topologies the same way the upload endpoint does
        def _as_list(x):
            return x if isinstance(x, list) else []

        candidates = [
            _as_list(data.get("vpn_topologies")),
            _as_list((data.get("vpn") or {}).get("topologies")),
            _as_list(data.get("topologies")),
        ]
        topologies = next((lst for lst in candidates if isinstance(lst, list) and len(lst) > 0), [])

        if not topologies:
            return {"success": False, "error": "No VPN topologies found in YAML"}

        out = []
        for t in topologies:
            if not isinstance(t, dict):
                continue
            name = (t.get("name") or "").strip()
            topo_type = t.get("topologyType") or ""
            route_based = t.get("routeBased")
            eps = t.get("endpoints") or []
            peers = []
            for ep in eps:
                if isinstance(ep, dict):
                    nm = ep.get("name") or (ep.get("device") or {}).get("name") or ""
                    pt = (ep.get("peerType") or "").upper()
                    ex = bool(ep.get("extranet"))
                    if nm:
                        peers.append({"name": str(nm), "peerType": pt, "extranet": ex})
            out.append({
                "name": name,
                "type": "FTDS2SVpn",
                "topologyType": topo_type,
                "routeBased": bool(route_based) if route_based is not None else None,
                "peers": peers,
                "raw": t,
            })

        return {
            "success": True,
            "action": "load_vpn_topology",
            "topologies": out,
            "vpn_yaml": vpn_yaml,
            "filename": filename,
            "message": f"VPN topology YAML '{filename}' with {len(out)} topology(ies) ready to load.",
        }


# ============================================================================
# FMC Operation Tool Definitions (connect, get/push config, VPN ops)
# ============================================================================

FMC_OPERATION_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "fmc_connect",
            "description": (
                "Connect to an FMC (Firewall Management Center) using saved credentials from the Saved Configs dropdown, "
                "or using manually provided credentials. After connecting, returns the list of available FTD devices "
                "and FMC domains. The UI will be updated with the connection details and device list."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "preset_name": {
                        "type": "string",
                        "description": "Name of the saved FMC preset/config to connect to (e.g. 'FMC-A', 'Production FMC'). Matches against the Saved Configs dropdown."
                    },
                    "fmc_ip": {
                        "type": "string",
                        "description": "FMC IP/URL if not using a preset (e.g. 'https://10.1.1.1:12202')"
                    },
                    "username": {
                        "type": "string",
                        "description": "FMC username if not using a preset"
                    },
                    "password": {
                        "type": "string",
                        "description": "FMC password if not using a preset. NEVER generate or guess passwords."
                    },
                    "domain_name": {
                        "type": "string",
                        "description": "FMC domain name to use (default: 'Global')"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_get_device_config",
            "description": (
                "Retrieve the full configuration from an FTD device managed by the connected FMC. "
                "The device must appear in the Available Devices list. Returns a YAML configuration file "
                "and loads it into the Device Configuration section of the UI. "
                "Generates a detailed summary report of all configuration types fetched."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_name": {
                        "type": "string",
                        "description": "Name of the FTD device to get configuration from (as shown in Available Devices)"
                    },
                    "domain_name": {
                        "type": "string",
                        "description": "FMC domain name (default: 'Global')"
                    }
                },
                "required": ["device_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_push_device_config",
            "description": (
                "Push the currently loaded Device Configuration to one or more FTD devices on the connected FMC. "
                "The configuration must be loaded first (via fmc_get_device_config, load_config_to_ui, or file upload). "
                "Generates a detailed tabular report of configurations applied, skipped, and failed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of FTD device names to push configuration to"
                    },
                    "domain_name": {
                        "type": "string",
                        "description": "FMC domain name (default: 'Global')"
                    }
                },
                "required": ["device_names"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_delete_device",
            "description": (
                "Delete/unregister FTD device(s) from the connected FMC. "
                "This is a DESTRUCTIVE operation that requires explicit user confirmation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Names of FTD devices to delete/unregister from FMC"
                    }
                },
                "required": ["device_names"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_delete_config",
            "description": (
                "Delete specific configuration types from a target FTD device on the connected FMC. "
                "Deletes the configuration objects currently loaded in the Device Configuration section. "
                "This is a DESTRUCTIVE operation that requires explicit user confirmation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_name": {
                        "type": "string",
                        "description": "Name of the target FTD device"
                    },
                    "config_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Configuration types to delete. Valid types: loopback_interfaces, physical_interfaces, etherchannel_interfaces, subinterfaces, vti_interfaces, security_zones"
                    }
                },
                "required": ["device_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_get_vpn_topologies",
            "description": (
                "Retrieve all S2S VPN topologies from the connected FMC, including endpoints and settings. "
                "Returns topology details and loads them into the VPN section of the UI. "
                "Generates a detailed summary report."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain_name": {
                        "type": "string",
                        "description": "FMC domain name (default: 'Global')"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_push_vpn_topologies",
            "description": (
                "Push VPN topologies to the connected FMC. Uses the currently loaded VPN topology data. "
                "Generates a detailed tabular report of applied, skipped, and failed changes."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "domain_name": {
                        "type": "string",
                        "description": "FMC domain name (default: 'Global')"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_replace_vpn_endpoints",
            "description": (
                "Replace VPN endpoints in the loaded VPN topologies, swapping one device for another. "
                "Modifies the loaded VPN data so that all endpoints referencing the source device "
                "are updated to reference the target device instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source_device": {
                        "type": "string",
                        "description": "Name of the source device whose endpoints will be replaced"
                    },
                    "target_device": {
                        "type": "string",
                        "description": "Name of the target device to replace with"
                    }
                },
                "required": ["source_device", "target_device"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_load_context_config",
            "description": (
                "Load the previously fetched device configuration into the Device Configuration section of the UI. "
                "Use this when the user asks to 'load config into the UI' or 'show config in the UI' after a "
                "fmc_get_device_config operation. This loads from stored context — no YAML string needed."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fmc_load_context_vpn",
            "description": (
                "Load the previously fetched VPN topologies into the VPN section of the UI. "
                "Use this when the user asks to 'load VPN into the UI' or 'show VPN topologies' after a "
                "fmc_get_vpn_topologies operation. This loads from stored context — no data needed."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
]


# Global executor instances
tool_executor = StrongSwanToolExecutor()
fmc_tool_executor = FMCToolExecutor()
vpn_tool_executor = VPNToolExecutor()


def get_tool_executor(context: str = "strongswan"):
    """Get the appropriate tool executor for the given context."""
    if context == "fmc":
        return fmc_tool_executor
    return tool_executor
