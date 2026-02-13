"""
AI Service Module - Bridge API Integration and RAG Pipeline

This module provides:
1. Bridge API authentication and token management
2. RAG pipeline for swanctl.conf documentation
3. Chat completion with streaming support
4. Tool calling for strongSwan config management
"""

import os
import json
import time
import base64
import hashlib
import logging
import asyncio
import httpx
from typing import Dict, List, Any, Optional, AsyncGenerator, Callable
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ============================================================================
# CIRCUIT API Configuration (Cisco GenAI Platform)
# ============================================================================

# Okta OAuth2 token endpoint for authentication
CIRCUIT_TOKEN_URL = os.environ.get("CIRCUIT_TOKEN_URL", "https://id.cisco.com/oauth2/default/v1/token")

# Chat completions endpoint base URL
CIRCUIT_CHAT_BASE_URL = os.environ.get("CIRCUIT_CHAT_BASE_URL", "https://chat-ai.cisco.com")

# Default model name
CIRCUIT_MODEL = os.environ.get("CIRCUIT_MODEL", "gpt-4o")

# API version for chat completions
CIRCUIT_API_VERSION = os.environ.get("CIRCUIT_API_VERSION", "2025-04-01-preview")


class CircuitAPIClient:
    """
    Client for Cisco CIRCUIT API (GenAI Platform) with automatic token refresh.
    Uses OAuth2 client credentials flow with Okta authentication.
    """
    
    def __init__(self):
        self.client_id = os.environ.get("BRIDGE_API_CLIENT_ID")
        self.client_secret = os.environ.get("BRIDGE_API_CLIENT_SECRET")
        self.app_key = os.environ.get("BRIDGE_API_APP_KEY")
        self.token_url = CIRCUIT_TOKEN_URL
        self.chat_base_url = CIRCUIT_CHAT_BASE_URL
        self.model = CIRCUIT_MODEL
        self.api_version = CIRCUIT_API_VERSION
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0
        self._lock = asyncio.Lock()
        
        if not self.client_id or not self.client_secret:
            logger.warning("BRIDGE_API_CLIENT_ID or BRIDGE_API_CLIENT_SECRET not set in environment")
        if not self.app_key:
            logger.warning("BRIDGE_API_APP_KEY not set in environment")
    
    def _get_chat_url(self, model: str = None) -> str:
        """Build the chat completions URL for the specified model."""
        model_name = model or self.model
        return f"{self.chat_base_url}/openai/deployments/{model_name}/chat/completions?api-version={self.api_version}"
    
    async def _get_access_token(self) -> str:
        """
        Get a valid access token, refreshing if necessary.
        Uses OAuth2 client credentials grant with Basic auth.
        """
        async with self._lock:
            # Check if token is still valid (with 60s buffer)
            if self._access_token and time.time() < (self._token_expires_at - 60):
                return self._access_token
            
            if not self.client_id or not self.client_secret:
                raise ValueError("CIRCUIT API credentials not configured. Set BRIDGE_API_CLIENT_ID and BRIDGE_API_CLIENT_SECRET in .env")
            
            logger.info("Refreshing CIRCUIT API access token from Okta...")
            
            try:
                # Build Basic auth header with base64 encoded client_id:client_secret
                credentials = f"{self.client_id}:{self.client_secret}"
                basic_auth = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
                
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        self.token_url,
                        data="grant_type=client_credentials",
                        headers={
                            "Accept": "*/*",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Authorization": f"Basic {basic_auth}"
                        }
                    )
                    
                    if response.status_code != 200:
                        error_detail = response.text[:500]
                        logger.error(f"Token request failed: {response.status_code} - {error_detail}")
                        raise Exception(f"Failed to get access token: {response.status_code} - {error_detail}")
                    
                    token_data = response.json()
                    self._access_token = token_data["access_token"]
                    # Default to 1 hour if expires_in not provided
                    expires_in = token_data.get("expires_in", 3600)
                    self._token_expires_at = time.time() + expires_in
                    
                    logger.info(f"CIRCUIT API token refreshed, expires in {expires_in}s")
                    return self._access_token
            except httpx.ConnectError as e:
                logger.error(f"Cannot connect to Okta at {self.token_url}: {e}")
                raise Exception(f"Cannot connect to Okta for authentication: {e}")
    
    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tools: Optional[List[Dict]] = None,
        tool_choice: Optional[str] = None,
        stream: bool = False
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Send a chat completion request with optional streaming.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature (0-2)
            max_tokens: Maximum tokens in response
            tools: Optional list of tool definitions for function calling
            tool_choice: Optional tool choice strategy
            stream: Whether to stream the response
            
        Yields:
            For streaming: chunks with delta content
            For non-streaming: single response dict
        """
        token = await self._get_access_token()
        chat_url = self._get_chat_url()
        
        # Build user field with appkey (required by CIRCUIT API)
        user_data = {"appkey": self.app_key} if self.app_key else {}
        
        payload = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream,
            "user": json.dumps(user_data),
            "stop": ["<|im_end|>"]
        }
        
        if tools:
            payload["tools"] = tools
        if tool_choice:
            payload["tool_choice"] = tool_choice
        
        # CIRCUIT API uses 'api-key' header instead of Bearer token
        headers = {
            "api-key": token,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        logger.debug(f"Sending chat request to {chat_url}")
        
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                if stream:
                    async with client.stream(
                        "POST",
                        chat_url,
                        json=payload,
                        headers=headers
                    ) as response:
                        if response.status_code != 200:
                            error_text = await response.aread()
                            logger.error(f"Chat API error: {response.status_code} - {error_text[:500]}")
                            raise Exception(f"Chat completion failed: {response.status_code} - {error_text.decode()[:200]}")
                        
                        async for line in response.aiter_lines():
                            if line.startswith("data: "):
                                data = line[6:]
                                if data == "[DONE]":
                                    break
                                try:
                                    chunk = json.loads(data)
                                    yield chunk
                                except json.JSONDecodeError:
                                    continue
                else:
                    response = await client.post(
                        chat_url,
                        json=payload,
                        headers=headers
                    )
                    
                    if response.status_code != 200:
                        logger.error(f"Chat API error: {response.status_code} - {response.text[:500]}")
                        raise Exception(f"Chat completion failed: {response.status_code} - {response.text[:200]}")
                    
                    yield response.json()
        except httpx.ConnectError as e:
            logger.error(f"Cannot connect to CIRCUIT API at {chat_url}: {e}")
            raise Exception(f"Cannot connect to CIRCUIT API: {e}")


# ============================================================================
# RAG Pipeline for swanctl.conf Documentation
# ============================================================================

class SwanctlRAGPipeline:
    """
    RAG pipeline for swanctl.conf documentation.
    Loads, chunks, embeds, and retrieves relevant documentation sections.
    """
    
    def __init__(self, docs_path: str = None):
        self.docs_path = docs_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "utils", "swanctl.conf.md"
        )
        self.chunks: List[Dict[str, Any]] = []
        self.chunk_embeddings: Dict[str, List[float]] = {}
        self._initialized = False
        
    def _load_and_chunk_document(self) -> List[Dict[str, Any]]:
        """
        Load swanctl.conf.md and chunk by logical sections.
        Each chunk contains a configuration option or section with context.
        """
        if not os.path.exists(self.docs_path):
            logger.warning(f"Documentation file not found: {self.docs_path}")
            return []
        
        with open(self.docs_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        chunks = []
        current_section = ""
        current_content = []
        
        lines = content.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            
            # Detect section headers (configuration options start with connections., secrets., pools., authorities.)
            is_config_option = (
                stripped.startswith('connections.') or
                stripped.startswith('secrets.') or
                stripped.startswith('pools.') or
                stripped.startswith('authorities.') or
                stripped in ['connections', 'secrets', 'pools', 'authorities', 'SETTINGS', 'NAME', 'DESCRIPTION', 'FILES', 'SEE ALSO']
            )
            
            if is_config_option and current_content:
                # Save previous chunk
                chunk_text = '\n'.join(current_content).strip()
                if chunk_text and len(chunk_text) > 20:
                    chunks.append({
                        "id": hashlib.md5(chunk_text.encode()).hexdigest()[:12],
                        "section": current_section,
                        "content": chunk_text,
                        "type": "config_option"
                    })
                current_content = []
                current_section = stripped.split()[0] if stripped.split() else stripped
            
            current_content.append(line)
            i += 1
        
        # Don't forget the last chunk
        if current_content:
            chunk_text = '\n'.join(current_content).strip()
            if chunk_text and len(chunk_text) > 20:
                chunks.append({
                    "id": hashlib.md5(chunk_text.encode()).hexdigest()[:12],
                    "section": current_section,
                    "content": chunk_text,
                    "type": "config_option"
                })
        
        # Re-chunk by meaningful sections (combine very small chunks, split very large ones)
        final_chunks = []
        for chunk in chunks:
            content = chunk["content"]
            # Split large chunks (>2000 chars) at paragraph boundaries
            if len(content) > 2000:
                paragraphs = content.split('\n\n')
                current_para_chunk = []
                current_len = 0
                
                for para in paragraphs:
                    if current_len + len(para) > 1500 and current_para_chunk:
                        final_chunks.append({
                            "id": hashlib.md5('\n\n'.join(current_para_chunk).encode()).hexdigest()[:12],
                            "section": chunk["section"],
                            "content": '\n\n'.join(current_para_chunk),
                            "type": chunk["type"]
                        })
                        current_para_chunk = [para]
                        current_len = len(para)
                    else:
                        current_para_chunk.append(para)
                        current_len += len(para)
                
                if current_para_chunk:
                    final_chunks.append({
                        "id": hashlib.md5('\n\n'.join(current_para_chunk).encode()).hexdigest()[:12],
                        "section": chunk["section"],
                        "content": '\n\n'.join(current_para_chunk),
                        "type": chunk["type"]
                    })
            else:
                final_chunks.append(chunk)
        
        logger.info(f"Loaded {len(final_chunks)} documentation chunks from {self.docs_path}")
        return final_chunks
    
    def initialize(self):
        """Initialize the RAG pipeline by loading and processing documents."""
        if self._initialized:
            return
        
        self.chunks = self._load_and_chunk_document()
        self._initialized = True
        logger.info(f"RAG pipeline initialized with {len(self.chunks)} chunks")
    
    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for relevant documentation chunks.
        Uses keyword matching and section relevance scoring.
        
        Args:
            query: Search query
            top_k: Number of results to return
            
        Returns:
            List of relevant chunks with scores
        """
        if not self._initialized:
            self.initialize()
        
        if not self.chunks:
            return []
        
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        
        scored_chunks = []
        for chunk in self.chunks:
            content_lower = chunk["content"].lower()
            section_lower = chunk["section"].lower()
            
            # Calculate relevance score
            score = 0.0
            
            # Exact phrase match bonus
            if query_lower in content_lower:
                score += 10.0
            
            # Term frequency scoring
            for term in query_terms:
                if len(term) > 2:  # Ignore very short terms
                    term_count = content_lower.count(term)
                    score += min(term_count * 0.5, 3.0)  # Cap per-term contribution
                    
                    # Section name match bonus
                    if term in section_lower:
                        score += 2.0
            
            # Boost for configuration options that match query structure
            config_keywords = ['connections', 'children', 'local', 'remote', 'secrets', 'pools', 'proposals', 'auth']
            for kw in config_keywords:
                if kw in query_lower and kw in content_lower:
                    score += 1.5
            
            if score > 0:
                scored_chunks.append({
                    **chunk,
                    "score": score
                })
        
        # Sort by score descending
        scored_chunks.sort(key=lambda x: x["score"], reverse=True)
        
        return scored_chunks[:top_k]
    
    def get_context_for_query(self, query: str, max_tokens: int = 3000) -> str:
        """
        Get formatted context string for a query, respecting token limits.
        
        Args:
            query: User query
            max_tokens: Approximate token limit (chars/4)
            
        Returns:
            Formatted context string
        """
        relevant_chunks = self.search(query, top_k=8)
        
        if not relevant_chunks:
            return ""
        
        context_parts = []
        total_chars = 0
        max_chars = max_tokens * 4  # Rough char-to-token ratio
        
        for chunk in relevant_chunks:
            chunk_text = f"### {chunk['section']}\n{chunk['content']}"
            if total_chars + len(chunk_text) > max_chars:
                break
            context_parts.append(chunk_text)
            total_chars += len(chunk_text)
        
        if context_parts:
            return "## Relevant swanctl.conf Documentation:\n\n" + "\n\n---\n\n".join(context_parts)
        
        return ""


# ============================================================================
# Chat Session Management
# ============================================================================

class ChatSession:
    """Represents a single chat session with history and context."""
    
    def __init__(self, session_id: str, user_id: str, title: str = "New Chat"):
        self.session_id = session_id
        self.user_id = user_id
        self.title = title
        self.messages: List[Dict[str, Any]] = []
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at
        self.tool_state: Dict[str, Any] = {}  # Track tool invocation state
        self.context_mode: str = "general"  # 'general' or 'strongswan'
    
    def add_message(self, role: str, content: str, tool_calls: List[Dict] = None, tool_call_id: str = None):
        """Add a message to the session history."""
        msg = {
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if tool_calls:
            msg["tool_calls"] = tool_calls
        if tool_call_id:
            msg["tool_call_id"] = tool_call_id
        
        self.messages.append(msg)
        self.updated_at = msg["timestamp"]
        
        # Auto-generate title from first user message
        if role == "user" and len(self.messages) == 1:
            self.title = content[:50] + ("..." if len(content) > 50 else "")
    
    def get_messages_for_api(self, max_messages: int = 20) -> List[Dict[str, str]]:
        """
        Get messages formatted for the chat API.
        Implements context window management via truncation.
        Filters out incomplete tool_call sequences to avoid API errors.
        """
        # Get recent messages, preserving tool call sequences
        recent = self.messages[-max_messages:] if len(self.messages) > max_messages else self.messages
        
        # First pass: collect all tool_call_ids that have responses
        responded_tool_ids = set()
        for msg in recent:
            if msg.get("role") == "tool" and "tool_call_id" in msg:
                responded_tool_ids.add(msg["tool_call_id"])
        
        api_messages = []
        for msg in recent:
            api_msg = {"role": msg["role"], "content": msg["content"]}
            
            if "tool_calls" in msg:
                # Filter to only include tool_calls that have corresponding responses
                sanitized_tool_calls = []
                for tc in msg["tool_calls"]:
                    tc_id = tc.get("id", "")
                    # Only include tool_calls that have responses
                    if tc_id in responded_tool_ids:
                        sanitized_tc = {
                            "id": tc_id,
                            "type": tc.get("type", "function"),
                            "function": tc.get("function", {"name": "", "arguments": ""})
                        }
                        sanitized_tool_calls.append(sanitized_tc)
                
                # Only add tool_calls if there are any with responses
                if sanitized_tool_calls:
                    api_msg["tool_calls"] = sanitized_tool_calls
                elif not msg.get("content"):
                    # Skip assistant messages that only had incomplete tool_calls
                    continue
                    
            if "tool_call_id" in msg:
                api_msg["tool_call_id"] = msg["tool_call_id"]
            api_messages.append(api_msg)
        
        return api_messages
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize session to dictionary."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "title": self.title,
            "messages": self.messages,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tool_state": self.tool_state,
            "context_mode": self.context_mode
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChatSession":
        """Deserialize session from dictionary."""
        session = cls(
            session_id=data["session_id"],
            user_id=data["user_id"],
            title=data.get("title", "Chat")
        )
        session.messages = data.get("messages", [])
        session.created_at = data.get("created_at", session.created_at)
        session.updated_at = data.get("updated_at", session.updated_at)
        session.tool_state = data.get("tool_state", {})
        session.context_mode = data.get("context_mode", "general")
        return session


class ChatStorage:
    """Persistent storage for chat sessions using JSON files."""
    
    def __init__(self, storage_dir: str = None):
        self.storage_dir = storage_dir or os.path.join(
            os.path.dirname(__file__), "data", "ai_chats"
        )
        os.makedirs(self.storage_dir, exist_ok=True)
        self._cache: Dict[str, Dict[str, ChatSession]] = {}  # user_id -> {session_id -> session}
    
    def _get_user_file(self, user_id: str) -> str:
        """Get the storage file path for a user."""
        safe_user_id = "".join(c if c.isalnum() else "_" for c in user_id)
        return os.path.join(self.storage_dir, f"{safe_user_id}_chats.json")
    
    def _load_user_sessions(self, user_id: str) -> Dict[str, ChatSession]:
        """Load all sessions for a user from disk."""
        if user_id in self._cache:
            return self._cache[user_id]
        
        filepath = self._get_user_file(user_id)
        sessions = {}
        
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for session_data in data.get("sessions", []):
                        session = ChatSession.from_dict(session_data)
                        sessions[session.session_id] = session
            except Exception as e:
                logger.error(f"Failed to load chat sessions for {user_id}: {e}")
        
        self._cache[user_id] = sessions
        return sessions
    
    def _save_user_sessions(self, user_id: str):
        """Save all sessions for a user to disk."""
        sessions = self._cache.get(user_id, {})
        filepath = self._get_user_file(user_id)
        
        try:
            data = {
                "user_id": user_id,
                "sessions": [s.to_dict() for s in sessions.values()]
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save chat sessions for {user_id}: {e}")
    
    def get_session(self, user_id: str, session_id: str) -> Optional[ChatSession]:
        """Get a specific session."""
        sessions = self._load_user_sessions(user_id)
        return sessions.get(session_id)
    
    def list_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """List all sessions for a user (metadata only)."""
        sessions = self._load_user_sessions(user_id)
        return [
            {
                "session_id": s.session_id,
                "title": s.title,
                "created_at": s.created_at,
                "updated_at": s.updated_at,
                "message_count": len(s.messages)
            }
            for s in sorted(sessions.values(), key=lambda x: x.updated_at, reverse=True)
        ]
    
    def create_session(self, user_id: str, title: str = "New Chat") -> ChatSession:
        """Create a new session."""
        import uuid
        session_id = str(uuid.uuid4())[:8]
        session = ChatSession(session_id, user_id, title)
        
        sessions = self._load_user_sessions(user_id)
        sessions[session_id] = session
        self._save_user_sessions(user_id)
        
        return session
    
    def update_session(self, session: ChatSession):
        """Update/save a session."""
        sessions = self._load_user_sessions(session.user_id)
        sessions[session.session_id] = session
        self._save_user_sessions(session.user_id)
    
    def delete_session(self, user_id: str, session_id: str) -> bool:
        """Delete a session."""
        sessions = self._load_user_sessions(user_id)
        if session_id in sessions:
            del sessions[session_id]
            self._save_user_sessions(user_id)
            return True
        return False


# ============================================================================
# System Prompts
# ============================================================================

SYSTEM_PROMPT_GENERAL = """You are Vyper AI, an intelligent assistant integrated into the Vyper network management application. You help users with:

1. **General Questions**: Answer questions about networking, VPNs, security, and system administration.
2. **strongSwan Configuration**: When users ask about strongSwan/swanctl configuration, use the provided documentation context to give accurate, grounded answers.
3. **Configuration Assistance**: Help users create, modify, and troubleshoot swanctl.conf configuration files.

## Guidelines:
- Be concise and technically accurate
- When referencing swanctl.conf options, quote or paraphrase the official documentation
- If information is not in the provided context, say so clearly rather than guessing
- For ambiguous requests, ask clarifying questions before taking action
- Explain your reasoning when making configuration recommendations

## Available Tools:
When in the strongSwan Configuration Files context, you have access to tools for managing configuration files. Always:
- Explain what changes you're about to make before making them
- Validate configuration syntax before saving
- Request explicit confirmation for destructive actions (delete, overwrite)
"""

SYSTEM_PROMPT_STRONGSWAN = """You are the strongSwan Configuration Assistant, specialized in helping users manage strongSwan VPN configurations, Netplan network configurations, Linux Traffic Control (tc) rules, tunnel traffic scripts, and general server administration. You have access to the official swanctl.conf(5), tc(8), and iperf3(1) man page documentation.

## Your Capabilities:

### strongSwan Configuration
1. **Create** new configuration files with valid swanctl.conf syntax
2. **Edit** existing configuration files
3. **Delete** configuration files (with user confirmation)
4. **Validate** configuration syntax before saving
5. **Explain** configuration options using official documentation
6. **Reload** strongSwan configuration after changes

### Netplan Network Configuration
7. **List** netplan configuration files in /etc/netplan/
8. **Read** and display netplan file contents
9. **Create/Edit** netplan YAML configuration files
10. **Delete** netplan files (with user confirmation)
11. **Apply** netplan configurations (netplan apply)
12. **Show Routes** - display the current routing table (route -n)

### Traffic Control (tc)
13. **View** current non-default tc rules (excludes fq_codel, noqueue, mq)
14. **Apply** one or more tc commands (supports multi-line)
15. **Remove** all tc rules from all interfaces (with user confirmation)

### General Command Execution
16. **Execute any command** on the connected strongSwan server via the `execute_command` tool
    - **Read-only commands** (ip link show, cat, ls, ifconfig, ping, etc.) can be executed immediately without user confirmation - set is_read_only=true
    - **Write/modify commands** (service restart, file changes, etc.) MUST require explicit user confirmation first - set is_read_only=false and user_confirmed=true only after user confirms

### Tunnel Traffic Management
17. **List** files in /var/tmp/tunnel_traffic on local (strongSwan) or remote server
18. **Read/Create/Edit/Delete** tunnel traffic files on either server
19. **Execute** .sh scripts as background processes (returns PID)
20. **Kill** running script processes by PID
21. **Create custom scripts** - e.g. iperf3 client/server scripts, traffic generators

## Critical Rules:
1. **Documentation-First**: Always base your answers on the provided documentation. Never invent configuration options.
2. **Syntax Validation**: Before saving any configuration, verify it follows valid syntax.
3. **Explicit Confirmation**: For any destructive or state-modifying action, you MUST ask for explicit user confirmation.
4. **Read-Only Auto-Execute**: For read-only informational commands (ip link show, cat /etc/..., ifconfig, route, etc.), execute immediately using execute_command with is_read_only=true. Do NOT refuse to run these.
5. **Transparency**: Always explain what changes you're making and why.
6. **Clarification**: If a user request is ambiguous, ask clarifying questions first.

## strongSwan Configuration Structure Reference:
- `connections.<conn>` - IKE connection configurations
- `connections.<conn>.children.<child>` - CHILD_SA configurations
- `secrets.ike<suffix>` - IKE preshared secrets
- `secrets.eap<suffix>` - EAP/XAuth secrets
- `pools.<name>` - Virtual IP pools
- `authorities.<name>` - CA configurations

## Netplan Configuration Reference:
- Files are YAML format in /etc/netplan/ (must end with .yaml or .yml)
- Top-level keys: network, version, renderer, ethernets, vlans, bridges, bonds, tunnels, routes
- After editing, remind users to run 'netplan apply' to activate changes

## Traffic Control (tc) Common Patterns:
- Add latency: `tc qdisc add dev <iface> root netem delay <ms>ms`
- Add packet loss: `tc qdisc add dev <iface> root netem loss <percent>%`
- Rate limiting: `tc qdisc add dev <iface> root tbf rate <rate> burst <burst> latency <latency>`
- HTB shaping: `tc qdisc add dev <iface> root handle 1: htb default 10`
- View config: `tc -s qdisc show dev <iface>`
- Remove: `tc qdisc del dev <iface> root`

## Tunnel Traffic Scripts:
- Scripts are stored in /var/tmp/tunnel_traffic on both local and remote servers
- .sh files are automatically made executable when saved
- Execute starts script as background process, returns PID
- Kill terminates a running script by PID
- Common use: iperf3 server/client scripts, traffic generation scripts

When creating configurations or scripts, use proper syntax and include helpful comments.
"""

SYSTEM_PROMPT_FMC = """You are the FMC Configuration Assistant, specialized in generating Cisco Firepower Management Center (FMC) device configurations that are compatible with the FMC REST API.

## Your Capabilities:
1. **Generate** complete FMC device configurations in YAML format
2. **Validate** configurations against the FMC API schema
3. **Explain** FMC API fields, types, enums, and constraints
4. **Load** generated configurations into the Device Configuration section

## Supported Configuration Types:
- **Interfaces**: Loopback, Physical, EtherChannel, Subinterfaces, VTI, Inline Sets, Bridge Group
- **Routing**: BGP General Settings, BGP Policies, BFD Policies, OSPFv2/v3 Policies & Interfaces, EIGRP, PBR, IPv4/IPv6 Static Routes, ECMP Zones, VRFs
- **Objects**: Security Zones, Network/Host/Range/FQDN Objects, Network Groups, Port Objects/Groups
- **Routing Templates & Lists**: BFD Templates, AS Path Lists, Key Chains, SLA Monitors, Community Lists (Standard/Extended), IPv4/IPv6 Prefix Lists, Access Lists (Standard/Extended), Route Maps
- **Address Pools**: IPv4, IPv6, MAC Address Pools

## Critical Rules:
1. **Schema Compliance**: All generated configurations MUST match the FMC REST API schema provided in the context. Never invent fields that don't exist in the schema.
2. **NEVER Generate Secrets**: For authentication fields (authKey, md5Key, password, neighborSecret, encryptionKey, preSharedKey, keyString), you MUST ask the user to provide the value. Never generate placeholder values like "changeme" or "password123".
3. **YAML Format**: Output configurations as valid YAML that matches the application's expected structure.
4. **Validation First**: Always validate generated configurations against the schema before presenting them.
5. **Bulk Generation**: When users request bulk/range-based configurations (e.g., "create 20 subinterfaces with IPs from 1.1.1.10 to 1.1.1.20"), correctly expand ranges, validate alignment, and generate all items.
6. **Completeness**: Include all required fields. For optional fields, include commonly-used ones with sensible defaults based on the schema.
7. **Ask for Missing Info**: If the user's request is missing required parameters (security zones, interface names, IP addresses), ask before generating.

## YAML Configuration Structure:
The configuration YAML follows this top-level structure:
```yaml
loopback_interfaces: [...]
physical_interfaces: [...]
etherchannel_interfaces: [...]
subinterfaces: [...]
vti_interfaces: [...]
inline_sets: [...]
bridge_group_interfaces: [...]
routing:
  bgp_general_settings: [...]
  bgp_policies: [...]
  bfd_policies: [...]
  ospfv2_policies: [...]
  ospfv2_interfaces: [...]
  ospfv3_policies: [...]
  ospfv3_interfaces: [...]
  eigrp_policies: [...]
  pbr_policies: [...]
  ipv4_static_routes: [...]
  ipv6_static_routes: [...]
  ecmp_zones: [...]
  vrfs: [...]
objects:
  interface:
    security_zones: [...]
  network:
    hosts: [...]
    ranges: [...]
    networks: [...]
    fqdns: [...]
    groups: [...]
  port:
    objects: [...]
  bfd_templates: [...]
  as_path_lists: [...]
  key_chains: [...]
  sla_monitors: [...]
  community_lists:
    community: [...]
    extended: [...]
  prefix_lists:
    ipv4: [...]
    ipv6: [...]
  access_lists:
    standard: [...]
    extended: [...]
  route_maps: [...]
  address_pools:
    ipv4: [...]
    ipv6: [...]
    mac: [...]
```

## Workflow:
1. Understand the user's request
2. Retrieve relevant FMC API schema information
3. Ask for any missing required parameters or secrets
4. Generate the configuration YAML
5. Validate against the schema
6. Present the configuration and offer to load it into the Device Configuration section

When the user asks you to generate a configuration, output the YAML in a code block with the language tag `yaml`. The frontend will detect this and offer to load it.
"""


# ============================================================================
# Global Instances
# ============================================================================

circuit_client = CircuitAPIClient()
rag_pipeline = SwanctlRAGPipeline()
chat_storage = ChatStorage()

# Lazy-loaded FMC schema RAG
_fmc_rag = None


def get_bridge_client() -> CircuitAPIClient:
    """Get the global CIRCUIT API client instance."""
    return circuit_client


def get_rag_pipeline() -> SwanctlRAGPipeline:
    """Get the global RAG pipeline instance."""
    if not rag_pipeline._initialized:
        rag_pipeline.initialize()
    return rag_pipeline


def get_fmc_rag():
    """Get the global FMC schema RAG instance (lazy-loaded)."""
    global _fmc_rag
    if _fmc_rag is None:
        from fmc_schema_rag import get_fmc_schema_rag
        _fmc_rag = get_fmc_schema_rag()
    return _fmc_rag


def get_chat_storage() -> ChatStorage:
    """Get the global chat storage instance."""
    return chat_storage
