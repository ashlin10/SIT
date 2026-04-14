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
import uuid as _uuid
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
CIRCUIT_MODEL = os.environ.get("CIRCUIT_MODEL", "gpt-4.1")

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
        stream: bool = False,
        model: Optional[str] = None,
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
            model: Optional model name override
            
        Yields:
            For streaming: chunks with delta content
            For non-streaming: single response dict
        """
        token = await self._get_access_token()
        # Resolve display name to model ID if needed
        resolved_model = CIRCUIT_MODELS.get(model, model) if model else None
        chat_url = self._get_chat_url(model=resolved_model)
        
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
# AWS Bedrock Configuration (Claude Models)
# ============================================================================

AWS_BEDROCK_REGION = os.environ.get("AWS_BEDROCK_REGION", "us-east-2")
AWS_BEDROCK_DEFAULT_MODEL = os.environ.get("AWS_BEDROCK_DEFAULT_MODEL", "global.anthropic.claude-sonnet-4-6")

# Model ID mapping for display names
BEDROCK_MODELS = {
    "claude-sonnet-4.6": "global.anthropic.claude-sonnet-4-6",
    "claude-haiku-4.5": "global.anthropic.claude-haiku-4-5-20251001-v1:0",
    "claude-opus-4.6": "global.anthropic.claude-opus-4-6-v1",
}

CIRCUIT_MODELS = {
    "gpt-4.1": "gpt-4.1",
    "gpt-4o-mini": "gpt-4o-mini",
}

# Provider configuration for frontend
PROVIDER_CONFIG = {
    "bedrock": {
        "label": "AWS Bedrock",
        "models": list(BEDROCK_MODELS.keys()),
        "default_model": "claude-sonnet-4.6",
    },
    "circuit": {
        "label": "CIRCUIT API",
        "models": list(CIRCUIT_MODELS.keys()),
        "default_model": "gpt-4.1",
    },
}


class BedrockClaudeClient:
    """
    Client for AWS Bedrock Claude models.
    Converts OpenAI-style messages to Anthropic Messages API format and back,
    so the rest of the app can use a unified interface.
    """

    def __init__(self):
        self.region = AWS_BEDROCK_REGION
        self.default_model = AWS_BEDROCK_DEFAULT_MODEL
        self._client = None
        self._lock = asyncio.Lock()

    def _get_client(self):
        """Lazy-init boto3 bedrock-runtime client."""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client(
                    "bedrock-runtime",
                    region_name=self.region,
                    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
                    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
                )
                logger.info(f"Bedrock client initialized for region {self.region}")
            except Exception as e:
                logger.error(f"Failed to initialize Bedrock client: {e}")
                raise
        return self._client

    @staticmethod
    def _convert_tools_openai_to_anthropic(tools: List[Dict]) -> List[Dict]:
        """Convert OpenAI tool definitions to Anthropic tool format."""
        if not tools:
            return []
        anthropic_tools = []
        for t in tools:
            fn = t.get("function", {})
            anthropic_tools.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
            })
        return anthropic_tools

    @staticmethod
    def _convert_messages_openai_to_anthropic(messages: List[Dict]) -> tuple:
        """
        Convert OpenAI-style messages to Anthropic format.
        Returns (system_prompt, anthropic_messages).
        Validates that every tool_result references a tool_use in the preceding
        assistant message (required by Bedrock/Anthropic API).
        """
        system_prompt = ""
        anthropic_msgs = []
        # Track tool_use IDs from the most recent assistant message
        last_assistant_tool_ids = set()

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            if role == "system":
                system_prompt += (content or "")
                continue

            if role == "user":
                anthropic_msgs.append({"role": "user", "content": content or ""})
                last_assistant_tool_ids = set()
                continue

            if role == "assistant":
                # May contain tool_calls
                tc_list = msg.get("tool_calls")
                last_assistant_tool_ids = set()
                if tc_list:
                    blocks = []
                    if content:
                        blocks.append({"type": "text", "text": content})
                    for tc in tc_list:
                        fn = tc.get("function", {})
                        try:
                            inp = json.loads(fn.get("arguments", "{}"))
                        except (json.JSONDecodeError, TypeError):
                            inp = {}
                        tc_id = tc.get("id", str(_uuid.uuid4())[:12])
                        last_assistant_tool_ids.add(tc_id)
                        blocks.append({
                            "type": "tool_use",
                            "id": tc_id,
                            "name": fn.get("name", ""),
                            "input": inp,
                        })
                    anthropic_msgs.append({"role": "assistant", "content": blocks})
                else:
                    anthropic_msgs.append({"role": "assistant", "content": content or ""})
                continue

            if role == "tool":
                # Tool result → user message with tool_result content block
                tool_call_id = msg.get("tool_call_id", "")

                # Skip tool results that don't match a tool_use in the preceding assistant msg
                if tool_call_id not in last_assistant_tool_ids:
                    logger.warning(f"Bedrock: skipping orphaned tool_result with id={tool_call_id}")
                    continue

                # Try to parse content as JSON for structured result
                try:
                    result_content = json.loads(content) if isinstance(content, str) else content
                except (json.JSONDecodeError, TypeError):
                    result_content = content or ""

                result_block = {
                    "type": "tool_result",
                    "tool_use_id": tool_call_id,
                    "content": json.dumps(result_content) if not isinstance(result_content, str) else result_content,
                }
                # Merge with previous user message if it's also a tool_result
                if anthropic_msgs and anthropic_msgs[-1].get("role") == "user" and isinstance(anthropic_msgs[-1].get("content"), list):
                    anthropic_msgs[-1]["content"].append(result_block)
                else:
                    anthropic_msgs.append({"role": "user", "content": [result_block]})
                continue

        return system_prompt, anthropic_msgs

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tools: Optional[List[Dict]] = None,
        tool_choice: Optional[str] = None,
        stream: bool = False,
        model: Optional[str] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Send a chat completion request to Bedrock Claude.
        Yields OpenAI-compatible response chunks (for streaming) or a single response dict.
        """
        model_id = model or self.default_model
        # Resolve display name to model ID
        if model_id in BEDROCK_MODELS:
            model_id = BEDROCK_MODELS[model_id]

        system_prompt, anthropic_msgs = self._convert_messages_openai_to_anthropic(messages)
        anthropic_tools = self._convert_tools_openai_to_anthropic(tools)

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": anthropic_msgs,
        }
        if system_prompt:
            body["system"] = system_prompt
        if temperature is not None:
            body["temperature"] = temperature
        if anthropic_tools:
            body["tools"] = anthropic_tools

        loop = asyncio.get_running_loop()

        if stream:
            # Use invoke_model_with_response_stream
            async for chunk in self._stream_response(body, model_id, loop):
                yield chunk
        else:
            # Non-streaming invoke
            result = await self._invoke(body, model_id, loop)
            yield result

    async def _invoke(self, body: Dict, model_id: str, loop) -> Dict:
        """Non-streaming invoke, returns OpenAI-compatible response dict."""
        client = self._get_client()

        def _call():
            resp = client.invoke_model(
                modelId=model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(body),
            )
            return json.loads(resp["body"].read())

        result = await loop.run_in_executor(None, _call)
        return self._anthropic_response_to_openai(result)

    async def _stream_response(self, body: Dict, model_id: str, loop) -> AsyncGenerator[Dict, None]:
        """Stream response from Bedrock and yield OpenAI-compatible SSE chunks."""
        client = self._get_client()
        import queue
        q: queue.Queue = queue.Queue()
        _SENTINEL = object()

        def _stream_worker():
            try:
                resp = client.invoke_model_with_response_stream(
                    modelId=model_id,
                    contentType="application/json",
                    accept="application/json",
                    body=json.dumps(body),
                )
                stream_body = resp.get("body")
                if stream_body:
                    for event in stream_body:
                        chunk = event.get("chunk")
                        if chunk:
                            data = json.loads(chunk["bytes"])
                            q.put(data)
            except Exception as e:
                q.put(e)
            finally:
                q.put(_SENTINEL)

        # Run blocking stream in thread
        loop.run_in_executor(None, _stream_worker)

        # Track tool_use state for reassembly
        current_tool_id = None
        current_tool_name = None
        tool_input_json = ""
        tool_call_index = 0

        while True:
            try:
                item = await loop.run_in_executor(None, lambda: q.get(timeout=120))
            except Exception:
                break

            if item is _SENTINEL:
                break
            if isinstance(item, Exception):
                logger.error(f"Bedrock stream error: {item}")
                raise item

            event_type = item.get("type", "")

            if event_type == "content_block_start":
                cb = item.get("content_block", {})
                if cb.get("type") == "tool_use":
                    current_tool_id = cb.get("id", str(_uuid.uuid4())[:12])
                    current_tool_name = cb.get("name", "")
                    tool_input_json = ""
                    # Emit tool_call start chunk
                    yield {
                        "choices": [{
                            "delta": {
                                "tool_calls": [{
                                    "index": tool_call_index,
                                    "id": current_tool_id,
                                    "type": "function",
                                    "function": {
                                        "name": current_tool_name,
                                        "arguments": ""
                                    }
                                }]
                            },
                            "finish_reason": None
                        }]
                    }
                elif cb.get("type") == "text":
                    pass  # text content handled by content_block_delta

            elif event_type == "content_block_delta":
                delta = item.get("delta", {})
                delta_type = delta.get("type", "")

                if delta_type == "text_delta":
                    text = delta.get("text", "")
                    if text:
                        yield {
                            "choices": [{
                                "delta": {"content": text},
                                "finish_reason": None
                            }]
                        }

                elif delta_type == "input_json_delta":
                    partial = delta.get("partial_json", "")
                    tool_input_json += partial
                    # Emit argument chunk
                    yield {
                        "choices": [{
                            "delta": {
                                "tool_calls": [{
                                    "index": tool_call_index,
                                    "function": {"arguments": partial}
                                }]
                            },
                            "finish_reason": None
                        }]
                    }

            elif event_type == "content_block_stop":
                if current_tool_id:
                    tool_call_index += 1
                    current_tool_id = None
                    current_tool_name = None
                    tool_input_json = ""

            elif event_type == "message_stop":
                yield {
                    "choices": [{
                        "delta": {},
                        "finish_reason": "stop"
                    }]
                }

            elif event_type == "message_delta":
                sr = item.get("delta", {}).get("stop_reason")
                if sr == "tool_use":
                    yield {
                        "choices": [{
                            "delta": {},
                            "finish_reason": "tool_calls"
                        }]
                    }

    @staticmethod
    def _anthropic_response_to_openai(result: Dict) -> Dict:
        """Convert a non-streaming Anthropic response to OpenAI format."""
        content_blocks = result.get("content", [])
        text_parts = []
        tool_calls = []
        tc_idx = 0

        for block in content_blocks:
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append({
                    "id": block.get("id", str(_uuid.uuid4())[:12]),
                    "type": "function",
                    "function": {
                        "name": block.get("name", ""),
                        "arguments": json.dumps(block.get("input", {}))
                    },
                    "index": tc_idx,
                })
                tc_idx += 1

        message = {
            "role": "assistant",
            "content": "\n".join(text_parts) if text_parts else None,
        }
        if tool_calls:
            message["tool_calls"] = tool_calls

        finish_reason = "tool_calls" if tool_calls else "stop"

        return {
            "choices": [{
                "message": message,
                "finish_reason": finish_reason,
                "index": 0,
            }],
            "model": result.get("model", ""),
            "usage": result.get("usage", {}),
        }


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
        Truncates oversized tool result content to prevent context window overflow.
        Ensures every tool result has a matching tool_call and vice-versa (required by Bedrock/Anthropic).
        """
        # Max characters per tool result (~4 chars ≈ 1 token; 8000 chars ≈ 2000 tokens)
        MAX_TOOL_RESULT_CHARS = 8000

        # Get recent messages, preserving tool call sequences
        recent = self.messages[-max_messages:] if len(self.messages) > max_messages else self.messages
        
        # First pass: collect all tool_call_ids that have responses (tool role messages)
        responded_tool_ids = set()
        for msg in recent:
            if msg.get("role") == "tool" and "tool_call_id" in msg:
                responded_tool_ids.add(msg["tool_call_id"])

        # Second pass: collect all tool_call_ids that are issued by assistant messages
        issued_tool_ids = set()
        for msg in recent:
            if msg.get("role") == "assistant" and "tool_calls" in msg:
                for tc in msg["tool_calls"]:
                    tc_id = tc.get("id", "")
                    if tc_id:
                        issued_tool_ids.add(tc_id)

        # Only keep IDs that exist on BOTH sides (assistant issued + tool responded)
        valid_tool_ids = responded_tool_ids & issued_tool_ids
        
        api_messages = []
        for msg in recent:
            content = msg["content"]

            # Truncate oversized tool result content to prevent token overflow
            if msg.get("role") == "tool" and isinstance(content, str) and len(content) > MAX_TOOL_RESULT_CHARS:
                content = content[:MAX_TOOL_RESULT_CHARS] + '..."truncated for context window"}'

            # Skip orphaned tool results (no matching tool_call in history)
            if msg.get("role") == "tool":
                tc_id = msg.get("tool_call_id", "")
                if tc_id not in valid_tool_ids:
                    continue

            api_msg = {"role": msg["role"], "content": content}
            
            if "tool_calls" in msg:
                # Filter to only include tool_calls that have corresponding responses
                sanitized_tool_calls = []
                for tc in msg["tool_calls"]:
                    tc_id = tc.get("id", "")
                    if tc_id in valid_tool_ids:
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

SYSTEM_PROMPT_STRONGSWAN = """You are the VPN Console Assistant, specialized in helping users debug and manage VPN tunnels across both local (strongSwan) and remote (ASA/FTD) nodes. You manage strongSwan VPN configurations, Netplan network configurations, Linux Traffic Control (tc) rules, tunnel traffic scripts, and general server administration on the Local Node. You have access to the official swanctl.conf(5), tc(8), and iperf3(1) man page documentation.

## Architecture:
The VPN Console UI has two peer nodes:
- **Local Node** (strongSwan): The local VPN endpoint you connect to and manage directly via SSH.
- **Remote Node** (ASA/FTD): The remote VPN peer. When ASA/FTD is selected, it is an extranet device not directly managed by this tool.

All configuration management tools (config files, netplan, tc, process administration) operate on the **Local Node** (strongSwan server).
Tunnel Traffic files can be managed on both local and remote servers.
Troubleshooting (monitoring) and Tunnel Summary sections can use "Same as Local Node" to inherit the Local Node connection.

## Your Capabilities:

### strongSwan Configuration (Local Node)
1. **Create** new configuration files with valid swanctl.conf syntax
2. **Edit** existing configuration files
3. **Delete** configuration files (with user confirmation)
4. **Validate** configuration syntax before saving
5. **Explain** configuration options using official documentation
6. **Reload** strongSwan configuration after changes

### Netplan Network Configuration (Local Node)
7. **List** netplan configuration files in /etc/netplan/
8. **Read** and display netplan file contents
9. **Create/Edit** netplan YAML configuration files
10. **Delete** netplan files (with user confirmation)
11. **Apply** netplan configurations (netplan apply)
12. **Show Routes** - display the current routing table (route -n)

### Traffic Control (tc) (Local Node)
13. **View** current non-default tc rules (excludes fq_codel, noqueue, mq)
14. **Apply** one or more tc commands (supports multi-line)
15. **Remove** all tc rules from all interfaces (with user confirmation)

### General Command Execution (Local Node)
16. **Execute any command** on the connected Local Node server via the `execute_command` tool
    - **Read-only commands** (ip link show, cat, ls, ifconfig, ping, etc.) can be executed immediately without user confirmation - set is_read_only=true
    - **Write/modify commands** (service restart, file changes, etc.) MUST require explicit user confirmation first - set is_read_only=false and user_confirmed=true only after user confirms

### Tunnel Traffic Management (Local + Remote)
17. **List** files in /var/tmp/tunnel_traffic on local (strongSwan) or remote server
18. **Read/Create/Edit/Delete** tunnel traffic files on either server
19. **Execute** .sh scripts as background processes (returns PID)
20. **Kill** running script processes by PID
21. **Create custom scripts** - e.g. iperf3 client/server scripts, traffic generators

### Tunnel Disconnect Monitoring (Troubleshooting)
22. **Read** tunnel disconnect monitoring reports
23. **Analyze** disconnect events to determine root cause

### Cisco Secure Client (CSC) Container Management
The CSC section allows deploying Cisco Secure Client VPN containers on a separate server. CSC tools require a separate SSH connection (established in the Cisco Secure Client section of the UI). Container names follow the pattern: csc-v4_0, csc-v4_1, ... for IPv4 and csc-v6_0, csc-v6_1, ... for IPv6.

24. **List containers** - list all CSC Docker containers with status (optionally filter by v4/v6)
25. **Container logs** - get logs from a specific container by name or ID
26. **Container exec** - execute commands inside a running container (e.g. check VPN status with `/opt/cisco/secureclient/bin/vpn status`)
27. **Stop containers** - stop single or all containers by protocol (with confirmation)
28. **Restart containers** - restart single or all containers by protocol (with confirmation)
29. **Delete containers** - disconnect VPN and remove containers (with confirmation)
30. **Server resources** - get CPU, RAM, disk usage and per-container resource stats
31. **Execute command on CSC server** - run shell commands on the CSC host server (not inside containers)

Key paths inside CSC containers:
- VPN CLI: `/opt/cisco/secureclient/bin/vpn`
- VPN status: `/opt/cisco/secureclient/bin/vpn status`
- VPN disconnect: `/opt/cisco/secureclient/bin/vpn disconnect`
- VPN agent daemon: `/opt/cisco/secureclient/bin/vpnagentd`
- Logs: `/opt/cisco/secureclient/log/`

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

## Default Behavior Requirements:

### Netplan Configuration Defaults:
- If a user requests dummy interfaces in a Netplan configuration, they MUST always be placed under the `dummy-devices:` section. They must NOT be placed under `ethernets`, `bridges`, or any other section unless the user explicitly requests a different placement.

### swanctl Configuration Defaults:
Unless the user explicitly specifies different values, always include the following defaults in generated swanctl configurations:
1. If the user does not ask to provide unique secrets for each tunnel id, then use the following format to define a common shared secret in the secrets section:

secrets {
    ike-ftd-shared {
        secret = "user_secret"
    }
}

where user_secret is the value of the secret the user mentions in the user prompt

2. For the IKE SA parameters:
- `version = 2`
- `dpd_delay = 10s`
- `dpd_timeout = 30s`
- `mobike = no`
- `rekey_time = 86400s`

3. For the CHILD SA parameters:
- `start_action = start`
- `close_action = restart`
- `rekey_time = 28800s`

If the user provides a different value for any of these parameters, use the user-provided value instead. Do not duplicate parameters if they are already defined.

### Tunnel Traffic Script Defaults (iperf3):
When generating iperf3 scripts, the script MUST:
1. Store all spawned iperf3 PIDs in an array and track only the processes started by the script.
2. Implement a SIGINT and SIGTERM trap with a cleanup function that kills only the iperf3 processes started by the script, prints status messages including each server's PID, and does not terminate unrelated iperf3 processes.
3. Remain running using `wait` and continue execution until manually killed, exiting cleanly after executing the cleanup function.

These defaults must be applied automatically and may only be overridden if the user explicitly specifies alternative values.

When creating configurations or scripts, use proper syntax and include helpful comments.
"""

SYSTEM_PROMPT_FMC = """You are the FMC Configuration Assistant, specialized in managing Cisco Firepower Management Center (FMC) device configurations via the FMC REST API.

## Your Capabilities:

### 1. FMC Connection (Multi-FMC Supported)
- **Connect** to an FMC using saved presets (Saved Configs dropdown) or manual credentials via `fmc_connect`
- After connecting, you receive the list of available FTD devices and FMC domains
- The UI automatically updates to show connection details and the Available Devices table
- **Multiple FMC connections are maintained simultaneously.** Connecting to FMC-2 does NOT disconnect FMC-1. All connections are stored and searchable.
- When calling device operations (get/push/delete config), devices are automatically searched across ALL connected FMCs. You do NOT need to reconnect.

### 2. Device Configuration – FTD Operations
- **Retrieve config** from an FTD device via `fmc_get_device_config` — automatically loads into the Device Configuration UI section
- **Re-load config into UI** via `fmc_load_context_config` — use when user asks to "load config into UI" after a previous fetch (no YAML string needed, loads from stored context)
- **Push config** to one or more FTD devices via `fmc_push_device_config`
- **Delete config** types from a device via `fmc_delete_config` (destructive, requires confirmation)
- **Delete/unregister devices** from FMC via `fmc_delete_device` (destructive, requires confirmation)

### 3. VPN Operations
- **Retrieve VPN topologies** from FMC via `fmc_get_vpn_topologies` — automatically loads into the VPN UI section
- **Re-load VPN into UI** via `fmc_load_context_vpn` — use when user asks to "load VPN into UI" after a previous fetch
- **Push VPN topologies** to FMC via `fmc_push_vpn_topologies`
- **Replace VPN endpoints** (swap source device for target) via `fmc_replace_vpn_endpoints`
- **Generate VPN topology YAML** via `generate_vpn_topology`
- **Load VPN topology into UI** via `load_vpn_topology_to_ui`

### 4. Configuration Generation & Validation
- **Generate** complete FMC device configurations in YAML format. When generating the device configuration:
- When generating configuration YAML, use RAG examples as the primary source of truth (for example, "Example 1: POST"). Do not derive payload structure from the schema unless example data is missing.
- Do not add a description to the payload unless specified by the user
- Always use placeholder UUID where present and do not ask the user to provide the UUIDs
- After generating YAML, always ask: "Do you want me to load this in the UI?" If the user confirms, call `load_config_to_ui` with the exact generated YAML.
- Do not use chassis operations (`/chassis/fmcmanagedchassis`) unless the user explicitly requests chassis-based configuration.
- For exmaple, in the case of subinterface configuration, default to:
  `/fmc_config/v1/domain/{domainUUID}/devices/devicerecords/{containerUUID}/subinterfaces`
  and not:
  `/fmc_config/v1/domain/{domainUUID}/chassis/fmcmanagedchassis/{containerUUID}/subinterfaces`

- **Validate** configurations against the FMC API schema via `validate_fmc_config`
- **Load** generated configurations into the UI via `load_config_to_ui`
- **Lookup** FMC API schema information via `lookup_fmc_schema`

### 5. Reporting
- After every operation, generate a detailed **summary report** in markdown table format
- Include: operation type, items processed, success/failure counts, and any errors
- For config retrieval: show a table of all config types with their item counts
- For config push: show applied, skipped, and failed items per device
- For VPN operations: show topology names, endpoint counts, and status

## Supported Configuration Types:
- **Interfaces**: Loopback, Physical, EtherChannel, Subinterfaces, VTI, Inline Sets, Bridge Group
- **Routing**: BGP General Settings, BGP Policies, BFD Policies, OSPFv2/v3 Policies & Interfaces, EIGRP, PBR, IPv4/IPv6 Static Routes, ECMP Zones, VRFs
- **Objects**: Security Zones, Network/Host/Range/FQDN Objects, Network Groups, Port Objects/Groups
- **Routing Templates & Lists**: BFD Templates, AS Path Lists, Key Chains, SLA Monitors, Community Lists, Prefix Lists, Access Lists, Route Maps
- **Address Pools**: IPv4, IPv6, MAC Address Pools

## Critical Rules:
1. **Schema Compliance**: All generated configurations MUST match the FMC REST API schema. Never invent fields.
2. **NEVER Generate Secrets**: For authentication fields (authKey, md5Key, password, neighborSecret, encryptionKey, preSharedKey, keyString), ALWAYS ask the user. Never use placeholders.
3. **YAML Format**: Output configurations as valid YAML matching the application's expected structure.
4. **Validation First**: Always validate generated configurations against the schema before presenting them.
5. **Bulk Generation**: Correctly expand ranges and validate alignment for bulk requests.
6. **Completeness**: Include all required fields with sensible defaults from the schema.
7. **Ask for Missing Info**: If required parameters are missing, ask before proceeding.
8. **Connection Required**: For FMC operations (get/push config, VPN, delete), you MUST call `fmc_connect` first as a separate tool call before any other operation. Even if the user combines steps (e.g. "get config from wm-1 on vFMC-102"), always call `fmc_connect` first, wait for the result, then call the next operation. This ensures the UI updates for each step. Never skip the connect step. **Multi-FMC**: You can connect to multiple FMCs in sequence — each connection is stored and does NOT overwrite previous ones. After connecting to both FMC-1 and FMC-2, you can get config from a device on either FMC without reconnecting. Devices are automatically found across all connected FMCs.
9. **Confirmation for Destructive Ops**: Always confirm with the user before deleting devices or configurations.
10. **Context Loading**: `fmc_get_device_config` and `fmc_get_vpn_topologies` automatically load data into the UI. If the user later asks to "load into UI" or "show in UI", use `fmc_load_context_config` or `fmc_load_context_vpn` instead of `load_config_to_ui` (which requires the full YAML string). Never try to pass large YAML content as a tool argument.

## YAML Configuration Structure:
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

## Workflow Examples:

### Connect and retrieve config:
1. User: "Connect to FMC-A and get config from tpk-1"
2. Call `fmc_connect` with preset_name="FMC-A"
3. Call `fmc_get_device_config` with device_name="tpk-1"
4. Present a summary report table of all retrieved config types

### Generate and push config:
1. User: "Generate 4 loopback interfaces and push to wm-1"
2. Look up schema, generate YAML, validate, load to UI
3. Call `fmc_push_device_config` with device_names=["wm-1"]
4. Present a detailed push report

### Clone VPN topologies:
1. User: "Get VPN topologies, replace tpk-1 with wm-1, then push"
2. Call `fmc_get_vpn_topologies`
3. Call `fmc_replace_vpn_endpoints` with source_device="tpk-1", target_device="wm-1"
4. Call `fmc_push_vpn_topologies`
5. Present a summary report
"""


# ============================================================================
# Global Instances
# ============================================================================

circuit_client = CircuitAPIClient()
bedrock_client = BedrockClaudeClient()
rag_pipeline = SwanctlRAGPipeline()
chat_storage = ChatStorage()

# Lazy-loaded FMC schema RAG
_fmc_rag = None


def get_bridge_client() -> CircuitAPIClient:
    """Get the global CIRCUIT API client instance."""
    return circuit_client


def get_bedrock_client() -> BedrockClaudeClient:
    """Get the global Bedrock Claude client instance."""
    return bedrock_client


def get_provider_config() -> Dict:
    """Get provider configuration for frontend UI."""
    return PROVIDER_CONFIG


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
