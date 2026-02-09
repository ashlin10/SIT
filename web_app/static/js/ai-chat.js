/**
 * AI Chat Panel - Global JavaScript Module
 * 
 * This module handles:
 * - Chat panel open/close state (persisted across pages)
 * - Session management (create, switch, delete)
 * - Message sending with streaming support
 * - Tool call handling and confirmation dialogs
 * - Markdown rendering for AI responses
 */

(function() {
    'use strict';

    // ========================================================================
    // State Management
    // ========================================================================
    
    const aiState = {
        isOpen: false,
        currentSessionId: null,
        sessions: [],
        isLoading: false,
        contextMode: 'general',
        pendingToolCalls: [],
        eventSource: null,
        panelWidth: 420,
        isResizing: false
    };

    // Load persisted state from localStorage
    function loadPersistedState() {
        try {
            const saved = localStorage.getItem('vyper_ai_chat_state');
            if (saved) {
                const parsed = JSON.parse(saved);
                aiState.isOpen = parsed.isOpen || false;
                aiState.currentSessionId = parsed.currentSessionId || null;
                aiState.contextMode = parsed.contextMode || 'general';
                aiState.panelWidth = parsed.panelWidth || 420;
            }
        } catch (e) {
            console.warn('Failed to load AI chat state:', e);
        }
    }

    // Save state to localStorage
    function savePersistedState() {
        try {
            localStorage.setItem('vyper_ai_chat_state', JSON.stringify({
                isOpen: aiState.isOpen,
                currentSessionId: aiState.currentSessionId,
                contextMode: aiState.contextMode,
                panelWidth: aiState.panelWidth
            }));
        } catch (e) {
            console.warn('Failed to save AI chat state:', e);
        }
    }

    // ========================================================================
    // DOM Elements
    // ========================================================================
    
    let elements = {};

    function initializeElements() {
        elements = {
            panel: document.getElementById('ai-chat-panel'),
            toggleBtn: document.getElementById('ai-chat-toggle'),
            closeBtn: document.getElementById('ai-chat-close'),
            newChatBtn: document.getElementById('ai-new-chat'),
            sessionsBtn: document.getElementById('ai-chat-sessions'),
            sessionsList: document.getElementById('ai-sessions-list'),
            sessionsContent: document.getElementById('ai-sessions-content'),
            sessionsClose: document.getElementById('ai-sessions-close'),
            contextMode: document.getElementById('ai-context-mode'),
            messages: document.getElementById('ai-messages'),
            input: document.getElementById('ai-input'),
            sendBtn: document.getElementById('ai-send')
        };
    }

    // ========================================================================
    // Panel Open/Close
    // ========================================================================
    
    function openPanel() {
        if (!elements.panel) return;
        
        aiState.isOpen = true;
        elements.panel.classList.remove('collapsed');
        elements.panel.classList.add('expanded');
        applyPanelWidth();
        document.body.classList.add('ai-chat-open');
        elements.toggleBtn?.classList.add('active');
        
        savePersistedState();
        
        // Load sessions if not loaded
        if (aiState.sessions.length === 0) {
            loadSessions();
        }
        
        // Load current session messages
        if (aiState.currentSessionId) {
            loadSessionMessages(aiState.currentSessionId);
        }
        
        // Focus input
        setTimeout(() => elements.input?.focus(), 300);
    }

    function applyPanelWidth() {
        if (!elements.panel) return;
        const w = Math.max(320, Math.min(aiState.panelWidth, window.innerWidth - 280));
        elements.panel.style.width = w + 'px';
        document.documentElement.style.setProperty('--ai-panel-width', w + 'px');
    }

    function closePanel() {
        if (!elements.panel) return;
        
        aiState.isOpen = false;
        elements.panel.classList.add('collapsed');
        elements.panel.classList.remove('expanded');
        document.body.classList.remove('ai-chat-open');
        elements.toggleBtn?.classList.remove('active');
        
        // Close sessions list if open
        elements.sessionsList?.classList.add('hidden');
        
        savePersistedState();
    }

    function togglePanel() {
        if (aiState.isOpen) {
            closePanel();
        } else {
            openPanel();
        }
    }

    // ========================================================================
    // Session Management
    // ========================================================================
    
    async function loadSessions() {
        try {
            const response = await fetch('/api/ai/sessions');
            const data = await response.json();
            
            if (data.success) {
                aiState.sessions = data.sessions || [];
                renderSessionsList();
            }
        } catch (e) {
            console.error('Failed to load sessions:', e);
        }
    }

    function renderSessionsList() {
        if (!elements.sessionsContent) return;
        
        if (aiState.sessions.length === 0) {
            elements.sessionsContent.innerHTML = `
                <div class="ai-sessions-empty" style="padding: 1rem; text-align: center; color: #9ca3af;">
                    <i class="fas fa-comments" style="font-size: 1.5rem; margin-bottom: 0.5rem;"></i>
                    <p>No chat history yet</p>
                </div>
            `;
            return;
        }
        
        elements.sessionsContent.innerHTML = aiState.sessions.map(session => `
            <div class="ai-session-item ${session.session_id === aiState.currentSessionId ? 'active' : ''}" 
                 data-session-id="${session.session_id}">
                <div class="ai-session-info">
                    <div class="ai-session-title">${escapeHtml(session.title)}</div>
                    <div class="ai-session-meta">${session.message_count} messages · ${formatDate(session.updated_at)}</div>
                </div>
                <button class="ai-session-delete" data-session-id="${session.session_id}" title="Delete chat">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `).join('');
        
        // Add click handlers
        elements.sessionsContent.querySelectorAll('.ai-session-item').forEach(item => {
            item.addEventListener('click', (e) => {
                if (!e.target.closest('.ai-session-delete')) {
                    switchSession(item.dataset.sessionId);
                }
            });
        });
        
        elements.sessionsContent.querySelectorAll('.ai-session-delete').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                deleteSession(btn.dataset.sessionId);
            });
        });
    }

    async function createNewSession() {
        try {
            const response = await fetch('/api/ai/sessions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: 'New Chat',
                    context_mode: aiState.contextMode
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                aiState.currentSessionId = data.session.session_id;
                aiState.sessions.unshift({
                    session_id: data.session.session_id,
                    title: data.session.title,
                    message_count: 0,
                    updated_at: data.session.created_at
                });
                
                renderSessionsList();
                clearMessages();
                showWelcomeMessage();
                savePersistedState();
                
                elements.sessionsList?.classList.add('hidden');
            }
        } catch (e) {
            console.error('Failed to create session:', e);
            showError('Failed to create new chat');
        }
    }

    async function switchSession(sessionId) {
        if (sessionId === aiState.currentSessionId) {
            elements.sessionsList?.classList.add('hidden');
            return;
        }
        
        aiState.currentSessionId = sessionId;
        savePersistedState();
        
        await loadSessionMessages(sessionId);
        renderSessionsList();
        elements.sessionsList?.classList.add('hidden');
    }

    async function loadSessionMessages(sessionId) {
        try {
            const response = await fetch(`/api/ai/sessions/${sessionId}`);
            const data = await response.json();
            
            if (data.success && data.session) {
                aiState.contextMode = data.session.context_mode || 'general';
                if (elements.contextMode) {
                    elements.contextMode.value = aiState.contextMode;
                }
                
                renderMessages(data.session.messages || []);
            }
        } catch (e) {
            console.error('Failed to load session messages:', e);
        }
    }

    async function deleteSession(sessionId) {
        if (!confirm('Delete this chat? This cannot be undone.')) return;
        
        try {
            const response = await fetch(`/api/ai/sessions/${sessionId}`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.success) {
                aiState.sessions = aiState.sessions.filter(s => s.session_id !== sessionId);
                
                if (aiState.currentSessionId === sessionId) {
                    aiState.currentSessionId = null;
                    clearMessages();
                    showWelcomeMessage();
                }
                
                renderSessionsList();
                savePersistedState();
            }
        } catch (e) {
            console.error('Failed to delete session:', e);
            showError('Failed to delete chat');
        }
    }

    // ========================================================================
    // Message Rendering
    // ========================================================================
    
    function clearMessages() {
        if (elements.messages) {
            elements.messages.innerHTML = '';
        }
    }

    function showWelcomeMessage() {
        if (!elements.messages) return;
        
        elements.messages.innerHTML = `
            <div class="ai-welcome-message">
                <i class="fas fa-robot ai-welcome-icon"></i>
                <h3>Welcome to Vyper AI</h3>
                <p>I can help you with networking questions and strongSwan configuration. Select "strongSwan Config Assistant" mode to manage configuration files.</p>
            </div>
        `;
    }

    function renderMessages(messages) {
        if (!elements.messages) return;
        
        if (!messages || messages.length === 0) {
            showWelcomeMessage();
            return;
        }
        
        elements.messages.innerHTML = messages
            .filter(m => m.role !== 'system')
            .map(m => renderMessage(m))
            .join('');
        
        scrollToBottom();
    }

    function renderMessage(message) {
        const role = message.role;
        const content = message.content || '';
        
        if (role === 'user') {
            return `
                <div class="ai-message user">
                    <div class="ai-message-avatar"><i class="fas fa-user"></i></div>
                    <div class="ai-message-content">${escapeHtml(content)}</div>
                </div>
            `;
        } else if (role === 'assistant') {
            let html = `
                <div class="ai-message assistant">
                    <div class="ai-message-avatar"><i class="fas fa-robot"></i></div>
                    <div class="ai-message-content">${renderMarkdown(content)}</div>
                </div>
            `;
            
            // Render tool calls if present
            if (message.tool_calls && message.tool_calls.length > 0) {
                html += message.tool_calls.map(tc => renderToolCall(tc)).join('');
            }
            
            return html;
        } else if (role === 'tool') {
            return renderToolResult(content, message.tool_call_id);
        }
        
        return '';
    }

    function renderToolCall(toolCall) {
        const name = toolCall.function?.name || 'Unknown tool';
        const displayName = formatToolName(name);
        let args = {};
        try {
            args = JSON.parse(toolCall.function?.arguments || '{}');
        } catch (e) {}
        
        // Show relevant summary instead of raw JSON
        let summary = '';
        if (args.filename) summary = `File: ${escapeHtml(args.filename)}`;
        else if (args.content) summary = `Content: ${escapeHtml(args.content.substring(0, 80))}...`;
        
        return `
            <div class="ai-tool-call">
                <div class="ai-tool-call-header">
                    <i class="fas fa-cog fa-spin"></i>
                    <span>${escapeHtml(displayName)}</span>
                </div>
                ${summary ? `<div class="ai-tool-summary">${summary}</div>` : ''}
            </div>
        `;
    }

    function formatToolName(name) {
        const names = {
            'list_config_files': 'Listing configuration files',
            'read_config_file': 'Reading configuration file',
            'validate_config_syntax': 'Validating configuration syntax',
            'save_config_file': 'Saving configuration file',
            'delete_config_file': 'Deleting configuration file',
            'reload_strongswan_config': 'Reloading strongSwan configuration',
            'edit_config_file': 'Editing configuration file'
        };
        return names[name] || name;
    }

    function renderToolResult(content, toolCallId) {
        let result = {};
        try {
            result = JSON.parse(content);
        } catch (e) {
            result = { message: content };
        }
        
        const isError = result.success === false || result.error;
        
        return `
            <div class="ai-tool-result ${isError ? 'error' : ''}">
                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
                    <i class="fas ${isError ? 'fa-exclamation-circle' : 'fa-check-circle'}"></i>
                    <strong>${isError ? 'Error' : 'Result'}</strong>
                </div>
                ${formatToolResultContent(result)}
            </div>
        `;
    }

    function formatToolResultContent(result) {
        // Format tool results as human-readable HTML instead of raw JSON
        let html = '';
        
        // Show message first if present
        if (result.message) {
            html += `<div class="ai-tool-msg">${escapeHtml(result.message)}</div>`;
        }
        if (result.error) {
            html += `<div class="ai-tool-msg" style="color:#dc2626;">${escapeHtml(result.error)}</div>`;
        }
        
        // File listing
        if (result.files && Array.isArray(result.files)) {
            html += '<div class="ai-tool-file-list">';
            result.files.forEach(f => {
                const sizeStr = f.size > 1024 ? `${(f.size / 1024).toFixed(1)} KB` : `${f.size} B`;
                html += `<div class="ai-tool-file-item">
                    <i class="fas fa-file-code"></i>
                    <span class="ai-tool-file-name">${escapeHtml(f.name)}</span>
                    <span class="ai-tool-file-size">${sizeStr}</span>
                </div>`;
            });
            html += '</div>';
        }
        
        // File content (read/edit)
        if (result.content && typeof result.content === 'string' && result.content.length > 0) {
            html += `<div class="ai-code-block-wrapper">
                <div class="ai-code-block-header">
                    <span>${escapeHtml(result.filename || 'Configuration')}</span>
                    <button class="ai-copy-btn" onclick="window._aiCopyText(this)" title="Copy to clipboard">
                        <i class="fas fa-copy"></i> Copy
                    </button>
                </div>
                <pre class="ai-code-block"><code>${escapeHtml(result.content)}</code></pre>
            </div>`;
        }
        
        // Validation result
        if (result.valid !== undefined) {
            html += `<div class="ai-tool-msg">${result.valid ? '<i class="fas fa-check" style="color:#16a34a"></i> Syntax is valid' : '<i class="fas fa-times" style="color:#dc2626"></i> Syntax validation failed'}</div>`;
            if (result.errors && result.errors.length > 0) {
                html += '<ul class="ai-tool-error-list">';
                result.errors.forEach(e => html += `<li>${escapeHtml(e)}</li>`);
                html += '</ul>';
            }
            if (result.warnings && result.warnings.length > 0) {
                html += '<ul class="ai-tool-warn-list">';
                result.warnings.forEach(w => html += `<li>${escapeHtml(w)}</li>`);
                html += '</ul>';
            }
        }
        
        // Reload output
        if (result.output && !result.content) {
            html += `<pre class="ai-code-block"><code>${escapeHtml(result.output)}</code></pre>`;
        }
        
        // Fallback: if nothing was rendered, show a summary
        if (!html) {
            html = `<div class="ai-tool-msg">${escapeHtml(JSON.stringify(result, null, 2))}</div>`;
        }
        
        return html;
    }

    function addMessage(role, content, toolCalls = null) {
        if (!elements.messages) return;
        
        // Remove welcome message if present
        const welcome = elements.messages.querySelector('.ai-welcome-message');
        if (welcome) {
            welcome.remove();
        }
        
        const messageEl = document.createElement('div');
        messageEl.innerHTML = renderMessage({ role, content, tool_calls: toolCalls });
        elements.messages.appendChild(messageEl.firstElementChild);
        
        if (toolCalls) {
            toolCalls.forEach(tc => {
                const toolEl = document.createElement('div');
                toolEl.innerHTML = renderToolCall(tc);
                elements.messages.appendChild(toolEl.firstElementChild);
            });
        }
        
        scrollToBottom();
    }

    function addStreamingMessage() {
        if (!elements.messages) return null;
        
        // Remove welcome message if present
        const welcome = elements.messages.querySelector('.ai-welcome-message');
        if (welcome) {
            welcome.remove();
        }
        
        const messageEl = document.createElement('div');
        messageEl.className = 'ai-message assistant';
        messageEl.innerHTML = `
            <div class="ai-message-avatar"><i class="fas fa-robot"></i></div>
            <div class="ai-message-content ai-streaming-content"></div>
        `;
        elements.messages.appendChild(messageEl);
        
        scrollToBottom();
        return messageEl.querySelector('.ai-streaming-content');
    }

    function showTypingIndicator() {
        if (!elements.messages) return;
        
        const typing = document.createElement('div');
        typing.className = 'ai-typing';
        typing.id = 'ai-typing-indicator';
        typing.innerHTML = `
            <div class="ai-typing-dots">
                <div class="ai-typing-dot"></div>
                <div class="ai-typing-dot"></div>
                <div class="ai-typing-dot"></div>
            </div>
        `;
        elements.messages.appendChild(typing);
        scrollToBottom();
    }

    function hideTypingIndicator() {
        const typing = document.getElementById('ai-typing-indicator');
        if (typing) {
            typing.remove();
        }
    }

    function scrollToBottom() {
        if (elements.messages) {
            elements.messages.scrollTop = elements.messages.scrollHeight;
        }
    }

    function showError(message) {
        if (!elements.messages) return;
        
        const errorEl = document.createElement('div');
        errorEl.className = 'ai-tool-result error';
        errorEl.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-exclamation-triangle"></i>
                <span>${escapeHtml(message)}</span>
            </div>
        `;
        elements.messages.appendChild(errorEl);
        scrollToBottom();
    }

    // ========================================================================
    // Send Message
    // ========================================================================
    
    async function sendMessage() {
        const message = elements.input?.value?.trim();
        if (!message || aiState.isLoading) return;
        
        aiState.isLoading = true;
        updateSendButton();
        
        // Add user message to UI
        addMessage('user', message);
        elements.input.value = '';
        autoResizeTextarea();
        
        showTypingIndicator();
        
        try {
            // Create session if none exists
            if (!aiState.currentSessionId) {
                const createRes = await fetch('/api/ai/sessions', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title: message.substring(0, 50),
                        context_mode: aiState.contextMode
                    })
                });
                const createData = await createRes.json();
                if (createData.success) {
                    aiState.currentSessionId = createData.session.session_id;
                    aiState.sessions.unshift({
                        session_id: createData.session.session_id,
                        title: message.substring(0, 50),
                        message_count: 0,
                        updated_at: new Date().toISOString()
                    });
                    renderSessionsList();
                    savePersistedState();
                }
            }
            
            // Send message with streaming using fetch (EventSource only supports GET)
            const response = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: message,
                    session_id: aiState.currentSessionId,
                    context_mode: aiState.contextMode,
                    stream: true
                })
            });
            
            hideTypingIndicator();
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            // Handle SSE stream
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let streamingEl = addStreamingMessage();
            let fullContent = '';
            let buffer = '';
            
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop() || '';
                
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = line.slice(6);
                        if (data === '[DONE]') continue;
                        
                        try {
                            const parsed = JSON.parse(data);
                            
                            if (parsed.content) {
                                fullContent += parsed.content;
                                if (streamingEl) {
                                    streamingEl.innerHTML = renderMarkdown(fullContent);
                                    addCopyButtonsToCodeBlocks(streamingEl);
                                    scrollToBottom();
                                }
                            }
                            
                            if (parsed.tool_calls) {
                                // Handle tool calls and feed results back to AI
                                await handleToolCalls(parsed.tool_calls);
                            }
                            
                            if (parsed.error) {
                                showError(parsed.error);
                            }
                        } catch (e) {
                            // Ignore parse errors for partial data
                        }
                    } else if (line.startsWith('event: ')) {
                        // Handle event type
                    }
                }
            }
            
            // Update session in list
            const sessionIdx = aiState.sessions.findIndex(s => s.session_id === aiState.currentSessionId);
            if (sessionIdx !== -1) {
                aiState.sessions[sessionIdx].message_count += 2;
                aiState.sessions[sessionIdx].updated_at = new Date().toISOString();
                if (aiState.sessions[sessionIdx].title === 'New Chat') {
                    aiState.sessions[sessionIdx].title = message.substring(0, 50);
                }
            }
            
        } catch (e) {
            hideTypingIndicator();
            console.error('Failed to send message:', e);
            showError('Failed to send message. Please try again.');
        } finally {
            aiState.isLoading = false;
            updateSendButton();
        }
    }

    async function handleToolCalls(toolCalls) {
        const toolResults = [];
        
        for (const tc of toolCalls) {
            const name = tc.function?.name;
            let args = {};
            try {
                args = JSON.parse(tc.function?.arguments || '{}');
            } catch (e) {}
            
            // Check if confirmation is needed
            const confirmTools = {
                'save_config_file': 'save', 'delete_config_file': 'delete', 'edit_config_file': 'edit',
                'load_config_to_ui': 'load into Device Configuration',
                'load_vpn_topology_to_ui': 'load into Create VPN Topology'
            };
            if (confirmTools[name] && !args.user_confirmed) {
                const action = confirmTools[name];
                const filename = args.filename || 'this file';
                
                if (!confirm(`The AI wants to ${action} "${filename}". Do you want to proceed?`)) {
                    const cancelResult = { success: false, error: 'User cancelled the operation' };
                    toolResults.push({ tool_call_id: tc.id, result: cancelResult });
                    
                    const resultEl = document.createElement('div');
                    resultEl.innerHTML = renderToolResult(JSON.stringify(cancelResult), tc.id);
                    elements.messages?.appendChild(resultEl.firstElementChild);
                    scrollToBottom();
                    continue;
                }
                
                args.user_confirmed = true;
            }
            
            // Show tool call indicator
            const toolCallEl = document.createElement('div');
            toolCallEl.innerHTML = renderToolCall(tc);
            elements.messages?.appendChild(toolCallEl.firstElementChild);
            scrollToBottom();
            
            // Execute tool
            try {
                const response = await fetch('/api/ai/tool-execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        tool_name: name,
                        arguments: args,
                        session_id: aiState.currentSessionId,
                        tool_call_id: tc.id,
                        context_mode: aiState.contextMode
                    })
                });
                
                const result = await response.json();
                toolResults.push({ tool_call_id: tc.id, result: result });
                
                // Handle load_config action from FMC tools
                if (result.action === 'load_config' && result.success && typeof window.applyFmcConfigToUI === 'function') {
                    try {
                        window.applyFmcConfigToUI(result.config, result.counts, result.filename, result.config_yaml);
                    } catch (loadErr) {
                        console.warn('Failed to load config into UI:', loadErr);
                    }
                }
                
                // Handle load_vpn_topology action from VPN tools
                if (result.action === 'load_vpn_topology' && result.success && typeof window.applyVpnTopologyToUI === 'function') {
                    try {
                        window.applyVpnTopologyToUI(result.topologies, result.vpn_yaml, result.filename);
                    } catch (loadErr) {
                        console.warn('Failed to load VPN topology into UI:', loadErr);
                    }
                }
                
                // Add tool result to messages
                const resultEl = document.createElement('div');
                resultEl.innerHTML = renderToolResult(JSON.stringify(result), tc.id);
                elements.messages?.appendChild(resultEl.firstElementChild);
                scrollToBottom();
                
            } catch (e) {
                console.error('Tool execution failed:', e);
                const errResult = { success: false, error: e.message };
                toolResults.push({ tool_call_id: tc.id, result: errResult });
                showError(`Tool "${name}" failed: ${e.message}`);
            }
        }
        
        // Send tool results back to AI so it can continue the conversation
        if (toolResults.length > 0) {
            await continueWithToolResults(toolCalls, toolResults);
        }
    }

    async function continueWithToolResults(toolCalls, toolResults) {
        // Send tool results back to the AI to continue the multi-step flow
        showTypingIndicator();
        
        try {
            const response = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    tool_results: toolResults.map(tr => ({
                        tool_call_id: tr.tool_call_id,
                        content: JSON.stringify(tr.result)
                    })),
                    tool_calls: toolCalls.map(tc => ({
                        id: tc.id,
                        type: tc.type || 'function',
                        function: tc.function
                    })),
                    session_id: aiState.currentSessionId,
                    context_mode: aiState.contextMode,
                    stream: true
                })
            });
            
            hideTypingIndicator();
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            // Handle SSE stream (same as sendMessage)
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let streamingEl = addStreamingMessage();
            let fullContent = '';
            let buffer = '';
            
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop() || '';
                
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = line.slice(6);
                        if (data === '[DONE]') continue;
                        
                        try {
                            const parsed = JSON.parse(data);
                            
                            if (parsed.content) {
                                fullContent += parsed.content;
                                if (streamingEl) {
                                    streamingEl.innerHTML = renderMarkdown(fullContent);
                                    addCopyButtonsToCodeBlocks(streamingEl);
                                    scrollToBottom();
                                }
                            }
                            
                            if (parsed.tool_calls) {
                                await handleToolCalls(parsed.tool_calls);
                            }
                            
                            if (parsed.error) {
                                showError(parsed.error);
                            }
                        } catch (e) {
                            // Ignore parse errors for partial data
                        }
                    }
                }
            }
        } catch (e) {
            hideTypingIndicator();
            console.error('Failed to continue with tool results:', e);
            showError('Failed to process tool results. Please try again.');
        }
    }

    // ========================================================================
    // Utilities
    // ========================================================================
    
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Configure marked.js with custom renderer for code blocks with copy buttons
    function setupMarked() {
        if (typeof marked === 'undefined') return;
        
        const renderer = new marked.Renderer();
        
        // Custom code block renderer with copy button
        renderer.code = function(code, language) {
            // Handle marked v5+ object-style args
            if (typeof code === 'object') {
                language = code.lang || '';
                code = code.text || '';
            }
            const lang = language || 'code';
            
            // Fix extra newlines by normalizing line breaks
            // This keeps code structure but removes excessive blank lines
            
            // First pass: Replace any case where a line is followed by multiple newlines
            // This specifically targets the pattern in swanctl/strongswan config blocks
            // where every line seems to be followed by two or more newlines
            code = code.replace(/(\S.*?)(\n\s*\n+)/g, '$1\n');
            
            // Second pass: Convert any remaining instances of 3+ newlines to 2
            code = code.replace(/\n\s*\n\s*\n+/g, '\n\n');
            
            // Handle the case of config block indentation better
            if (language === 'conf' || language === 'ini' || code.includes('{') && code.includes('}')) {
                // In config files, normalize all newline sequences and remove trailing empty lines
                code = code.replace(/\n\s*\n/g, '\n');
            }
            
            // Trim leading/trailing newlines
            code = code.trim();
            
            const escaped = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
            return `<div class="ai-code-block-wrapper"><div class="ai-code-block-header"><span>${lang}</span><button class="ai-copy-btn" onclick="window._aiCopyText(this)" title="Copy to clipboard"><i class="fas fa-copy"></i> Copy</button></div><pre class="ai-code-block"><code class="language-${lang}">${escaped}</code></pre></div>`;
        };
        
        // Open links in new tab
        renderer.link = function(href, title, text) {
            if (typeof href === 'object') {
                text = href.text || '';
                title = href.title || '';
                href = href.href || '';
            }
            const titleAttr = title ? ` title="${title}"` : '';
            return `<a href="${href}" target="_blank" rel="noopener"${titleAttr}>${text}</a>`;
        };
        
        marked.setOptions({
            renderer: renderer,
            breaks: true,
            gfm: true,
            headerIds: false,
            mangle: false
        });
    }

    function renderMarkdown(text) {
        if (!text) return '';
        
        // Use marked.js if available for proper markdown rendering
        if (typeof marked !== 'undefined') {
            try {
                return marked.parse(text);
            } catch (e) {
                console.warn('marked.js parsing failed, falling back:', e);
            }
        }
        
        // Fallback: simple markdown rendering
        let html = escapeHtml(text);
        
        // Code blocks
        html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (match, lang, code) => {
            return `<div class="ai-code-block-wrapper"><div class="ai-code-block-header"><span>${lang || 'code'}</span><button class="ai-copy-btn" onclick="window._aiCopyText(this)" title="Copy to clipboard"><i class="fas fa-copy"></i> Copy</button></div><pre class="ai-code-block"><code class="language-${lang}">${code.trim()}</code></pre></div>`;
        });
        
        // Inline code
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        
        // Headers
        html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
        html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
        
        // Bold
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        
        // Italic
        html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
        
        // Unordered lists
        html = html.replace(/^[\-\*] (.+)$/gm, '<li>$1</li>');
        html = html.replace(/((?:<li>.*<\/li>\n?)+)/g, '<ul>$1</ul>');
        
        // Numbered lists
        html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
        
        // Links
        html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');
        
        // Horizontal rules
        html = html.replace(/^---$/gm, '<hr>');
        
        // Line breaks (but not inside block elements)
        html = html.replace(/\n/g, '<br>');
        
        return html;
    }

    // Global copy function for code blocks
    window._aiCopyText = function(btn) {
        const wrapper = btn.closest('.ai-code-block-wrapper');
        const codeEl = wrapper?.querySelector('code') || wrapper?.querySelector('pre');
        if (!codeEl) return;
        
        const text = codeEl.textContent;

        function onSuccess() {
            const origHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.innerHTML = origHTML;
                btn.classList.remove('copied');
            }, 2000);
        }

        function fallbackCopy(str) {
            const ta = document.createElement('textarea');
            ta.value = str;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            ta.style.top = '-9999px';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            try {
                document.execCommand('copy');
                onSuccess();
            } catch (err) {
                console.error('Fallback copy failed:', err);
            }
            document.body.removeChild(ta);
        }

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(onSuccess).catch(() => fallbackCopy(text));
        } else {
            fallbackCopy(text);
        }
    };

    function addCopyButtonsToCodeBlocks(container) {
        if (!container) return;
        // Add copy buttons to any pre>code blocks that don't already have them
        container.querySelectorAll('pre').forEach(pre => {
            if (pre.closest('.ai-code-block-wrapper')) return; // Already wrapped
            
            const wrapper = document.createElement('div');
            wrapper.className = 'ai-code-block-wrapper';
            wrapper.innerHTML = `<div class="ai-code-block-header"><span>code</span><button class="ai-copy-btn" onclick="window._aiCopyText(this)" title="Copy to clipboard"><i class="fas fa-copy"></i> Copy</button></div>`;
            
            pre.parentNode.insertBefore(wrapper, pre);
            pre.classList.add('ai-code-block');
            wrapper.appendChild(pre);
        });
    }

    function formatDate(dateStr) {
        if (!dateStr) return '';
        try {
            const date = new Date(dateStr);
            const now = new Date();
            const diff = now - date;
            
            if (diff < 60000) return 'Just now';
            if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
            if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
            if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
            
            return date.toLocaleDateString();
        } catch (e) {
            return '';
        }
    }

    function updateSendButton() {
        if (!elements.sendBtn || !elements.input) return;
        
        const hasContent = elements.input.value.trim().length > 0;
        elements.sendBtn.disabled = !hasContent || aiState.isLoading;
    }

    function autoResizeTextarea() {
        if (!elements.input) return;
        
        elements.input.style.height = 'auto';
        elements.input.style.height = Math.min(elements.input.scrollHeight, 120) + 'px';
    }

    // ========================================================================
    // Event Handlers
    // ========================================================================
    
    function setupEventListeners() {
        // Toggle button
        elements.toggleBtn?.addEventListener('click', togglePanel);
        
        // Close button
        elements.closeBtn?.addEventListener('click', closePanel);
        
        // New chat button
        elements.newChatBtn?.addEventListener('click', createNewSession);
        
        // Sessions button
        elements.sessionsBtn?.addEventListener('click', () => {
            elements.sessionsList?.classList.toggle('hidden');
            if (!elements.sessionsList?.classList.contains('hidden')) {
                loadSessions();
            }
        });
        
        // Sessions close
        elements.sessionsClose?.addEventListener('click', () => {
            elements.sessionsList?.classList.add('hidden');
        });
        
        // Context mode change
        elements.contextMode?.addEventListener('change', (e) => {
            aiState.contextMode = e.target.value;
            savePersistedState();
        });
        
        // Input handling
        elements.input?.addEventListener('input', () => {
            updateSendButton();
            autoResizeTextarea();
        });
        
        elements.input?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
        
        // Send button
        elements.sendBtn?.addEventListener('click', sendMessage);
        
        // Keyboard shortcut to toggle panel (Ctrl/Cmd + Shift + A)
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'A') {
                e.preventDefault();
                togglePanel();
            }
        });
        
        // Resize handle
        setupResizeHandle();
    }

    function setupResizeHandle() {
        const panel = elements.panel;
        if (!panel) return;
        
        // Create resize handle
        const handle = document.createElement('div');
        handle.className = 'ai-resize-handle';
        handle.title = 'Drag to resize';
        panel.appendChild(handle);
        
        let startX, startWidth;
        
        handle.addEventListener('mousedown', (e) => {
            e.preventDefault();
            aiState.isResizing = true;
            startX = e.clientX;
            startWidth = panel.offsetWidth;
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
            
            const onMouseMove = (e) => {
                if (!aiState.isResizing) return;
                const diff = startX - e.clientX;
                const newWidth = Math.max(320, Math.min(startWidth + diff, window.innerWidth - 280));
                aiState.panelWidth = newWidth;
                panel.style.width = newWidth + 'px';
                document.documentElement.style.setProperty('--ai-panel-width', newWidth + 'px');
            };
            
            const onMouseUp = () => {
                aiState.isResizing = false;
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                savePersistedState();
            };
            
            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    }

    // ========================================================================
    // Initialization
    // ========================================================================
    
    function initialize() {
        // Only initialize if panel exists (user is logged in)
        if (!document.getElementById('ai-chat-panel')) {
            return;
        }
        
        initializeElements();
        loadPersistedState();
        setupMarked();
        setupEventListeners();
        
        // Auto-detect context mode based on current page
        const pagePath = window.location.pathname;
        if (pagePath.includes('/fmc-configuration') || pagePath.includes('/fmc_configuration')) {
            aiState.contextMode = 'fmc';
        } else if (pagePath.includes('/strongswan')) {
            aiState.contextMode = 'strongswan';
        }
        
        // Set initial context mode
        if (elements.contextMode) {
            elements.contextMode.value = aiState.contextMode;
        }
        
        // Restore open state
        if (aiState.isOpen) {
            openPanel();
        }
        
        console.log('AI Chat initialized');
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }

})();
