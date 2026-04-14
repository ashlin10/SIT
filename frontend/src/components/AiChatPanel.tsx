import { useState, useEffect, useRef, useCallback } from 'react'
import { cn } from '@/lib/utils'
import {
  Bot, X, Send, Plus, History, Trash2, Copy, Check,
  Loader2, Settings2, AlertCircle, CheckCircle2, Cog, MessageSquare, Sparkles,
} from 'lucide-react'

// ── Saved Prompts ──

interface SavedPrompt {
  id: string
  label: string
  description: string
  /** If fetchReport is true, the prompt will first fetch /api/strongswan/monitoring/download and prepend the report content */
  fetchReport?: boolean
  template: string
}

const SAVED_PROMPTS: SavedPrompt[] = [
  {
    id: 'analyze-vpn-report',
    label: 'Analyze VPN Monitoring Report',
    description: 'Fetch the latest monitoring report and generate a detailed disconnect analysis',
    fetchReport: true,
    template: `Analyze the following VPN tunnel monitoring report.

Provide ONLY these sections:

1. **Disconnect Events Table** — a table with columns: Time, Local IP, Remote IP, Username, Disconnect Reason

2. **Summary Table** — a table with columns: Peer (Local ↔ Remote), Total Disconnects, Most Common Reason, Likely Root Cause

3. **Executive Summary** — a short paragraph summarising the overall VPN health, key patterns, and the most impacted peers

4. **Recommended Next Steps** — a concise numbered list of troubleshooting actions

Keep the response concise. Do not include any other sections.

--- BEGIN REPORT ---
{report}
--- END REPORT ---`,
  },
]

// ── Types ──

interface Session {
  session_id: string
  title: string
  message_count: number
  updated_at: string
}

interface Message {
  role: 'user' | 'assistant' | 'tool' | 'system'
  content: string
  tool_calls?: ToolCall[]
  tool_call_id?: string
}

interface ToolCall {
  id: string
  type?: string
  function?: { name: string; arguments: string }
}

interface ProviderConfig {
  [key: string]: { label: string; models: string[]; default_model: string }
}

const TOOL_NAMES: Record<string, string> = {
  list_config_files: 'Listing configuration files',
  read_config_file: 'Reading configuration file',
  validate_config_syntax: 'Validating configuration syntax',
  save_config_file: 'Saving configuration file',
  delete_config_file: 'Deleting configuration file',
  reload_strongswan_config: 'Reloading strongSwan configuration',
  edit_config_file: 'Editing configuration file',
  lookup_fmc_schema: 'Looking up FMC schema',
  validate_fmc_config: 'Validating FMC config',
  load_config_to_ui: 'Loading config to UI',
}

const CONFIRM_TOOLS: Record<string, string> = {
  save_config_file: 'save',
  delete_config_file: 'delete',
  edit_config_file: 'edit',
  load_config_to_ui: 'load into Device Configuration',
  fmc_delete_device: 'DELETE/UNREGISTER device(s) from FMC',
  fmc_push_device_config: 'PUSH configuration to device(s)',
}

const DEFAULT_PROVIDERS: ProviderConfig = {
  bedrock: { label: 'AWS Bedrock', models: ['claude-sonnet-4.6', 'claude-haiku-4.5'], default_model: 'claude-sonnet-4.6' },
  circuit: { label: 'CIRCUIT API', models: ['gpt-4.1', 'gpt-4o-mini'], default_model: 'gpt-4.1' },
}

// ── Lightweight Markdown ──

function renderMarkdown(text: string): string {
  if (!text) return ''
  let h = text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

  // Code blocks
  h = h.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, lang, code) => {
    const l = lang || 'code'
    return `<div class="ai-code-wrap"><div class="ai-code-hdr"><span>${l}</span></div><pre class="ai-code"><code>${code.trim()}</code></pre></div>`
  })

  // Tables: detect consecutive lines with | delimiters
  h = h.replace(/((?:^\|.+\|\s*$\n?)+)/gm, (tableBlock) => {
    const rows = tableBlock.trim().split('\n').filter(r => r.trim())
    if (rows.length < 2) return tableBlock
    const parseRow = (row: string) => row.replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim())
    const isSep = (row: string) => /^[\|\s:\-]+$/.test(row)
    let html = '<div class="ai-table-wrap"><table class="ai-table">'
    let headerDone = false
    for (let i = 0; i < rows.length; i++) {
      if (isSep(rows[i])) { headerDone = true; continue }
      const cells = parseRow(rows[i])
      const tag = (!headerDone && i === 0) ? 'th' : 'td'
      html += '<tr>' + cells.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>'
      if (tag === 'th') headerDone = true
    }
    html += '</table></div>'
    return html
  })

  h = h.replace(/`([^`]+)`/g, '<code class="ai-inline-code">$1</code>')
  h = h.replace(/^#### (.+)$/gm, '<h5 class="font-semibold text-[11px] mt-2 mb-1">$1</h5>')
  h = h.replace(/^### (.+)$/gm, '<h4 class="font-semibold text-xs mt-2 mb-1">$1</h4>')
  h = h.replace(/^## (.+)$/gm, '<h3 class="font-semibold text-sm mt-2 mb-1">$1</h3>')
  h = h.replace(/^# (.+)$/gm, '<h2 class="font-bold text-sm mt-3 mb-1">$1</h2>')
  h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  h = h.replace(/\*([^*]+)\*/g, '<em>$1</em>')
  h = h.replace(/^[\-\*] (.+)$/gm, '<li class="ml-3">• $1</li>')
  h = h.replace(/^\d+\. (.+)$/gm, '<li class="ml-3">$1</li>')
  h = h.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" class="text-vyper-500 underline">$1</a>')
  h = h.replace(/^---$/gm, '<hr class="my-2 border-surface-200 dark:border-surface-700">')
  h = h.replace(/\n/g, '<br>')
  return h
}

function formatDate(d: string): string {
  if (!d) return ''
  const diff = Date.now() - new Date(d).getTime()
  if (diff < 60000) return 'Just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return new Date(d).toLocaleDateString()
}

// ── Component ──

export default function AiChatPanel() {
  const [open, setOpen] = useState(() => localStorage.getItem('ai-chat-open') === 'true')
  const [panelWidth, setPanelWidth] = useState(() => parseInt(localStorage.getItem('ai-chat-width') || '380', 10))
  const resizingRef = useRef(false)
  const [sessions, setSessions] = useState<Session[]>([])
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(() => localStorage.getItem('ai-chat-session'))
  const currentSessionIdRef = useRef(currentSessionId)
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [showSessions, setShowSessions] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  const [showPrompts, setShowPrompts] = useState(false)

  const [provider, setProvider] = useState(() => localStorage.getItem('ai-chat-provider') || 'bedrock')
  const [model, setModel] = useState(() => localStorage.getItem('ai-chat-model') || 'claude-sonnet-4.6')
  const [contextMode, setContextMode] = useState('general')
  const [providers, setProviders] = useState<ProviderConfig>(DEFAULT_PROVIDERS)

  const messagesRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  // Keep session ID ref in sync
  useEffect(() => { currentSessionIdRef.current = currentSessionId }, [currentSessionId])

  // Resize handler
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!resizingRef.current) return
      const newWidth = Math.min(900, Math.max(300, window.innerWidth - e.clientX))
      setPanelWidth(newWidth)
    }
    const handleMouseUp = () => {
      if (resizingRef.current) {
        resizingRef.current = false
        document.body.style.cursor = ''
        document.body.style.userSelect = ''
        localStorage.setItem('ai-chat-width', String(panelWidth))
      }
    }
    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)
    return () => { document.removeEventListener('mousemove', handleMouseMove); document.removeEventListener('mouseup', handleMouseUp) }
  }, [panelWidth])

  const startResize = () => {
    resizingRef.current = true
    document.body.style.cursor = 'ew-resize'
    document.body.style.userSelect = 'none'
  }

  // Persist state
  useEffect(() => { localStorage.setItem('ai-chat-open', String(open)) }, [open])
  useEffect(() => { if (currentSessionId) localStorage.setItem('ai-chat-session', currentSessionId) }, [currentSessionId])
  useEffect(() => { localStorage.setItem('ai-chat-provider', provider) }, [provider])
  useEffect(() => { localStorage.setItem('ai-chat-model', model) }, [model])

  // Auto-detect context mode
  useEffect(() => {
    const p = window.location.pathname
    if (p.includes('/fmc-configuration')) setContextMode('fmc')
    else if (p.includes('/vpn-console')) setContextMode('strongswan')
    else setContextMode('general')
  }, [])

  // Load providers on mount
  useEffect(() => {
    fetch('/api/ai/providers', { credentials: 'include' })
      .then(r => r.json())
      .then(d => { if (d.success && d.providers) setProviders(d.providers) })
      .catch(() => {})
  }, [])

  // Load sessions when panel opens
  useEffect(() => {
    if (open) loadSessions()
  }, [open])

  // Scroll to bottom
  useEffect(() => {
    if (messagesRef.current) messagesRef.current.scrollTop = messagesRef.current.scrollHeight
  }, [messages])

  // Keyboard shortcut
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'A') {
        e.preventDefault()
        setOpen(o => !o)
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  const loadSessions = async () => {
    try {
      const r = await fetch('/api/ai/sessions', { credentials: 'include' })
      const d = await r.json()
      if (d.success) setSessions(d.sessions || [])
    } catch { /* ignore */ }
  }

  const loadSessionMessages = async (sid: string) => {
    try {
      const r = await fetch(`/api/ai/sessions/${sid}`, { credentials: 'include' })
      const d = await r.json()
      if (d.success && d.session) {
        setMessages(d.session.messages?.filter((m: Message) => m.role !== 'system') || [])
        if (d.session.context_mode) setContextMode(d.session.context_mode)
      }
    } catch { /* ignore */ }
  }

  const createSession = async (title = 'New Chat') => {
    try {
      const r = await fetch('/api/ai/sessions', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ title, context_mode: contextMode }),
      })
      const d = await r.json()
      if (d.success) {
        setCurrentSessionId(d.session.session_id)
        setSessions(s => [{ session_id: d.session.session_id, title, message_count: 0, updated_at: new Date().toISOString() }, ...s])
        setMessages([])
        return d.session.session_id
      }
    } catch { /* ignore */ }
    return null
  }

  const deleteSession = async (sid: string) => {
    if (!confirm('Delete this chat?')) return
    try {
      await fetch(`/api/ai/sessions/${sid}`, { method: 'DELETE', credentials: 'include' })
      setSessions(s => s.filter(x => x.session_id !== sid))
      if (currentSessionId === sid) { setCurrentSessionId(null); setMessages([]) }
    } catch { /* ignore */ }
  }

  const switchSession = async (sid: string) => {
    setCurrentSessionId(sid)
    setShowSessions(false)
    await loadSessionMessages(sid)
  }

  // ── SSE Stream Parser ──

  const readStream = useCallback(async (response: Response, onContent: (c: string) => void, onToolCalls: (tc: ToolCall[]) => void, onError: (e: string) => void) => {
    const reader = response.body!.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() || ''
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        const data = line.slice(6)
        if (data === '[DONE]') continue
        try {
          const parsed = JSON.parse(data)
          if (parsed.content) onContent(parsed.content)
          if (parsed.tool_calls) onToolCalls(parsed.tool_calls)
          if (parsed.error) onError(parsed.error)
        } catch { /* partial */ }
      }
    }
  }, [])

  // ── Handle Tool Calls ──

  const handleToolCalls = useCallback(async (toolCalls: ToolCall[], sessionId: string) => {
    const toolResults: { tool_call_id: string; result: Record<string, unknown> }[] = []

    for (const tc of toolCalls) {
      const name = tc.function?.name || ''
      let args: Record<string, unknown> = {}
      try { args = JSON.parse(tc.function?.arguments || '{}') } catch { /* */ }

      // Confirm destructive tools
      if (CONFIRM_TOOLS[name] && !args.user_confirmed) {
        const target = (args.filename as string) || 'this operation'
        if (!confirm(`The AI wants to ${CONFIRM_TOOLS[name]} "${target}". Proceed?`)) {
          toolResults.push({ tool_call_id: tc.id, result: { success: false, error: 'User cancelled' } })
          setMessages(m => [...m, { role: 'tool', content: JSON.stringify({ success: false, error: 'User cancelled' }), tool_call_id: tc.id }])
          continue
        }
        args.user_confirmed = true
      }

      // Show tool executing indicator
      setMessages(m => [...m, { role: 'assistant', content: '', tool_calls: [tc] }])

      try {
        const r = await fetch('/api/ai/tool-execute', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ tool_name: name, arguments: args, session_id: sessionId, tool_call_id: tc.id, context_mode: contextMode }),
        })
        const result = await r.json()
        const aiResult = { ...result }
        delete aiResult.config; delete aiResult.config_yaml; delete aiResult.vpn_yaml
        toolResults.push({ tool_call_id: tc.id, result: aiResult })
        setMessages(m => [...m, { role: 'tool', content: JSON.stringify(aiResult), tool_call_id: tc.id }])
      } catch (e) {
        const err = { success: false, error: e instanceof Error ? e.message : 'Tool failed' }
        toolResults.push({ tool_call_id: tc.id, result: err })
        setMessages(m => [...m, { role: 'tool', content: JSON.stringify(err), tool_call_id: tc.id }])
      }
    }

    // Continue conversation with tool results
    if (toolResults.length > 0) {
      const response = await fetch('/api/ai/chat', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          tool_results: toolResults.map(tr => ({ tool_call_id: tr.tool_call_id, content: JSON.stringify(tr.result) })),
          tool_calls: toolCalls.map(tc => ({ id: tc.id, type: tc.type || 'function', function: tc.function })),
          session_id: sessionId, context_mode: contextMode, provider, model, stream: true,
        }),
      })
      if (response.ok) {
        let full = ''
        setMessages(m => [...m, { role: 'assistant', content: '' }])
        await readStream(response,
          c => { full += c; setMessages(m => { const arr = [...m]; arr[arr.length - 1] = { ...arr[arr.length - 1], content: full }; return arr }) },
          async tc2 => { await handleToolCalls(tc2, sessionId) },
          err => { setMessages(m => [...m, { role: 'assistant', content: `Error: ${err}` }]) },
        )
      }
    }
  }, [contextMode, provider, model, readStream])

  // ── Use Saved Prompt ──

  const handleUsePrompt = useCallback(async (prompt: SavedPrompt) => {
    setShowPrompts(false)
    if (loading) return

    let finalMsg = prompt.template
    if (prompt.fetchReport) {
      try {
        const res = await fetch('/api/strongswan/monitoring/download', { credentials: 'include' })
        const report = res.ok ? await res.text() : ''
        if (!report) {
          setMessages(m => [...m, { role: 'assistant', content: 'No monitoring report data available. Start monitoring first and wait for at least one interval to complete.' }])
          return
        }
        finalMsg = prompt.template.replace('{report}', report)
      } catch {
        setMessages(m => [...m, { role: 'assistant', content: 'Failed to fetch monitoring report.' }])
        return
      }
    }

    sendMessageDirect(finalMsg, prompt.label)
  }, [loading])

  // ── Send Message ──

  const sendMessageDirect = useCallback(async (msgOverride: string, displayLabel?: string) => {
    const msg = msgOverride.trim()
    if (!msg) return
    setLoading(true)
    setInput('')

    // Show a shorter label in the user bubble for long prompts
    setMessages(m => [...m, { role: 'user', content: displayLabel ? `📋 ${displayLabel}` : msg }])

    let sid = currentSessionIdRef.current
    if (!sid) { sid = await createSession(msg.substring(0, 50)); if (!sid) { setLoading(false); return } }

    try {
      const response = await fetch('/api/ai/chat', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ message: msg, session_id: sid, context_mode: contextMode, provider, model, stream: true }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)

      let full = ''
      setMessages(m => [...m, { role: 'assistant', content: '' }])
      await readStream(response,
        c => { full += c; setMessages(m => { const arr = [...m]; arr[arr.length - 1] = { ...arr[arr.length - 1], content: full }; return arr }) },
        async tc => { await handleToolCalls(tc, sid!) },
        err => { setMessages(m => [...m, { role: 'assistant', content: `Error: ${err}` }]) },
      )
    } catch {
      setMessages(m => [...m, { role: 'assistant', content: 'Failed to send message. Please try again.' }])
    } finally { setLoading(false) }
  }, [loading, contextMode, provider, model, readStream, handleToolCalls])

  const sendMessage = useCallback(() => {
    if (!input.trim()) return
    sendMessageDirect(input)
  }, [input, sendMessageDirect])

  // ── Render Helpers ──

  const providerModels = providers[provider]?.models || []
  const validModel = providerModels.includes(model) ? model : (providers[provider]?.default_model || providerModels[0] || '')

  const btnBase = 'p-1.5 rounded-md transition-colors text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-800'

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-5 right-5 z-50 w-11 h-11 rounded-full bg-vyper-500 text-white shadow-lg hover:bg-vyper-600 flex items-center justify-center transition-all hover:scale-105"
        title="Open AI Chat (⌘+Shift+A)"
      >
        <Bot className="w-5 h-5" />
      </button>
    )
  }

  return (
    <div className="fixed top-0 right-0 z-50 h-screen flex flex-col border-l border-surface-200 dark:border-surface-800 bg-white dark:bg-surface-900 shadow-2xl" style={{ width: panelWidth }}>
      {/* Resize handle */}
      <div
        onMouseDown={startResize}
        className="absolute top-0 left-0 w-1 h-full cursor-ew-resize z-10 hover:bg-vyper-500/30 active:bg-vyper-500/50 transition-colors"
      />
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2.5 border-b border-surface-200 dark:border-surface-800 shrink-0">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-vyper-500" />
          <span className="text-xs font-semibold text-surface-800 dark:text-surface-200">Vyper AI</span>
          <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-vyper-500/10 text-vyper-600 dark:text-vyper-400 font-medium">
            {contextMode === 'fmc' ? 'FMC' : contextMode === 'strongswan' ? 'VPN Console' : 'General'}
          </span>
        </div>
        <div className="flex items-center gap-0.5">
          <button onClick={() => { createSession(); setShowSessions(false) }} className={btnBase} title="New Chat"><Plus className="w-3.5 h-3.5" /></button>
          <button onClick={() => { setShowSessions(s => !s); if (!showSessions) loadSessions() }} className={btnBase} title="Chat History"><History className="w-3.5 h-3.5" /></button>
          <button onClick={() => setShowSettings(s => !s)} className={btnBase} title="Settings"><Settings2 className="w-3.5 h-3.5" /></button>
          <button onClick={() => setOpen(false)} className={btnBase} title="Close"><X className="w-3.5 h-3.5" /></button>
        </div>
      </div>

      {/* Settings dropdown */}
      {showSettings && (
        <div className="px-3 py-2 border-b border-surface-200 dark:border-surface-800 bg-surface-50 dark:bg-surface-800/50 space-y-2 shrink-0">
          <div className="flex items-center gap-2">
            <label className="text-[10px] font-medium text-surface-500 w-14 shrink-0">Mode</label>
            <select value={contextMode} onChange={e => setContextMode(e.target.value)}
              className="flex-1 text-[10px] px-2 py-1 rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 text-surface-700 dark:text-surface-300">
              <option value="general">General</option>
              <option value="strongswan">VPN Console</option>
              <option value="fmc">FMC Configuration</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-[10px] font-medium text-surface-500 w-14 shrink-0">Provider</label>
            <select value={provider} onChange={e => { setProvider(e.target.value); setModel(providers[e.target.value]?.default_model || '') }}
              className="flex-1 text-[10px] px-2 py-1 rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 text-surface-700 dark:text-surface-300">
              {Object.entries(providers).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-[10px] font-medium text-surface-500 w-14 shrink-0">Model</label>
            <select value={validModel} onChange={e => setModel(e.target.value)}
              className="flex-1 text-[10px] px-2 py-1 rounded-md border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 text-surface-700 dark:text-surface-300">
              {providerModels.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
        </div>
      )}

      {/* Sessions list overlay */}
      {showSessions && (
        <div className="absolute top-10 left-0 right-0 z-10 max-h-[50vh] overflow-y-auto bg-white dark:bg-surface-900 border-b border-surface-200 dark:border-surface-800 shadow-lg">
          <div className="flex items-center justify-between px-3 py-2 border-b border-surface-100 dark:border-surface-800">
            <span className="text-[10px] font-semibold text-surface-500 uppercase tracking-wider">Chat History</span>
            <button onClick={() => setShowSessions(false)} className={btnBase}><X className="w-3 h-3" /></button>
          </div>
          {sessions.length === 0 ? (
            <div className="px-3 py-6 text-center text-[10px] text-surface-400">No chats yet</div>
          ) : sessions.map(s => (
            <div key={s.session_id}
              onClick={() => switchSession(s.session_id)}
              className={cn(
                'flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors',
                s.session_id === currentSessionId && 'bg-vyper-500/5'
              )}>
              <div className="min-w-0 flex-1">
                <div className="text-[11px] font-medium text-surface-700 dark:text-surface-300 truncate">{s.title}</div>
                <div className="text-[9px] text-surface-400">{s.message_count} msgs · {formatDate(s.updated_at)}</div>
              </div>
              <button onClick={e => { e.stopPropagation(); deleteSession(s.session_id) }} className="p-1 text-surface-300 hover:text-red-500 transition-colors shrink-0">
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Messages */}
      <div ref={messagesRef} className="flex-1 overflow-y-auto px-3 py-3 space-y-3">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center py-12">
            <Bot className="w-10 h-10 text-vyper-500/30 mb-3" />
            <h3 className="text-sm font-semibold text-surface-600 dark:text-surface-400 mb-1">Welcome to Vyper AI</h3>
            <p className="text-[10px] text-surface-400 max-w-[240px]">
              Ask networking questions, manage strongSwan configs, or get FMC configuration help.
            </p>
          </div>
        )}
        {messages.map((m, i) => (
          <MessageBubble key={i} message={m} />
        ))}
        {loading && (
          <div className="flex items-center gap-2 px-2 py-1.5">
            <Loader2 className="w-3.5 h-3.5 text-vyper-500 animate-spin" />
            <span className="text-[10px] text-surface-400">Thinking...</span>
          </div>
        )}
      </div>

      {/* Prompts Popover */}
      {showPrompts && (
        <div className="mx-3 mb-1 border border-surface-200 dark:border-surface-700 rounded-lg bg-white dark:bg-surface-900 shadow-lg overflow-hidden shrink-0">
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-surface-100 dark:border-surface-800">
            <span className="text-[10px] font-semibold text-surface-500 uppercase tracking-wider">Prompts</span>
            <button onClick={() => setShowPrompts(false)} className={btnBase}><X className="w-3 h-3" /></button>
          </div>
          {SAVED_PROMPTS.map(p => (
            <button
              key={p.id}
              onClick={() => handleUsePrompt(p)}
              disabled={loading}
              className="w-full text-left px-3 py-2 hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors disabled:opacity-40 border-b border-surface-50 dark:border-surface-800 last:border-b-0"
            >
              <div className="flex items-center gap-1.5">
                <Sparkles className="w-3 h-3 text-vyper-500 shrink-0" />
                <span className="text-[11px] font-medium text-surface-700 dark:text-surface-300">{p.label}</span>
              </div>
              <p className="text-[10px] text-surface-400 mt-0.5 ml-[18px]">{p.description}</p>
            </button>
          ))}
        </div>
      )}

      {/* Input */}
      <div className="px-3 py-2.5 border-t border-surface-200 dark:border-surface-800 shrink-0">
        <div className="flex items-end gap-1.5">
          <button
            onClick={() => setShowPrompts(s => !s)}
            className={cn('p-2 rounded-lg transition-colors shrink-0', showPrompts ? 'bg-vyper-500/10 text-vyper-500' : 'text-surface-400 hover:text-surface-600 dark:hover:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-800')}
            title="Saved Prompts"
          >
            <Sparkles className="w-3.5 h-3.5" />
          </button>
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage() } }}
            placeholder="Ask anything..."
            rows={1}
            className="flex-1 text-[11px] px-3 py-2 rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50 dark:bg-surface-800/50 text-surface-800 dark:text-surface-200 placeholder-surface-400 resize-none focus:outline-none focus:ring-1 focus:ring-vyper-500/40"
            style={{ maxHeight: '100px' }}
          />
          <button
            onClick={sendMessage}
            disabled={!input.trim() || loading}
            className="p-2 rounded-lg bg-vyper-500 text-white hover:bg-vyper-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Message Bubble ──

function MessageBubble({ message }: { message: Message }) {
  const [copied, setCopied] = useState(false)

  if (message.role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] px-3 py-2 rounded-xl rounded-br-sm bg-vyper-500 text-white text-[11px] leading-relaxed">
          {message.content}
        </div>
      </div>
    )
  }

  if (message.role === 'tool') {
    let result: Record<string, unknown> = {}
    try { result = JSON.parse(message.content) } catch { result = { message: message.content } }
    const isError = result.success === false || !!result.error
    return (
      <div className={cn('mx-2 px-2.5 py-1.5 rounded-lg border text-[10px]',
        isError ? 'border-red-200 dark:border-red-800/30 bg-red-50/50 dark:bg-red-900/10' : 'border-emerald-200 dark:border-emerald-800/30 bg-emerald-50/50 dark:bg-emerald-900/10'
      )}>
        <div className="flex items-center gap-1.5 mb-1">
          {isError ? <AlertCircle className="w-3 h-3 text-red-500" /> : <CheckCircle2 className="w-3 h-3 text-emerald-500" />}
          <span className={cn('font-medium', isError ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400')}>
            {isError ? 'Error' : 'Result'}
          </span>
        </div>
        {result.message ? <div className="text-surface-600 dark:text-surface-400">{String(result.message)}</div> : null}
        {result.error ? <div className="text-red-600 dark:text-red-400">{String(result.error)}</div> : null}
        {result.files && Array.isArray(result.files) ? (
          <div className="mt-1 space-y-0.5">
            {(result.files as { name: string; size: number }[]).map((f, i) => (
              <div key={i} className="flex items-center gap-1 text-surface-500">
                <MessageSquare className="w-2.5 h-2.5" />
                <span>{f.name}</span>
                <span className="text-surface-400 ml-auto">{f.size > 1024 ? `${(f.size / 1024).toFixed(1)}KB` : `${f.size}B`}</span>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    )
  }

  // Tool call indicator
  if (message.role === 'assistant' && message.tool_calls?.length && !message.content) {
    return (
      <div className="mx-2 space-y-1">
        {message.tool_calls.map((tc, i) => (
          <div key={i} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-surface-100 dark:bg-surface-800/50 border border-surface-200 dark:border-surface-700">
            <Cog className="w-3 h-3 text-vyper-500 animate-spin" />
            <span className="text-[10px] text-surface-600 dark:text-surface-400">
              {TOOL_NAMES[tc.function?.name || ''] || tc.function?.name || 'Running tool...'}
            </span>
          </div>
        ))}
      </div>
    )
  }

  // Assistant message
  if (message.role === 'assistant' && message.content) {
    const copyAll = () => {
      navigator.clipboard.writeText(message.content).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) }).catch(() => {})
    }
    return (
      <div className="group relative">
        <div className="flex items-start gap-2">
          <div className="w-5 h-5 rounded-md bg-vyper-500/10 flex items-center justify-center shrink-0 mt-0.5">
            <Bot className="w-3 h-3 text-vyper-500" />
          </div>
          <div className="flex-1 min-w-0">
            <div
              className="ai-msg-content text-[11px] leading-relaxed text-surface-700 dark:text-surface-300 prose-sm"
              dangerouslySetInnerHTML={{ __html: renderMarkdown(message.content) }}
            />
          </div>
        </div>
        <button onClick={copyAll} className="absolute top-0 right-0 opacity-0 group-hover:opacity-100 p-1 rounded text-surface-400 hover:text-surface-600 transition-all" title="Copy">
          {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
        </button>
      </div>
    )
  }

  return null
}
