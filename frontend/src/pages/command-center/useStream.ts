import { useCommandCenterStore } from '@/stores/commandCenterStore'

export async function runStream(url: string, payload: Record<string, unknown>) {
  const store = useCommandCenterStore.getState()
  store.clearExec()
  store.setExecuting(true)
  store.setExecStatus('Running on selected device(s)…')

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(payload),
    })
    if (!res.ok || !res.body) throw new Error('Stream failed to start')

    const reader = res.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''

    const handleLine = (line: string) => {
      if (!line) return
      if (line.startsWith('RESULT ')) {
        try {
          const r = JSON.parse(line.slice(7))
          useCommandCenterStore.getState().addResult(r)
        } catch { /* ignore */ }
        return
      }
      if (line.startsWith('SUMMARY ')) {
        try {
          const s = JSON.parse(line.slice(8))
          useCommandCenterStore.getState().setExecStatus(`Completed: ${s.success_count}/${s.total}`)
        } catch { /* ignore */ }
        return
      }
      useCommandCenterStore.getState().appendLog(line)
    }

    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let idx
      while ((idx = buffer.indexOf('\n')) >= 0) {
        handleLine(buffer.slice(0, idx))
        buffer = buffer.slice(idx + 1)
      }
    }
    if (buffer) handleLine(buffer)
  } catch (err) {
    useCommandCenterStore.getState().setExecStatus('Error: ' + (err instanceof Error ? err.message : String(err)))
  } finally {
    useCommandCenterStore.getState().setExecuting(false)
  }
}
