import { useState } from 'react'
import { useVpnDebuggerStore } from '@/stores/vpnDebuggerStore'
import { cn } from '@/lib/utils'
import { X, Copy, Check, Save, Download, Loader2 } from 'lucide-react'
import { saveFileContent, saveNetplanContent, fetchConfigFiles, fetchNetplanFiles } from './api'

export default function FileViewerModal() {
  const {
    fileViewerOpen, fileViewerTitle, fileViewerContent, fileViewerEditable,
    fileViewerFilename, fileViewerType, fileViewerLoading,
    closeFileViewer, setFileViewerContent,
  } = useVpnDebuggerStore()

  const [copied, setCopied] = useState(false)
  const [saving, setSaving] = useState(false)

  if (!fileViewerOpen) return null

  const handleCopy = () => {
    navigator.clipboard.writeText(fileViewerContent)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      if (fileViewerType === 'netplan') {
        await saveNetplanContent(fileViewerFilename, fileViewerContent)
      } else {
        await saveFileContent(fileViewerFilename, fileViewerContent)
      }
      if (fileViewerType === 'config') fetchConfigFiles()
      if (fileViewerType === 'netplan') fetchNetplanFiles()
    } finally {
      setSaving(false)
    }
  }

  const handleDownload = () => {
    if (!fileViewerContent) return
    const blob = new Blob([fileViewerContent], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = fileViewerFilename || 'download.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-[1000]" onClick={closeFileViewer} />
      <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[1001] w-[800px] max-w-[90vw] max-h-[80vh] flex flex-col rounded-xl border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-900 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-surface-100 dark:border-surface-800">
          <h3 className="text-sm font-semibold text-surface-800 dark:text-surface-200 truncate">{fileViewerTitle}</h3>
          <div className="flex items-center gap-2">
            <button onClick={handleCopy} disabled={fileViewerLoading} className={cn(
              'flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors disabled:opacity-40',
              copied ? 'text-accent-emerald bg-accent-emerald/10' : 'text-surface-500 hover:text-surface-700 dark:hover:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-800'
            )}>
              {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button onClick={handleDownload} disabled={fileViewerLoading || !fileViewerContent} className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-surface-500 hover:text-surface-700 dark:hover:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors disabled:opacity-40">
              <Download className="w-3 h-3" /> Download
            </button>
            {fileViewerEditable && (
              <button onClick={handleSave} disabled={saving || fileViewerLoading} className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-vyper-600 hover:bg-vyper-50 dark:hover:bg-vyper-900/20 transition-colors disabled:opacity-40">
                <Save className="w-3 h-3" />
                {saving ? 'Saving...' : 'Save'}
              </button>
            )}
            <button onClick={closeFileViewer} className="p-1 rounded hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors">
              <X className="w-4 h-4 text-surface-400" />
            </button>
          </div>
        </div>
        {/* Content */}
        <div className="flex-1 overflow-auto">
          {fileViewerLoading ? (
            <div className="flex flex-col items-center justify-center min-h-[300px] gap-3">
              <Loader2 className="w-6 h-6 text-vyper-500 animate-spin" />
              <span className="text-xs text-surface-400">Loading file content...</span>
            </div>
          ) : fileViewerEditable ? (
            <textarea
              value={fileViewerContent}
              onChange={(e) => setFileViewerContent(e.target.value)}
              className="w-full h-full min-h-[400px] p-4 bg-surface-950 text-accent-emerald font-mono text-xs leading-relaxed resize-none focus:outline-none"
              spellCheck={false}
            />
          ) : (
            <pre className="p-4 bg-surface-950 text-accent-emerald font-mono text-xs leading-relaxed whitespace-pre-wrap break-all min-h-[300px]">
              {fileViewerContent || 'Empty file'}
            </pre>
          )}
        </div>
      </div>
    </>
  )
}
