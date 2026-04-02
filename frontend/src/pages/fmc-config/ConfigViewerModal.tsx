import { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import { useFmcConfigStore } from '@/stores/fmcConfigStore'
import { X, Save, Copy, Check } from 'lucide-react'

export default function ConfigViewerModal() {
  const { viewerOpen, viewerTitle, viewerContent, viewerOnSave, closeViewer } = useFmcConfigStore()
  const [editedContent, setEditedContent] = useState('')
  const [copied, setCopied] = useState(false)
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    setEditedContent(viewerContent)
    setDirty(false)
  }, [viewerContent])

  if (!viewerOpen) return null

  const handleCopy = async () => {
    await navigator.clipboard.writeText(editedContent)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const handleSave = () => {
    if (viewerOnSave) viewerOnSave(editedContent)
    setDirty(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={closeViewer} />

      {/* Modal */}
      <div className={cn(
        'relative w-[90vw] max-w-5xl max-h-[85vh] flex flex-col',
        'bg-white dark:bg-surface-900 rounded-xl border border-surface-200 dark:border-surface-800',
        'shadow-2xl overflow-hidden'
      )}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-surface-200 dark:border-surface-800/50 shrink-0">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-medium text-surface-800 dark:text-surface-200">{viewerTitle}</h3>
            {dirty && (
              <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-accent-amber/10 text-accent-amber font-medium">Modified</span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium text-surface-500 hover:bg-surface-100 dark:hover:bg-surface-800 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-accent-emerald" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            {viewerOnSave && (
              <button
                onClick={handleSave}
                disabled={!dirty}
                className={cn(
                  'flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium transition-colors',
                  dirty
                    ? 'bg-vyper-600 hover:bg-vyper-700 text-white'
                    : 'text-surface-400 cursor-default'
                )}
              >
                <Save className="w-3.5 h-3.5" /> Save
              </button>
            )}
            <button
              onClick={closeViewer}
              className="p-1.5 rounded-md hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-400 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-hidden">
          <textarea
            value={editedContent}
            onChange={(e) => { setEditedContent(e.target.value); setDirty(true) }}
            readOnly={!viewerOnSave}
            spellCheck={false}
            className={cn(
              'w-full h-full resize-none p-4 font-mono text-[11px] leading-relaxed',
              'bg-surface-950 text-surface-300',
              'focus:outline-none',
              !viewerOnSave && 'cursor-default'
            )}
            style={{ minHeight: '50vh' }}
          />
        </div>
      </div>
    </div>
  )
}
