import { useEffect, useRef, useState } from 'react'
import { tasks as tasksApi } from '../../lib/api'
import { ws } from '../../lib/websocket'
import { cn } from '../../lib/utils'
import { ModuleIcon } from '../ui/ModuleIcon'
import type { TaskLog } from '../../types'

export const LiveLogs = ({ taskId, active }: { taskId: string; active?: boolean }) => {
  const [logs, setLogs] = useState<TaskLog[]>([])
  const [loading, setLoading] = useState(true)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setLoading(true)
    tasksApi.logs(taskId).then(d => setLogs(d || [])).catch(() => setLogs([])).finally(() => setLoading(false))
  }, [taskId])

  useEffect(() => {
    if (!active) return
    return ws.on('task_log', (payload: unknown) => {
      const log = payload as TaskLog & {task_id: string}
      if (log.task_id === taskId) setLogs(p => [...p.slice(-2000), log])
    })
  }, [taskId, active])

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [logs])

  const lc = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'error': return 'text-severity-critical'
      case 'warn': case 'warning': return 'text-severity-medium'
      case 'success': return 'text-severity-low'
      case 'debug': return 'text-text-muted'
      default: return 'text-text-secondary'
    }
  }

  return (
    <div className="h-full overflow-y-auto p-3 font-mono text-xs space-y-0.5">
      {loading && <p className="text-text-muted">Loading…</p>}
      {!loading && logs.length === 0 && <p className="text-text-muted">No logs yet.</p>}
      {logs.map((log, i) => (
        <div key={log.id || i} className={cn('leading-relaxed break-all', lc(log.level))}>
          <span className="text-text-muted mr-2">{new Date((log as any).time || log.created_at).toLocaleTimeString()}</span>
          <span className="mr-1.5 inline-flex align-middle"><ModuleIcon module={(log as any).module} size={16} /></span>
          {log.message}
        </div>
      ))}
      <div ref={bottomRef}/>
    </div>
  )
}
