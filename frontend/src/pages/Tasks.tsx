import { useEffect, useState } from 'react'
import { tasks as tasksApi } from '../lib/api'
import { ws } from '../lib/websocket'
import { Badge, Button, Spinner, Empty } from '../components/ui'
import { LiveLogs } from '../components/tasks/LiveLogs'
import { useUIStore } from '../store/ui'
import { timeAgo, cn } from '../lib/utils'
import type { Task } from '../types'

const dot: Record<string,string> = { running:'bg-accent animate-pulse', finished:'bg-severity-low', failed:'bg-severity-critical', pending:'bg-text-muted', cancelled:'bg-border-strong' }
const tc: Record<string,string> = { running:'text-accent', finished:'text-severity-low', failed:'text-severity-critical', pending:'text-text-muted', cancelled:'text-text-muted' }

// Terminal-style status tags, e.g. "[running]" — reads like a log level.
const tt = (s: string) => `[${s}]`

export default function Tasks() {
  const [taskList, setTaskList] = useState<Task[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Task | null>(null)
  const [statusFilter, setStatusFilter] = useState('')
  const [taskSort, setTaskSort] = useState('recent')
  const { addToast } = useUIStore()

  const load = async (status?: string) => {
    try {
      const p: Record<string,string> = { limit: '100' }; if (status) p.status = status
      setTaskList(await tasksApi.list(p) || [])
    } catch { /**/ } finally { setLoading(false) }
  }

  useEffect(() => {
    load(statusFilter)
    const off = ws.on('task_update', (payload: unknown) => {
      const task = payload as Task
      setTaskList(p => p.some(t => t.id === task.id) ? p.map(t => t.id === task.id ? task : t) : [task, ...p])
      setSelected(p => p?.id === task.id ? task : p)
    })
    const i = setInterval(() => load(statusFilter), 15000)
    return () => { off(); clearInterval(i) }
  }, [statusFilter])

  const handleCancel = async (task: Task, e: React.MouseEvent) => {
    e.stopPropagation()
    try { await tasksApi.cancel(task.id); addToast('info', 'Task cancelled'); load(statusFilter) }
    catch { addToast('error', 'Failed to cancel') }
  }

  // Resumable = it stopped (failed/cancelled — e.g. the scan watchdog) AND it
  // has modules that never got a chance to run. A task with no
  // completed_modules recorded yet (older DB rows, migrated pre-resume) is
  // treated as resumable too — worst case the backend says "nothing to
  // resume" and we surface that.
  const canResume = (task: Task) =>
    (task.status === 'failed' || task.status === 'cancelled') &&
    (task.modules?.length || 0) > (task.completed_modules?.length || 0)

  const handleResume = async (task: Task, e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      const newTask = await tasksApi.resume(task.id)
      addToast('success', `Resumed — ${newTask.modules.length} module(s) remaining`)
      load(statusFilter)
    } catch (err: unknown) {
      addToast('error', err instanceof Error ? err.message : 'Failed to resume')
    }
  }

  return (
    <div className="flex flex-col lg:flex-row gap-4 lg:h-[calc(100vh-9rem)]">
      {/* Task list — full width column on mobile, fixed rail on desktop. */}
      <div className="flex flex-col w-full lg:w-72 shrink-0 h-[46vh] lg:h-auto min-h-0">
        <div className="flex items-center justify-between mb-3">
          <h1 className="text-xl font-bold">Tasks</h1>
          <Button size="sm" variant="ghost" onClick={() => load(statusFilter)}>↻</Button>
        </div>
        <div className="flex gap-2 mb-3">
          <select className="input text-xs flex-1" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
            {['','running','pending','finished','failed','cancelled'].map(s => <option key={s} value={s} className="bg-surface-3">{s || 'All statuses'}</option>)}
          </select>
          <select className="input text-xs flex-1" value={taskSort} onChange={e => setTaskSort(e.target.value)} title="Sort tasks">
            <option value="recent" className="bg-surface-3">Newest</option>
            <option value="status" className="bg-surface-3">Status</option>
            <option value="progress" className="bg-surface-3">Progress</option>
            <option value="name" className="bg-surface-3">Name</option>
          </select>
        </div>
        <div className="flex-1 overflow-y-auto space-y-1.5">
          {loading ? <div className="flex justify-center h-32"><Spinner/></div>
            : taskList.length === 0 ? <Empty message="No tasks"/>
            : [...taskList].sort((a, b) => {
                switch (taskSort) {
                  case 'status':   return (a.status || '').localeCompare(b.status || '')
                  case 'progress': return ((b.progress || 0) / Math.max(1, b.total || 1)) - ((a.progress || 0) / Math.max(1, a.total || 1))
                  case 'name':     return (a.name || a.target_domain || '').localeCompare(b.name || b.target_domain || '')
                  default:         return (b.started_at || b.created_at || '').localeCompare(a.started_at || a.created_at || '')
                }
              }).map(task => (
              <div key={task.id} onClick={() => setSelected(task)}
                className={cn('card p-3 cursor-pointer', selected?.id === task.id ? 'border-accent/40 bg-accent/5' : 'hover:border-border-strong')}>
                <div className="flex items-center gap-2 mb-1">
                  <span className={cn('w-2 h-2 rounded-full shrink-0', dot[task.status] || 'bg-text-muted')}/>
                  <span className="text-xs font-medium truncate flex-1" title={task.target_domain}>{task.name || task.target_domain || 'Unknown'}</span>
                  <span className={cn('text-xs font-mono', tc[task.status])}>{tt(task.status)}</span>
                </div>
                <p className="text-xs text-text-muted ml-4">{task.modules?.join(', ') || 'all'}</p>
                {task.current_module && <p className="text-xs text-accent ml-4 mt-0.5">{task.current_module}</p>}
                {task.status === 'failed' && task.error && (
                  <p className="text-xs text-severity-critical ml-4 mt-0.5 truncate" title={task.error}>{task.error}</p>
                )}
                <div className="flex items-center gap-2 mt-1.5 ml-4">
                  {(task.status === 'running' || task.status === 'pending') && (
                    <button onClick={e => handleCancel(task, e)} className="text-xs text-text-muted hover:text-severity-critical transition-colors">Cancel</button>
                  )}
                  {canResume(task) && (
                    <button onClick={e => handleResume(task, e)} className="text-xs text-accent hover:text-accent-hover transition-colors">▶ Resume</button>
                  )}
                  <span className="text-xs text-text-muted ml-auto">{timeAgo(task.created_at)}</span>
                </div>
              </div>
            ))}
        </div>
      </div>
      <div className="flex-1 card overflow-hidden min-h-[50vh] lg:min-h-0" style={{padding:0}}>
        {selected ? (
          <div className="flex flex-col h-full">
            <div className="px-4 py-3 border-b border-border flex items-center gap-3">
              <div><p className="text-sm font-medium">{selected.name || selected.target_domain}</p><p className="text-xs text-text-muted">{selected.name ? `${selected.target_domain} · ` : ''}#{selected.id.slice(0,8)}</p></div>
              <Badge variant={selected.status === 'finished' ? 'success' : selected.status === 'failed' ? 'error' : selected.status === 'running' ? 'info' : 'neutral'} className="ml-auto">{selected.status}</Badge>
            </div>
            {selected.status === 'failed' && selected.error && (
              <div className="px-4 py-2.5 bg-severity-critical/10 border-b border-severity-critical/30 text-xs text-severity-critical flex items-center gap-3">
                <span><span className="font-semibold">Why it failed: </span>{selected.error}</span>
                {canResume(selected) && (
                  <button onClick={e => handleResume(selected, e)}
                    className="ml-auto shrink-0 btn-secondary text-[11px] whitespace-nowrap">▶ Resume remaining</button>
                )}
              </div>
            )}
            <div className="flex-1 min-h-0"><LiveLogs taskId={selected.id} active={selected.status === 'running'}/></div>
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-text-muted text-sm">Select a task to view logs</div>
        )}
      </div>
    </div>
  )
}
