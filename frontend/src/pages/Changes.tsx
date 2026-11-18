import ChangeLog from '../components/changes/ChangeLog'

export default function Changes() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Changes</h1>
        <p className="text-sm text-text-muted">One readable log for watch rounds, monitoring, scope, and alerts.</p>
      </div>
      <ChangeLog />
    </div>
  )
}
