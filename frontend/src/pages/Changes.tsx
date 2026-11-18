import ChangesExplorer from '../components/changes/ChangesExplorer'

export default function Changes() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Changes</h1>
        <p className="text-sm text-text-muted">One timeline for watch rounds and monitoring.</p>
      </div>
      <ChangesExplorer />
    </div>
  )
}
