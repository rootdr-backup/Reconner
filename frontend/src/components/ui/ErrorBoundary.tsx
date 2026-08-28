import { Component, type ReactNode } from 'react'

interface Props { children: ReactNode }
interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="p-6 text-center">
          <p className="text-severity-critical font-medium mb-1">Render error</p>
          <p className="text-xs text-text-muted font-mono">{this.state.error.message}</p>
          <button
            className="mt-4 text-xs text-accent hover:underline"
            onClick={() => this.setState({ error: null })}
          >Retry</button>
        </div>
      )
    }
    return this.props.children
  }
}
