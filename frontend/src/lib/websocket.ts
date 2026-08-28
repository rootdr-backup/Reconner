type Handler = (payload: unknown) => void

class WSClient {
  private ws: WebSocket | null = null
  private handlers = new Map<string, Set<Handler>>()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectDelay = 1000
  private shouldConnect = false
  private pingInterval: ReturnType<typeof setInterval> | null = null

  connect() { this.shouldConnect = true; this._connect() }

  disconnect() {
    this.shouldConnect = false
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null }
    if (this.pingInterval) { clearInterval(this.pingInterval); this.pingInterval = null }
    if (this.ws) { this.ws.close(); this.ws = null }
  }

  private _connect() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    try { this.ws = new WebSocket(`${proto}//${window.location.host}/ws`) }
    catch { this._scheduleReconnect(); return }
    this.ws.onopen = () => {
      this.reconnectDelay = 1000
      this.pingInterval = setInterval(() => {
        if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify({ type: 'ping' }))
      }, 25000)
    }
    this.ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as {type: string; payload: unknown}
        this._emit(msg.type, msg.payload)
        this._emit('*', msg)
      } catch { /**/ }
    }
    this.ws.onclose = () => {
      if (this.pingInterval) { clearInterval(this.pingInterval); this.pingInterval = null }
      if (this.shouldConnect) this._scheduleReconnect()
    }
    this.ws.onerror = () => this.ws?.close()
  }

  private _scheduleReconnect() {
    if (this.reconnectTimer) return
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      if (this.shouldConnect) this._connect()
    }, this.reconnectDelay)
    this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, 30000)
  }

  private _emit(type: string, payload: unknown) {
    this.handlers.get(type)?.forEach(h => { try { h(payload) } catch { /**/ } })
  }

  on(type: string, handler: Handler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, new Set())
    this.handlers.get(type)!.add(handler)
    return () => this.handlers.get(type)?.delete(handler)
  }

  get connected(): boolean { return this.ws?.readyState === WebSocket.OPEN }
}

export const ws = new WSClient()
