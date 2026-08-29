import { create } from 'zustand'

export interface Toast { id: string; type: 'success'|'error'|'info'|'warning'; message: string }

interface UIState {
  toasts: Toast[]
  addToast: (type: Toast['type'], message: string) => void
  removeToast: (id: string) => void
  // Off-canvas sidebar (mobile / tablet). Desktop (lg+) ignores this — the
  // sidebar is statically visible there.
  sidebarOpen: boolean
  setSidebarOpen: (v: boolean) => void
}

let n = 0
export const useUIStore = create<UIState>((set) => ({
  toasts: [],
  addToast: (type, message) => {
    const id = String(++n)
    set((s: UIState) => ({ toasts: [...s.toasts, { id, type, message }] }))
    setTimeout(() => set((s: UIState) => ({ toasts: s.toasts.filter(t => t.id !== id) })), 4000)
  },
  removeToast: (id: string) => set((s: UIState) => ({ toasts: s.toasts.filter(t => t.id !== id) })),
  sidebarOpen: false,
  setSidebarOpen: (v: boolean) => set({ sidebarOpen: v }),
}))
