import { create } from 'zustand'
import { auth as authApi } from '../lib/api'

interface AuthState {
  user: {id?: number; username: string; role: string; must_change_password?: boolean} | null
  initialized: boolean
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  checkAuth: () => Promise<void>
  refreshMe: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null, initialized: false, loading: false,
  login: async (username, password) => {
    set({ loading: true })
    try {
      await authApi.login(username, password)
      const user = await authApi.me()
      set({ user, loading: false })
    } catch (err) { set({ loading: false }); throw err }
  },
  logout: async () => { await authApi.logout().catch(() => {}); set({ user: null }) },
  checkAuth: async () => {
    try { const user = await authApi.me(); set({ user, initialized: true }) }
    catch { set({ user: null, initialized: true }) }
  },
  refreshMe: async () => {
    try { const user = await authApi.me(); set({ user }) } catch { /* keep current */ }
  },
}))
