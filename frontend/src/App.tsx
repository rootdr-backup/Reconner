import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { useAuthStore } from './store/auth'
import { ws } from './lib/websocket'
import { Shell } from './components/layout/Shell'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Targets from './pages/Targets'
import TargetDetail from './pages/TargetDetail'
import Findings from './pages/Findings'
import Tasks from './pages/Tasks'
import System from './pages/System'
import { Spinner } from './components/ui'

function AuthGuard({ children }: { children: React.ReactNode }) {
  const { user, initialized } = useAuthStore()
  const location = useLocation()
  if (!initialized) return (
    <div className="min-h-[100dvh] flex flex-col items-center justify-center gap-4 bg-surface">
      <Spinner className="w-14 h-14"/>
      <div className="text-center">
        <p className="text-sm font-semibold tracking-wide text-text-primary">Reconner</p>
        <p className="mt-1 text-[10px] uppercase tracking-[.2em] text-text-muted">Establishing secure session</p>
      </div>
    </div>
  )
  if (!user) return <Navigate to="/login" state={{ from: location }} replace/>
  return <>{children}</>
}

function Init() {
  const { checkAuth, user } = useAuthStore()
  useEffect(() => { checkAuth() }, [])
  useEffect(() => { if (user) ws.connect(); else ws.disconnect() }, [user])
  return null
}

export default function App() {
  return (
    <BrowserRouter>
      <Init/>
      <Routes>
        <Route path="/login" element={<Login/>}/>
        <Route path="/" element={<AuthGuard><Shell/></AuthGuard>}>
          <Route index element={<Dashboard/>}/>
          <Route path="targets" element={<Targets/>}/>
          <Route path="targets/:id" element={<TargetDetail/>}/>
          <Route path="findings" element={<Findings/>}/>
          <Route path="tasks" element={<Tasks/>}/>
          <Route path="system" element={<System/>}/>
        </Route>
        <Route path="*" element={<Navigate to="/" replace/>}/>
      </Routes>
    </BrowserRouter>
  )
}
