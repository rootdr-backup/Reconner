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
  if (!initialized) return <div className="min-h-screen flex items-center justify-center bg-surface"><Spinner className="w-6 h-6"/></div>
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
