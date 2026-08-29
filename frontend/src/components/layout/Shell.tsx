import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { ForcePasswordChange } from './ForcePasswordChange'
import { UpdateBanner } from './UpdateBanner'
import { useUIStore } from '../../store/ui'

export const Shell = () => {
  const { sidebarOpen, setSidebarOpen } = useUIStore()
  return (
    <div className="relative flex h-screen overflow-hidden">
      <div className="aurora" aria-hidden />
      <div className="scanlines" aria-hidden />
      {/* Mobile off-canvas backdrop — tap to close the sidebar drawer. */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/70 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden
        />
      )}
      <Sidebar/>
      <div className="relative z-10 flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar/>
        <UpdateBanner/>
        <main className="flex-1 overflow-y-auto p-4 sm:p-6"><Outlet/></main>
      </div>
      <ForcePasswordChange/>
    </div>
  )
}
