import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { ForcePasswordChange } from './ForcePasswordChange'
import { UpdateBanner } from './UpdateBanner'
import { UpdateCenterProvider } from './UpdateCenter'

export const Shell = () => (
  <UpdateCenterProvider>
    <div className="recon-shell relative flex h-[100dvh] overflow-hidden">
      <div className="command-grid" aria-hidden />
      <Sidebar/>
      <div className="relative z-10 flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar/>
        <UpdateBanner/>
        <main className="workspace flex-1 overflow-y-auto overflow-x-hidden p-4 sm:p-6 xl:p-8">
          <div className="w-full max-w-[1680px] mx-auto"><Outlet/></div>
        </main>
      </div>
      <ForcePasswordChange/>
    </div>
  </UpdateCenterProvider>
)
