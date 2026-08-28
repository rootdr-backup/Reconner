import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { ForcePasswordChange } from './ForcePasswordChange'
import { UpdateBanner } from './UpdateBanner'

export const Shell = () => (
  <div className="relative flex h-screen overflow-hidden">
    <div className="aurora" aria-hidden />
    <Sidebar/>
    <div className="relative z-10 flex flex-col flex-1 min-w-0 overflow-hidden">
      <TopBar/>
      <UpdateBanner/>
      <main className="flex-1 overflow-y-auto p-6"><Outlet/></main>
    </div>
    <ForcePasswordChange/>
  </div>
)
