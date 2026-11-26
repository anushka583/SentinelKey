import {
  Activity,
  BellRing,
  Bug,
  LayoutDashboard,
  LogOut,
  ShieldCheck,
} from 'lucide-react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'

const navigation = [
  { label: 'Overview', to: '/', icon: LayoutDashboard },
  { label: 'Events', to: '/events', icon: Activity },
  { label: 'Alerts', to: '/alerts', icon: BellRing },
  { label: 'Vulnerabilities', to: '/vulnerabilities', icon: Bug },
]

function NavigationLinks({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <>
      {navigation.map(({ label, to, icon: Icon }) => (
        <NavLink
          key={to}
          to={to}
          end={to === '/'}
          onClick={onNavigate}
          className={({ isActive }) =>
            `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition ${
              isActive
                ? 'bg-cyan-400/10 text-cyan-200 ring-1 ring-inset ring-cyan-300/15'
                : 'text-slate-400 hover:bg-slate-800/70 hover:text-slate-100'
            }`
          }
        >
          <Icon aria-hidden="true" size={18} />
          {label}
        </NavLink>
      ))}
    </>
  )
}

export function AppShell() {
  const { signOut } = useAuth()
  const location = useLocation()
  const currentPage =
    navigation.find((item) => item.to === location.pathname)?.label ?? 'Overview'

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col border-r border-slate-800/80 bg-slate-950 lg:flex">
        <div className="flex h-20 items-center gap-3 px-6">
          <div className="flex size-10 items-center justify-center rounded-xl border border-cyan-300/20 bg-cyan-400/10 text-cyan-300">
            <ShieldCheck aria-hidden="true" size={22} />
          </div>
          <div>
            <p className="text-base font-semibold tracking-wide text-white">
              SentinelKey
            </p>
            <p className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">
              Security operations
            </p>
          </div>
        </div>

        <div className="px-4 pt-6">
          <p className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">
            Workspace
          </p>
          <nav aria-label="Primary navigation" className="space-y-1">
            <NavigationLinks />
          </nav>
        </div>

        <div className="mt-auto border-t border-slate-800/80 p-4">
          <div className="mb-4 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
              Session status
            </p>
            <p className="mt-1 truncate text-sm font-medium text-slate-200">
              API access verified
            </p>
            <p className="mt-1 flex items-center gap-2 text-xs text-emerald-300">
              <span className="size-1.5 rounded-full bg-emerald-400" />
              API session verified
            </p>
          </div>
          <button
            type="button"
            onClick={signOut}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-slate-400 transition hover:bg-slate-800 hover:text-white"
          >
            <LogOut aria-hidden="true" size={17} />
            Sign out
          </button>
        </div>
      </aside>

      <div className="lg:pl-64">
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-slate-800/80 bg-slate-950/95 px-4 backdrop-blur sm:px-7">
          <div className="flex items-center gap-3">
            <div className="flex size-9 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-400/10 text-cyan-300 lg:hidden">
              <ShieldCheck aria-hidden="true" size={20} />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">{currentPage}</p>
              <p className="hidden text-xs text-slate-500 sm:block">
                SentinelKey security workspace
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 rounded-full border border-emerald-400/15 bg-emerald-400/5 px-3 py-1.5 text-xs font-medium text-emerald-300 sm:inline-flex">
              <span className="size-1.5 rounded-full bg-emerald-400" />
              Connected
            </span>
            <button
              type="button"
              onClick={signOut}
              aria-label="Sign out"
              className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white lg:hidden"
            >
              <LogOut aria-hidden="true" size={18} />
            </button>
          </div>
        </header>

        <nav
          aria-label="Mobile navigation"
          className="flex gap-1 overflow-x-auto border-b border-slate-800/80 px-3 py-2 lg:hidden"
        >
          {navigation.map(({ label, to }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `shrink-0 rounded-lg px-3 py-2 text-xs font-medium transition ${
                  isActive
                    ? 'bg-cyan-400/10 text-cyan-200'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        <main className="mx-auto min-h-[calc(100vh-4rem)] max-w-7xl px-4 py-8 sm:px-7 sm:py-10">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
