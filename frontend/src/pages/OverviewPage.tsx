import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
} from 'react'
import { RefreshCw } from 'lucide-react'
import { fetchDashboard, type DashboardSection } from '../api/dashboard'
import type {
  AlertResponse,
  SecurityEventResponse,
  SecurityMonitoringSummary,
  VulnerabilitySummary,
} from '../api/types'
import {
  EventsOverTime,
  EventSources,
  MetricCard,
  RecentAlerts,
  RecentEvents,
  VulnerabilityDistribution,
  type DashboardWidgetState,
} from '../components/DashboardWidgets'

function initialState<T>(): DashboardWidgetState<T> {
  return { data: null, error: null, loading: true }
}

function applyResult<T>(
  setState: Dispatch<SetStateAction<DashboardWidgetState<T>>>,
  result: DashboardSection<T>,
) {
  setState((previous) => ({
    data: result.data ?? previous.data,
    error: result.error,
    loading: false,
  }))
}

export function OverviewPage() {
  const [monitoring, setMonitoring] =
    useState<DashboardWidgetState<SecurityMonitoringSummary>>(initialState)
  const [vulnerabilities, setVulnerabilities] =
    useState<DashboardWidgetState<VulnerabilitySummary>>(initialState)
  const [alerts, setAlerts] =
    useState<DashboardWidgetState<AlertResponse[]>>(initialState)
  const [events, setEvents] =
    useState<DashboardWidgetState<SecurityEventResponse[]>>(initialState)
  const [isRefreshing, setIsRefreshing] = useState(true)
  const [lastChecked, setLastChecked] = useState<Date | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  const load = useCallback(async (controller: AbortController) => {
    try {
      await fetchDashboard(controller.signal, {
        monitoring: (result) => applyResult(setMonitoring, result),
        vulnerabilities: (result) => applyResult(setVulnerabilities, result),
        alerts: (result) => applyResult(setAlerts, result),
        events: (result) => applyResult(setEvents, result),
      })
      if (!controller.signal.aborted) setLastChecked(new Date())
    } finally {
      if (controllerRef.current === controller) {
        controllerRef.current = null
        setIsRefreshing(false)
      }
    }
  }, [])

  const refresh = useCallback(() => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    setIsRefreshing(true)
    setMonitoring((state) => ({ ...state, loading: true, error: null }))
    setVulnerabilities((state) => ({ ...state, loading: true, error: null }))
    setAlerts((state) => ({ ...state, loading: true, error: null }))
    setEvents((state) => ({ ...state, loading: true, error: null }))
    void load(controller)
  }, [load])

  useEffect(() => {
    const controller = new AbortController()
    controllerRef.current = controller
    const timer = window.setTimeout(() => void load(controller), 0)
    return () => {
      window.clearTimeout(timer)
      controllerRef.current?.abort()
      controllerRef.current = null
    }
  }, [load])

  const openAlerts = monitoring.data
    ? monitoring.data.new_alerts + monitoring.data.acknowledged_alerts
    : null

  return (
    <div className="mx-auto max-w-7xl">
      <header className="mb-7 flex flex-col gap-5 sm:mb-8 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            SentinelKey / Security operations
          </p>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
            Overview
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
            Tenant-scoped event activity, alerts, and vulnerability exposure.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <p className="text-xs text-slate-500" aria-live="polite">
            {lastChecked
              ? `Last checked ${lastChecked.toLocaleTimeString()}`
              : 'Waiting for API data'}
          </p>
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={isRefreshing}
            className="inline-flex shrink-0 items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-400/40 hover:text-white disabled:cursor-wait disabled:opacity-60"
          >
            <RefreshCw
              aria-hidden="true"
              size={15}
              className={isRefreshing ? 'animate-spin' : ''}
            />
            {isRefreshing ? 'Refreshing' : 'Refresh'}
          </button>
        </div>
      </header>

      <section
        aria-label="Security metrics"
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5"
      >
        <MetricCard
          label="Total events"
          value={monitoring.data?.total_events ?? null}
          loading={monitoring.loading}
          error={monitoring.error}
          note="All recorded events"
          accent="bg-cyan-400"
        />
        <MetricCard
          label="Critical events"
          value={monitoring.data?.critical_events ?? null}
          loading={monitoring.loading}
          error={monitoring.error}
          note="All recorded events"
          accent="bg-rose-400"
        />
        <MetricCard
          label="High-severity events"
          value={monitoring.data?.high_severity_events ?? null}
          loading={monitoring.loading}
          error={monitoring.error}
          note="All recorded events"
          accent="bg-orange-400"
        />
        <MetricCard
          label="Open alerts"
          value={openAlerts}
          loading={monitoring.loading}
          error={monitoring.error}
          note="New + acknowledged"
          accent="bg-amber-300"
        />
        <MetricCard
          label="Open vulnerabilities"
          value={vulnerabilities.data?.open_findings ?? null}
          loading={vulnerabilities.loading}
          error={vulnerabilities.error}
          note="Open status"
          accent="bg-violet-400"
        />
      </section>

      <section
        aria-label="Security analytics"
        className="mt-5 grid gap-5 xl:grid-cols-[1.45fr_1fr]"
      >
        <EventsOverTime state={monitoring} />
        <EventSources state={monitoring} />
        <VulnerabilityDistribution state={vulnerabilities} />
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 shadow-lg shadow-black/10 sm:p-6">
          <div className="mb-5">
            <h2 className="text-base font-semibold text-slate-100">
              Alert status
            </h2>
            <p className="mt-1 text-xs text-slate-500">
              Tenant alert counts reported by the monitoring summary
            </p>
          </div>
          {!monitoring.data && monitoring.loading ? (
            <div className="flex min-h-40 items-center justify-center text-sm text-slate-400">
              Loading alert metrics…
            </div>
          ) : null}
          {!monitoring.data && !monitoring.loading && monitoring.error ? (
            <p role="alert" className="py-12 text-center text-sm text-rose-300">
              {monitoring.error}
            </p>
          ) : null}
          {monitoring.data ? (
            <div className="grid grid-cols-3 gap-3">
              {[
                ['New', monitoring.data.new_alerts, 'text-cyan-200'],
                [
                  'Acknowledged',
                  monitoring.data.acknowledged_alerts,
                  'text-amber-200',
                ],
                ['Resolved', monitoring.data.resolved_alerts, 'text-emerald-300'],
              ].map(([label, count, color]) => (
                <div
                  key={label}
                  className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 sm:p-4"
                >
                  <p className="text-xs text-slate-500">{label}</p>
                  <p className={`mt-3 text-2xl font-semibold tabular-nums ${color}`}>
                    {typeof count === 'number' ? count.toLocaleString() : count}
                  </p>
                </div>
              ))}
            </div>
          ) : null}
        </section>
      </section>

      <section
        aria-label="Recent activity"
        className="mt-5 grid gap-5 xl:grid-cols-2"
      >
        <RecentAlerts state={alerts} />
        <RecentEvents state={events} />
      </section>
    </div>
  )
}
