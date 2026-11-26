import { AlertCircle, LoaderCircle } from 'lucide-react'
import type { ReactNode } from 'react'
import type {
  AlertResponse,
  AlertSeverity,
  AlertStatus,
  SecurityEventResponse,
  SecurityMonitoringSummary,
  VulnerabilitySummary,
} from '../api/types'
import type { DashboardSection } from '../api/dashboard'

export interface DashboardWidgetState<T> extends DashboardSection<T> {
  loading: boolean
}

interface PanelProps {
  title: string
  description: string
  children: ReactNode
  className?: string
}

function Panel({ title, description, children, className = '' }: PanelProps) {
  return (
    <section
      className={`rounded-2xl border border-slate-800 bg-slate-900/60 p-5 shadow-lg shadow-black/10 sm:p-6 ${className}`}
    >
      <div className="mb-5">
        <h2 className="text-base font-semibold text-slate-100">{title}</h2>
        <p className="mt-1 text-xs text-slate-500">{description}</p>
      </div>
      {children}
    </section>
  )
}

function LoadingState() {
  return (
    <div className="flex min-h-40 items-center justify-center gap-2 text-sm text-slate-400">
      <LoaderCircle aria-hidden="true" size={17} className="animate-spin" />
      Loading dashboard data…
    </div>
  )
}

function MessageState({
  message,
  error = false,
}: {
  message: string
  error?: boolean
}) {
  return (
    <div
      className={`flex min-h-40 flex-col items-center justify-center gap-2 text-center text-sm ${
        error ? 'text-rose-300' : 'text-slate-500'
      }`}
      role={error ? 'alert' : undefined}
    >
      {error ? <AlertCircle aria-hidden="true" size={19} /> : null}
      <span>{message}</span>
    </div>
  )
}

function StaleDataNotice({ error }: { error: string | null }) {
  if (!error) return null
  return (
    <p role="status" className="mb-3 text-xs text-amber-300">
      Refresh failed. Showing the last loaded data.
    </p>
  )
}

export interface MetricCardProps {
  label: string
  value: number | null
  loading: boolean
  error: string | null
  note: string
  accent: string
}

export function MetricCard({
  label,
  value,
  loading,
  error,
  note,
  accent,
}: MetricCardProps) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/65 p-4 shadow-lg shadow-black/10 sm:p-5">
      <div className="flex items-start justify-between gap-3">
        <p className="text-xs font-medium text-slate-400">{label}</p>
        <span className={`mt-1 size-2 rounded-full ${accent}`} />
      </div>
      <p className="mt-4 text-3xl font-semibold tracking-tight text-white tabular-nums">
        {value !== null ? value.toLocaleString() : loading ? '…' : '—'}
      </p>
      <p className="mt-2 text-[11px] text-slate-500">{note}</p>
      {error && value === null ? (
        <p role="alert" className="mt-2 text-xs text-rose-300">
          {error}
        </p>
      ) : null}
      {error && value !== null ? (
        <p role="status" className="mt-2 text-xs text-amber-300">
          Refresh failed; showing last loaded value.
        </p>
      ) : null}
    </section>
  )
}

export function EventsOverTime({
  state,
}: {
  state: DashboardWidgetState<SecurityMonitoringSummary>
}) {
  const buckets = state.data?.events_over_time ?? []
  const totalInPeriod = buckets.reduce((sum, bucket) => sum + bucket.count, 0)

  return (
    <Panel
      title="Events over time"
      description="Daily event volume for the last 30 days"
    >
      {!state.data && state.loading ? <LoadingState /> : null}
      {!state.data && !state.loading && state.error ? (
        <MessageState message={state.error} error />
      ) : null}
      {state.data ? (
        <>
          <StaleDataNotice error={state.error} />
          {buckets.length === 0 || totalInPeriod === 0 ? (
            <MessageState message="No security events recorded in this period." />
          ) : (
            <EventsLineChart buckets={buckets} />
          )}
        </>
      ) : null}
    </Panel>
  )
}

function EventsLineChart({
  buckets,
}: {
  buckets: SecurityMonitoringSummary['events_over_time']
}) {
  const width = 720
  const height = 220
  const left = 42
  const right = 12
  const top = 14
  const bottom = 32
  const plotWidth = width - left - right
  const plotHeight = height - top - bottom
  const maximum = Math.max(1, ...buckets.map((bucket) => bucket.count))
  const points = buckets.map((bucket, index) => {
    const x =
      left +
      (buckets.length < 2 ? plotWidth / 2 : (index / (buckets.length - 1)) * plotWidth)
    const y = top + plotHeight - (bucket.count / maximum) * plotHeight
    return { x, y, bucket }
  })
  const line = points.map(({ x, y }) => `${x},${y}`).join(' ')
  const area = `${left},${top + plotHeight} ${line} ${left + plotWidth},${top + plotHeight}`
  const middleIndex = Math.floor((buckets.length - 1) / 2)
  const labelIndices = [...new Set([0, middleIndex, buckets.length - 1])]
  const yLabels = [...new Set([maximum, Math.ceil(maximum / 2), 0])]

  return (
    <div>
      <div className="mb-3 flex items-center justify-between text-xs text-slate-500">
        <span>{buckets.reduce((sum, bucket) => sum + bucket.count, 0).toLocaleString()} events</span>
        <span>30-day window</span>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full overflow-visible"
        role="img"
        aria-label="Daily security event counts over the last 30 days"
      >
        {yLabels.map((label) => {
          const y = top + plotHeight - (label / maximum) * plotHeight
          return (
            <g key={label}>
              <line
                x1={left}
                x2={width - right}
                y1={y}
                y2={y}
                stroke="#1e293b"
                strokeDasharray="3 5"
              />
              <text
                x={left - 9}
                y={y + 4}
                textAnchor="end"
                fill="#64748b"
                fontSize="10"
              >
                {label}
              </text>
            </g>
          )
        })}
        <polygon points={area} fill="url(#event-area)" />
        <defs>
          <linearGradient id="event-area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.22" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
          </linearGradient>
        </defs>
        <polyline
          points={line}
          fill="none"
          stroke="#22d3ee"
          strokeWidth="2.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        {points.map(({ x, y, bucket }) => (
          <circle key={bucket.date} cx={x} cy={y} r="3" fill="#67e8f9">
            <title>{`${bucket.date}: ${bucket.count} events`}</title>
          </circle>
        ))}
        {labelIndices.map((index) => {
          const bucket = buckets[index]
          if (!bucket) return null
          const x =
            left +
            (buckets.length < 2 ? plotWidth / 2 : (index / (buckets.length - 1)) * plotWidth)
          return (
            <text
              key={bucket.date}
              x={x}
              y={height - 7}
              textAnchor={index === 0 ? 'start' : index === buckets.length - 1 ? 'end' : 'middle'}
              fill="#64748b"
              fontSize="10"
            >
              {formatDate(bucket.date)}
            </text>
          )
        })}
      </svg>
    </div>
  )
}

export function EventSources({
  state,
}: {
  state: DashboardWidgetState<SecurityMonitoringSummary>
}) {
  const sources = Object.entries(state.data?.events_by_source ?? {}).sort(
    (left, right) => right[1] - left[1],
  )
  const maximum = Math.max(1, ...sources.map(([, count]) => count))

  return (
    <Panel title="Events by source" description="Distribution across event sources">
      {!state.data && state.loading ? <LoadingState /> : null}
      {!state.data && !state.loading && state.error ? (
        <MessageState message={state.error} error />
      ) : null}
      {state.data ? (
        <>
          <StaleDataNotice error={state.error} />
          {sources.length === 0 ? (
            <MessageState message="No event sources to display." />
          ) : (
            <div className="space-y-5">
              {sources.map(([source, count]) => (
                <div key={source}>
                  <div className="mb-2 flex items-center justify-between gap-4 text-sm">
                    <span className="truncate text-slate-300">{source}</span>
                    <span className="shrink-0 font-medium tabular-nums text-slate-100">
                      {count.toLocaleString()}
                    </span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-cyan-400"
                      style={{ width: `${(count / maximum) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      ) : null}
    </Panel>
  )
}

export function VulnerabilityDistribution({
  state,
}: {
  state: DashboardWidgetState<VulnerabilitySummary>
}) {
  const summary = state.data
  const knownSeverityTotal = summary
    ? summary.critical_findings +
      summary.high_findings +
      summary.medium_findings +
      summary.low_findings
    : 0
  const severityCounts = summary
    ? [
        { label: 'Critical', count: summary.critical_findings, color: 'bg-rose-400' },
        { label: 'High', count: summary.high_findings, color: 'bg-orange-400' },
        { label: 'Medium', count: summary.medium_findings, color: 'bg-amber-300' },
        { label: 'Low', count: summary.low_findings, color: 'bg-cyan-400' },
        {
          label: 'Informational',
          count: Math.max(0, summary.total_vulnerabilities - knownSeverityTotal),
          color: 'bg-slate-400',
        },
      ]
    : []
  const maximum = Math.max(1, ...severityCounts.map(({ count }) => count))

  return (
    <Panel
      title="Vulnerability severity"
      description="Finding counts by severity"
    >
      {!summary && state.loading ? <LoadingState /> : null}
      {!summary && !state.loading && state.error ? (
        <MessageState message={state.error} error />
      ) : null}
      {summary ? (
        <>
          <StaleDataNotice error={state.error} />
          {summary.total_vulnerabilities === 0 ? (
            <MessageState message="No vulnerability findings to display." />
          ) : (
            <div className="space-y-4">
              {severityCounts.map(({ label, count, color }) => (
                <div key={label}>
                  <div className="mb-1.5 flex items-center justify-between text-sm">
                    <span className="text-slate-300">{label}</span>
                    <span className="font-medium tabular-nums text-slate-100">
                      {count.toLocaleString()}
                    </span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className={`h-full rounded-full ${color}`}
                      style={{ width: `${(count / maximum) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      ) : null}
    </Panel>
  )
}

const severityStyles: Record<AlertSeverity, string> = {
  critical: 'border-rose-400/20 bg-rose-400/10 text-rose-200',
  high: 'border-orange-400/20 bg-orange-400/10 text-orange-200',
  medium: 'border-amber-300/20 bg-amber-300/10 text-amber-200',
  low: 'border-cyan-400/20 bg-cyan-400/10 text-cyan-200',
  informational: 'border-slate-400/20 bg-slate-400/10 text-slate-300',
}

const statusStyles: Record<AlertStatus, string> = {
  New: 'text-cyan-200',
  Acknowledged: 'text-amber-200',
  Resolved: 'text-emerald-300',
}

function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return (
    <span
      className={`inline-flex rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wide ${severityStyles[severity]}`}
    >
      {severity}
    </span>
  )
}

export function RecentAlerts({
  state,
}: {
  state: DashboardWidgetState<AlertResponse[]>
}) {
  const alerts = [...(state.data ?? [])]
    .sort(
      (left, right) =>
        new Date(right.created_at).getTime() -
        new Date(left.created_at).getTime(),
    )
    .slice(0, 6)

  return (
    <Panel
      title="Recent alerts"
      description="Latest tenant alerts with current status"
    >
      {!state.data && state.loading ? <LoadingState /> : null}
      {!state.data && !state.loading && state.error ? (
        <MessageState message={state.error} error />
      ) : null}
      {state.data ? (
        <>
          <StaleDataNotice error={state.error} />
          {alerts.length === 0 ? (
            <MessageState message="No alerts have been generated." />
          ) : (
            <ul className="divide-y divide-slate-800">
              {alerts.map((alert) => (
                <li key={alert.id} className="py-4 first:pt-0 last:pb-0">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0">
                      <p className="text-sm leading-5 text-slate-200">
                        {alert.description}
                      </p>
                      <p className="mt-1.5 text-xs text-slate-500">
                        {alert.rule_id} · {formatTimestamp(alert.created_at)}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <SeverityBadge severity={alert.severity} />
                      <span className={`text-xs font-medium ${statusStyles[alert.status]}`}>
                        {alert.status}
                      </span>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : null}
    </Panel>
  )
}

export function RecentEvents({
  state,
}: {
  state: DashboardWidgetState<SecurityEventResponse[]>
}) {
  const events = [...(state.data ?? [])]
    .sort(
      (left, right) =>
        new Date(right.timestamp).getTime() -
        new Date(left.timestamp).getTime(),
    )
    .slice(0, 6)

  return (
    <Panel
      title="Recent security events"
      description="Latest events by event timestamp"
    >
      {!state.data && state.loading ? <LoadingState /> : null}
      {!state.data && !state.loading && state.error ? (
        <MessageState message={state.error} error />
      ) : null}
      {state.data ? (
        <>
          <StaleDataNotice error={state.error} />
          {events.length === 0 ? (
            <MessageState message="No security events have been recorded." />
          ) : (
            <ul className="divide-y divide-slate-800">
              {events.map((event) => (
                <li key={event.id} className="py-4 first:pt-0 last:pb-0">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium capitalize text-slate-200">
                        {event.event_type.replaceAll('_', ' ')}
                      </p>
                      <p className="mt-1 truncate text-xs text-slate-500">
                        {event.source} · {formatTimestamp(event.timestamp)}
                      </p>
                    </div>
                    <SeverityBadge
                      severity={event.severity}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : null}
    </Panel>
  )
}

function formatDate(value: string): string {
  const date = new Date(`${value}T00:00:00`)
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function formatTimestamp(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}
