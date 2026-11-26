import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, Plus, RefreshCw, Search } from 'lucide-react'
import { ApiError } from '../api/client'
import { getSecurityEvents } from '../api/securityEvents'
import type {
  SecurityEventResponse,
  SecurityEventSeverity,
} from '../api/types'
import { EventDetailsDialog } from '../components/EventDetailsDialog'
import { EventIngestionForm } from '../components/EventIngestionForm'
import { filterSecurityEvents, type EventFilters } from '../events/eventUtils'

const severityOptions: SecurityEventSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]

const severityStyles: Record<SecurityEventSeverity, string> = {
  critical: 'border-rose-400/20 bg-rose-400/10 text-rose-200',
  high: 'border-orange-400/20 bg-orange-400/10 text-orange-200',
  medium: 'border-amber-300/20 bg-amber-300/10 text-amber-200',
  low: 'border-cyan-400/20 bg-cyan-400/10 text-cyan-200',
  informational: 'border-slate-400/20 bg-slate-400/10 text-slate-300',
}

const initialFilters: EventFilters = {
  search: '',
  severity: '',
  source: '',
  eventType: '',
}

function messageForError(error: unknown): string {
  if (error instanceof ApiError) return error.message
  return 'Unable to load security events. Check the API connection and try again.'
}

function formatTimestamp(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function SeverityBadge({ severity }: { severity: SecurityEventSeverity }) {
  return (
    <span
      className={`inline-flex rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wide ${severityStyles[severity]}`}
    >
      {severity}
    </span>
  )
}

export function EventsPage() {
  const [events, setEvents] = useState<SecurityEventResponse[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isIngestionOpen, setIsIngestionOpen] = useState(false)
  const [selectedEvent, setSelectedEvent] =
    useState<SecurityEventResponse | null>(null)
  const [filters, setFilters] = useState<EventFilters>(initialFilters)
  const controllerRef = useRef<AbortController | null>(null)

  const loadEvents = useCallback(async (controller: AbortController) => {
    try {
      const result = await getSecurityEvents(controller.signal)
      if (!controller.signal.aborted) {
        setEvents(result)
        setError(null)
      }
    } catch (cause) {
      if (controller.signal.aborted || (cause instanceof Error && cause.name === 'AbortError')) {
        return
      }
      setError(messageForError(cause))
    } finally {
      if (controllerRef.current === controller) {
        controllerRef.current = null
        setIsLoading(false)
      }
    }
  }, [])

  const refreshEvents = useCallback(async () => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    setIsLoading(true)
    setError(null)
    await loadEvents(controller)
  }, [loadEvents])

  useEffect(() => {
    const controller = new AbortController()
    controllerRef.current = controller
    const timer = window.setTimeout(() => void loadEvents(controller), 0)
    return () => {
      window.clearTimeout(timer)
      controllerRef.current?.abort()
      controllerRef.current = null
    }
  }, [loadEvents])

  const sources = useMemo(
    () => [...new Set(events.map((event) => event.source))].sort(),
    [events],
  )
  const eventTypes = useMemo(
    () => [...new Set(events.map((event) => event.event_type))].sort(),
    [events],
  )
  const visibleEvents = useMemo(
    () =>
      filterSecurityEvents(events, filters).sort(
        (left, right) =>
          new Date(right.timestamp).getTime() -
          new Date(left.timestamp).getTime(),
      ),
    [events, filters],
  )
  const hasActiveFilters = Boolean(
    filters.search || filters.severity || filters.source || filters.eventType,
  )

  function updateFilter<K extends keyof EventFilters>(
    key: K,
    value: EventFilters[K],
  ) {
    setFilters((current) => ({ ...current, [key]: value }))
  }

  return (
    <div className="mx-auto max-w-7xl">
      <header className="mb-7 flex flex-col gap-5 sm:mb-8 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
            SentinelKey / Security operations
          </p>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
            Security events
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
            Search, filter, inspect, and ingest tenant-scoped security events.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void refreshEvents()}
            disabled={isLoading}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm font-medium text-slate-200 transition hover:border-cyan-400/40 hover:text-white disabled:cursor-wait disabled:opacity-60"
          >
            <RefreshCw
              aria-hidden="true"
              size={15}
              className={isLoading ? 'animate-spin' : ''}
            />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => setIsIngestionOpen((open) => !open)}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-400 px-3 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
          >
            <Plus aria-hidden="true" size={16} />
            Ingest event
          </button>
        </div>
      </header>

      {isIngestionOpen ? (
        <div className="mb-5">
          <EventIngestionForm
            onCancel={() => setIsIngestionOpen(false)}
            onIngested={refreshEvents}
          />
        </div>
      ) : null}

      <section
        aria-label="Security event filters"
        className="mb-5 rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-5"
      >
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-[minmax(220px,1.5fr)_repeat(3,minmax(150px,1fr))_auto]">
          <label className="relative block">
            <span className="sr-only">Search events</span>
            <Search
              aria-hidden="true"
              size={16}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
            />
            <input
              type="search"
              value={filters.search}
              onChange={(event) => updateFilter('search', event.target.value)}
              placeholder="Search type, source, description"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2.5 pl-9 pr-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-400/60"
            />
          </label>

          <label>
            <span className="sr-only">Filter by severity</span>
            <select
              value={filters.severity}
              onChange={(event) =>
                updateFilter(
                  'severity',
                  event.target.value as EventFilters['severity'],
                )
              }
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm capitalize text-slate-200 outline-none focus:border-cyan-400/60"
            >
              <option value="">All severities</option>
              {severityOptions.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span className="sr-only">Filter by source</span>
            <select
              value={filters.source}
              onChange={(event) => updateFilter('source', event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-200 outline-none focus:border-cyan-400/60"
            >
              <option value="">All sources</option>
              {sources.map((source) => (
                <option key={source} value={source}>
                  {source}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span className="sr-only">Filter by event type</span>
            <select
              value={filters.eventType}
              onChange={(event) => updateFilter('eventType', event.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-200 outline-none focus:border-cyan-400/60"
            >
              <option value="">All event types</option>
              {eventTypes.map((eventType) => (
                <option key={eventType} value={eventType}>
                  {eventType}
                </option>
              ))}
            </select>
          </label>

          <button
            type="button"
            onClick={() => setFilters(initialFilters)}
            disabled={!hasActiveFilters}
            className="rounded-lg border border-slate-700 px-3 py-2.5 text-sm text-slate-400 transition hover:bg-slate-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            Clear filters
          </button>
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
          <p aria-live="polite">
            Showing {visibleEvents.length.toLocaleString()} of{' '}
            {events.length.toLocaleString()} events
          </p>
          <p>Client-side filters · API list is unpaginated</p>
        </div>
      </section>

      {error ? (
        <div
          role="alert"
          className="mb-5 flex flex-col gap-3 rounded-xl border border-rose-400/20 bg-rose-400/5 px-4 py-3 text-sm text-rose-200 sm:flex-row sm:items-center sm:justify-between"
        >
          <span className="inline-flex items-center gap-2">
            <AlertCircle aria-hidden="true" size={17} />
            {error}
          </span>
          {events.length > 0 ? (
            <span className="text-xs text-amber-200">
              Showing the last loaded event list.
            </span>
          ) : null}
        </div>
      ) : null}

      <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60 shadow-lg shadow-black/10">
        {isLoading && events.length === 0 ? (
          <div className="flex min-h-56 flex-col items-center justify-center gap-3 text-sm text-slate-400">
            <RefreshCw aria-hidden="true" size={20} className="animate-spin" />
            Loading security events…
          </div>
        ) : null}

        {!isLoading && events.length === 0 && !error ? (
          <div className="px-5 py-16 text-center">
            <h2 className="text-base font-semibold text-slate-200">
              No security events yet
            </h2>
            <p className="mt-2 text-sm text-slate-500">
              Ingest an event or connect an authorized source to begin monitoring.
            </p>
          </div>
        ) : null}

        {!isLoading && events.length > 0 && visibleEvents.length === 0 ? (
          <div className="px-5 py-16 text-center">
            <h2 className="text-base font-semibold text-slate-200">
              No matching events
            </h2>
            <p className="mt-2 text-sm text-slate-500">
              Adjust or clear the current search and filters.
            </p>
          </div>
        ) : null}

        {visibleEvents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-left">
              <thead className="border-b border-slate-800 bg-slate-950/50">
                <tr>
                  {[
                    'Timestamp',
                    'Event type',
                    'Source',
                    'Description',
                    'Severity',
                    'Origin',
                    '',
                  ].map((heading) => (
                    <th
                      key={heading || 'details'}
                      scope="col"
                      className="px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {visibleEvents.map((event) => (
                  <tr
                    key={event.id}
                    className="transition hover:bg-slate-800/30"
                  >
                    <td className="whitespace-nowrap px-4 py-4 text-xs text-slate-400">
                      {formatTimestamp(event.timestamp)}
                    </td>
                    <td className="px-4 py-4 text-sm font-medium text-slate-200">
                      {event.event_type}
                    </td>
                    <td className="px-4 py-4 text-sm text-slate-300">
                      {event.source}
                    </td>
                    <td className="max-w-sm px-4 py-4 text-sm text-slate-400">
                      <span className="line-clamp-2">{event.description}</span>
                    </td>
                    <td className="px-4 py-4">
                      <SeverityBadge severity={event.severity} />
                    </td>
                    <td className="px-4 py-4 text-xs capitalize text-slate-400">
                      {event.origin}
                    </td>
                    <td className="px-4 py-4 text-right">
                      <button
                        type="button"
                        onClick={() => setSelectedEvent(event)}
                        className="whitespace-nowrap rounded-lg px-2.5 py-1.5 text-xs font-medium text-cyan-200 transition hover:bg-cyan-400/10"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      {selectedEvent ? (
        <EventDetailsDialog
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      ) : null}
    </div>
  )
}
