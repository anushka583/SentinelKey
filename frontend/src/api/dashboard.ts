import { ApiError, apiRequest } from './client'
import type {
  AlertResponse,
  SecurityEventResponse,
  SecurityMonitoringSummary,
  VulnerabilitySummary,
} from './types'

export interface DashboardSection<T> {
  data: T | null
  error: string | null
}

export interface DashboardHandlers {
  monitoring: (result: DashboardSection<SecurityMonitoringSummary>) => void
  vulnerabilities: (result: DashboardSection<VulnerabilitySummary>) => void
  alerts: (result: DashboardSection<AlertResponse[]>) => void
  events: (result: DashboardSection<SecurityEventResponse[]>) => void
}

async function loadSection<T>(
  path: string,
  signal: AbortSignal,
  onResult: (result: DashboardSection<T>) => void,
): Promise<void> {
  try {
    const data = await apiRequest<T>(path, { signal })
    if (!signal.aborted) onResult({ data, error: null })
  } catch (error) {
    if (signal.aborted || (error instanceof Error && error.name === 'AbortError')) {
      return
    }

    const message =
      error instanceof ApiError
        ? error.message
        : 'Unable to load this dashboard section.'
    onResult({ data: null, error: message })
  }
}

export function fetchDashboard(
  signal: AbortSignal,
  handlers: DashboardHandlers,
): Promise<void> {
  return Promise.all([
    loadSection(
      '/api/v1/security-events/summary?days=30',
      signal,
      handlers.monitoring,
    ),
    loadSection(
      '/api/v1/vulnerabilities/summary',
      signal,
      handlers.vulnerabilities,
    ),
    loadSection('/api/v1/alerts', signal, handlers.alerts),
    loadSection('/api/v1/security-events', signal, handlers.events),
  ]).then(() => undefined)
}
