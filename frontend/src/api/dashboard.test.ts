import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiRequest } from './client'
import { fetchDashboard } from './dashboard'

vi.mock('./client', () => ({
  ApiError: class ApiError extends Error {
    readonly status: number

    constructor(
      status: number,
      message: string,
    ) {
      super(message)
      this.status = status
    }
  },
  apiRequest: vi.fn(),
}))

const apiRequestMock = vi.mocked(apiRequest)

afterEach(() => {
  vi.clearAllMocks()
})

describe('fetchDashboard', () => {
  it('requests the documented dashboard endpoints and returns their data', async () => {
    const monitoring = {
      total_events: 9,
      critical_events: 1,
      high_severity_events: 2,
      events_by_source: { idp: 9 },
      new_alerts: 1,
      acknowledged_alerts: 2,
      resolved_alerts: 0,
      events_over_time: [{ date: '2026-11-26', count: 9 }],
    }
    const vulnerabilities = {
      total_vulnerabilities: 3,
      critical_findings: 1,
      high_findings: 1,
      medium_findings: 1,
      low_findings: 0,
      open_findings: 2,
      resolved_findings: 1,
      overdue_findings: 0,
    }
    const alerts = [
      {
        id: 'alert-1',
        tenant_id: 'tenant-1',
        event_id: 'event-1',
        rule_id: 'high_severity_event',
        severity: 'critical',
        description: 'Critical event',
        status: 'New',
        created_at: '2026-11-26T10:00:00Z',
        updated_at: '2026-11-26T10:00:00Z',
      },
    ]
    const events = [
      {
        id: 'event-1',
        tenant_id: 'tenant-1',
        event_type: 'suspicious_login',
        severity: 'critical',
        source: 'idp',
        description: 'Suspicious sign-in',
        payload: {},
        metadata: {},
        timestamp: '2026-11-26T10:00:00Z',
        origin: 'manual',
        created_at: '2026-11-26T10:00:00Z',
      },
    ]
    apiRequestMock
      .mockResolvedValueOnce(monitoring)
      .mockResolvedValueOnce(vulnerabilities)
      .mockResolvedValueOnce(alerts)
      .mockResolvedValueOnce(events)

    const results = {
      monitoring: null as unknown,
      vulnerabilities: null as unknown,
      alerts: null as unknown,
      events: null as unknown,
    }
    const controller = new AbortController()
    await fetchDashboard(controller.signal, {
      monitoring: (result) => {
        results.monitoring = result
      },
      vulnerabilities: (result) => {
        results.vulnerabilities = result
      },
      alerts: (result) => {
        results.alerts = result
      },
      events: (result) => {
        results.events = result
      },
    })

    expect(apiRequestMock).toHaveBeenNthCalledWith(
      1,
      '/api/v1/security-events/summary?days=30',
      { signal: controller.signal },
    )
    expect(apiRequestMock).toHaveBeenNthCalledWith(
      2,
      '/api/v1/vulnerabilities/summary',
      { signal: controller.signal },
    )
    expect(apiRequestMock).toHaveBeenNthCalledWith(
      3,
      '/api/v1/alerts',
      { signal: controller.signal },
    )
    expect(apiRequestMock).toHaveBeenNthCalledWith(
      4,
      '/api/v1/security-events',
      { signal: controller.signal },
    )
    expect(results.monitoring).toEqual({ data: monitoring, error: null })
    expect(results.vulnerabilities).toEqual({
      data: vulnerabilities,
      error: null,
    })
    expect(results.alerts).toEqual({ data: alerts, error: null })
    expect(results.events).toEqual({ data: events, error: null })
  })

  it('keeps other dashboard sections available when one request fails', async () => {
    apiRequestMock
      .mockRejectedValueOnce(new ApiError(403, 'You do not have permission.'))
      .mockResolvedValueOnce({
        total_vulnerabilities: 0,
        critical_findings: 0,
        high_findings: 0,
        medium_findings: 0,
        low_findings: 0,
        open_findings: 0,
        resolved_findings: 0,
        overdue_findings: 0,
      })
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])

    const results = {
      monitoring: null as unknown,
      vulnerabilities: null as unknown,
      alerts: null as unknown,
      events: null as unknown,
    }
    await fetchDashboard(new AbortController().signal, {
      monitoring: (result) => {
        results.monitoring = result
      },
      vulnerabilities: (result) => {
        results.vulnerabilities = result
      },
      alerts: (result) => {
        results.alerts = result
      },
      events: (result) => {
        results.events = result
      },
    })

    expect(results.monitoring).toEqual({
      data: null,
      error: 'You do not have permission.',
    })
    expect(results.vulnerabilities).toMatchObject({
      data: { total_vulnerabilities: 0 },
      error: null,
    })
    expect(results.alerts).toEqual({ data: [], error: null })
    expect(results.events).toEqual({ data: [], error: null })
  })
})
