import { afterEach, describe, expect, it, vi } from 'vitest'
import { apiRequest } from './client'
import {
  getSecurityEvents,
  ingestSecurityEvent,
} from './securityEvents'
import type {
  SecurityEventCreateRequest,
  SecurityEventResponse,
} from './types'

vi.mock('./client', () => ({
  apiRequest: vi.fn(),
}))

const apiRequestMock = vi.mocked(apiRequest)

afterEach(() => {
  vi.clearAllMocks()
})

describe('security event API', () => {
  it('fetches tenant-scoped events through the authenticated API client', async () => {
    apiRequestMock.mockResolvedValueOnce([])
    const controller = new AbortController()

    await expect(getSecurityEvents(controller.signal)).resolves.toEqual([])
    expect(apiRequestMock).toHaveBeenCalledWith(
      '/api/v1/security-events',
      { signal: controller.signal },
    )
  })

  it('posts the validated event without any client-supplied tenant id', async () => {
    const payload: SecurityEventCreateRequest = {
      event_type: 'failed_login',
      severity: 'high',
      source: 'identity-provider',
      description: 'Repeated sign-in failure',
      metadata: { attempt_count: 5 },
      origin: 'simulated',
    }
    const created: SecurityEventResponse = {
      id: 'event-1',
      tenant_id: 'tenant-from-auth',
      ...payload,
      payload: payload.metadata ?? {},
      metadata: payload.metadata ?? {},
      timestamp: '2026-11-26T10:00:00Z',
      created_at: '2026-11-26T10:00:00Z',
    }
    apiRequestMock.mockResolvedValueOnce(created)

    await expect(ingestSecurityEvent(payload)).resolves.toEqual(created)
    expect(apiRequestMock).toHaveBeenCalledWith('/api/v1/security-events', {
      method: 'POST',
      body: payload,
    })
    expect(payload).not.toHaveProperty('tenant_id')
  })

  it('propagates safe API errors to the form for display', async () => {
    const apiError = new Error('The request did not pass API validation.')
    apiRequestMock.mockRejectedValueOnce(apiError)

    await expect(
      ingestSecurityEvent({
        event_type: 'invalid',
        severity: 'medium',
        source: 'source',
        description: 'event',
        origin: 'manual',
      }),
    ).rejects.toBe(apiError)
  })
})
