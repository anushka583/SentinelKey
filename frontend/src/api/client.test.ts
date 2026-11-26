import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiRequest } from './client'
import {
  clearAccessToken,
  getAccessToken,
  setAccessToken,
} from '../auth/tokenStore'

afterEach(() => {
  clearAccessToken()
  vi.unstubAllGlobals()
})

describe('apiRequest', () => {
  it('attaches the in-memory bearer token to API requests', async () => {
    setAccessToken('test-token')
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        Response.json([{ id: 'tenant-1', name: 'Local Lab' }]),
      )
    vi.stubGlobal('fetch', fetchMock)

    const tenants = await apiRequest<Array<{ id: string; name: string }>>(
      '/api/v1/tenants',
    )

    expect(tenants[0]?.name).toBe('Local Lab')
    const request = fetchMock.mock.calls[0]?.[1]
    expect(new Headers(request?.headers).get('Authorization')).toBe(
      'Bearer test-token',
    )
  })

  it('clears the in-memory token on 401 without exposing the response body', async () => {
    setAccessToken('private-test-token')
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue(
        Response.json({ detail: 'private-test-token' }, { status: 401 }),
      ),
    )

    await expect(apiRequest('/api/v1/tenants')).rejects.toMatchObject({
      status: 401,
      message: 'Session is invalid or expired. Enter a valid token.',
    })
    expect(getAccessToken()).toBeNull()
  })

  it('reports permission failures without clearing the session', async () => {
    setAccessToken('test-token')
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockResolvedValue(
        Response.json({ detail: 'Forbidden' }, { status: 403 }),
      ),
    )

    await expect(apiRequest('/api/v1/vulnerabilities')).rejects.toBeInstanceOf(
      ApiError,
    )
    expect(getAccessToken()).toBe('test-token')
  })

  it('converts network failures into a safe, non-sensitive message', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockRejectedValue(
        new TypeError('network failed for private-token'),
      ),
    )

    await expect(apiRequest('/api/v1/tenants')).rejects.toMatchObject({
      status: 0,
      message:
        'Unable to reach the SentinelKey API. Check the backend connection.',
    })
  })

  it('refuses non-API paths so tokens cannot be sent to arbitrary URLs', async () => {
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)

    await expect(apiRequest('https://example.test/collect')).rejects.toThrow(
      'API requests must use a relative /api/ path.',
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
