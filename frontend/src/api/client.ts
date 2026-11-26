import { clearAccessToken, getAccessToken } from '../auth/tokenStore'

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const unauthorizedEvent = 'sentinelkey:unauthorized'

export class ApiError extends Error {
  readonly status: number

  constructor(
    status: number,
    message: string,
  ) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

type ApiRequestOptions = Omit<RequestInit, 'body'> & {
  body?: unknown
  authenticated?: boolean
}

function messageForStatus(status: number): string {
  if (status === 401) return 'Session is invalid or expired. Enter a valid token.'
  if (status === 403) return 'You do not have permission to perform this action.'
  if (status === 422) return 'The request did not pass API validation.'
  if (status >= 500) return 'The SentinelKey API encountered an error.'
  return `The API request failed (HTTP ${status}).`
}

export async function apiRequest<T>(
  path: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  if (!path.startsWith('/api/')) {
    throw new ApiError(0, 'API requests must use a relative /api/ path.')
  }

  const { body, authenticated = true, ...requestOptions } = options
  const headers = new Headers(requestOptions.headers)
  const token = authenticated ? getAccessToken() : null

  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (body !== undefined) headers.set('Content-Type', 'application/json')

  let response: Response
  try {
    response = await fetch(`${apiBaseUrl}${path}`, {
      ...requestOptions,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error
    throw new ApiError(
      0,
      'Unable to reach the SentinelKey API. Check the backend connection.',
    )
  }

  if (response.status === 401) {
    clearAccessToken()
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new Event(unauthorizedEvent))
    }
  }

  if (!response.ok) {
    throw new ApiError(response.status, messageForStatus(response.status))
  }

  if (response.status === 204) return undefined as T
  if (!response.headers.get('content-type')?.includes('application/json')) {
    throw new ApiError(response.status, 'The API returned an unexpected response.')
  }

  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError(response.status, 'The API returned invalid JSON.')
  }
}
