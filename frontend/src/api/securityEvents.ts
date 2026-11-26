import { apiRequest } from './client'
import type {
  SecurityEventCreateRequest,
  SecurityEventResponse,
} from './types'

export function getSecurityEvents(
  signal?: AbortSignal,
): Promise<SecurityEventResponse[]> {
  return apiRequest<SecurityEventResponse[]>('/api/v1/security-events', {
    signal,
  })
}

export function ingestSecurityEvent(
  event: SecurityEventCreateRequest,
): Promise<SecurityEventResponse> {
  return apiRequest<SecurityEventResponse>('/api/v1/security-events', {
    method: 'POST',
    body: event,
  })
}
