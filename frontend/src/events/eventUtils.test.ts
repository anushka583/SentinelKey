import { describe, expect, it } from 'vitest'
import type { SecurityEventResponse } from '../api/types'
import {
  filterSecurityEvents,
  validateEventDraft,
  type EventDraft,
} from './eventUtils'

const eventList: SecurityEventResponse[] = [
  {
    id: 'event-1',
    tenant_id: 'tenant-1',
    event_type: 'failed_login',
    severity: 'high',
    source: 'identity-provider',
    description: 'Repeated sign-in failure',
    payload: {},
    metadata: {},
    timestamp: '2026-11-26T10:00:00Z',
    origin: 'manual',
    created_at: '2026-11-26T10:00:00Z',
  },
  {
    id: 'event-2',
    tenant_id: 'tenant-1',
    event_type: 'policy_violation',
    severity: 'critical',
    source: 'endpoint-agent',
    description: 'Unexpected privilege change',
    payload: {},
    metadata: {},
    timestamp: '2026-11-26T11:00:00Z',
    origin: 'simulated',
    created_at: '2026-11-26T11:00:00Z',
  },
]

const validDraft: EventDraft = {
  event_type: 'Failed Login',
  severity: 'high',
  source: ' Identity Provider ',
  description: '  Repeated sign-in failure  ',
  timestamp: '',
  metadata: '',
  origin: 'manual',
}

describe('filterSecurityEvents', () => {
  it('combines severity, source, event type, and text search filters', () => {
    expect(
      filterSecurityEvents(eventList, {
        search: 'SIGN-IN',
        severity: 'high',
        source: 'identity-provider',
        eventType: 'failed_login',
      }).map((event) => event.id),
    ).toEqual(['event-1'])
    expect(
      filterSecurityEvents(eventList, {
        search: 'privilege',
        severity: '',
        source: '',
        eventType: '',
      }).map((event) => event.id),
    ).toEqual(['event-2'])
  })
})

describe('validateEventDraft', () => {
  it('normalizes event type and trims required fields', () => {
    expect(validateEventDraft(validDraft)).toEqual({
      payload: {
        event_type: 'failed_login',
        severity: 'high',
        source: 'Identity Provider',
        description: 'Repeated sign-in failure',
        origin: 'manual',
      },
      errors: {},
    })
  })

  it('converts an optional local timestamp into timezone-aware UTC', () => {
    const result = validateEventDraft({
      ...validDraft,
      timestamp: '2026-11-25T10:30',
    })
    expect(result.errors.timestamp).toBeUndefined()
    expect(result.payload?.timestamp).toMatch(/Z$/)
  })

  it('rejects invalid fields, non-object metadata, and oversized metadata', () => {
    const invalid = validateEventDraft({
      ...validDraft,
      event_type: '3bad type',
      severity: 'urgent',
      source: ' ',
      description: ' ',
      timestamp: 'not-a-date',
      metadata: '[]',
      origin: 'scanner',
    })
    expect(invalid.payload).toBeNull()
    expect(Object.keys(invalid.errors)).toEqual(
      expect.arrayContaining([
        'event_type',
        'severity',
        'source',
        'description',
        'timestamp',
        'metadata',
        'origin',
      ]),
    )

    const oversized = validateEventDraft({
      ...validDraft,
      metadata: JSON.stringify({ value: 'x'.repeat(16_400) }),
    })
    expect(oversized.errors.metadata).toBe(
      'Metadata must not exceed 16,384 bytes.',
    )

    const oversizedEscapedMetadata = validateEventDraft({
      ...validDraft,
      metadata: JSON.stringify({ value: 'é'.repeat(2_729) }),
    })
    expect(oversizedEscapedMetadata.errors.metadata).toBe(
      'Metadata must not exceed 16,384 bytes.',
    )
  })
})
