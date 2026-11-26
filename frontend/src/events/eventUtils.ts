import type {
  SecurityEventCreateRequest,
  SecurityEventOrigin,
  SecurityEventResponse,
  SecurityEventSeverity,
} from '../api/types'

const severities: readonly SecurityEventSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]

const origins: readonly SecurityEventOrigin[] = [
  'manual',
  'simulated',
  'integration',
]

export interface EventFilters {
  search: string
  severity: SecurityEventSeverity | ''
  source: string
  eventType: string
}

export function filterSecurityEvents(
  events: SecurityEventResponse[],
  filters: EventFilters,
): SecurityEventResponse[] {
  const search = filters.search.trim().toLocaleLowerCase()

  return events.filter((event) => {
    if (filters.severity && event.severity !== filters.severity) return false
    if (filters.source && event.source !== filters.source) return false
    if (filters.eventType && event.event_type !== filters.eventType) return false
    if (!search) return true

    return [event.event_type, event.source, event.description].some((value) =>
      value.toLocaleLowerCase().includes(search),
    )
  })
}

export interface EventDraft {
  event_type: string
  severity: string
  source: string
  description: string
  timestamp: string
  metadata: string
  origin: string
}

export type EventDraftField = keyof EventDraft
export type EventDraftErrors = Partial<Record<EventDraftField, string>>

export interface EventDraftValidation {
  payload: SecurityEventCreateRequest | null
  errors: EventDraftErrors
}

function isNonFinite(value: unknown): boolean {
  if (typeof value === 'number') return !Number.isFinite(value)
  if (Array.isArray(value)) return value.some(isNonFinite)
  if (typeof value === 'object' && value !== null) {
    return Object.values(value).some(isNonFinite)
  }
  return false
}

function encodedPythonJsonSize(value: Record<string, unknown>): number {
  const json = JSON.stringify(value)
  let pythonEscapedJson = ''
  for (let index = 0; index < json.length; index += 1) {
    const character = json[index] ?? ''
    const codeUnit = character.charCodeAt(0)
    pythonEscapedJson +=
      codeUnit > 0x7f
        ? `\\u${codeUnit.toString(16).padStart(4, '0')}`
        : character
  }
  return new TextEncoder().encode(pythonEscapedJson).length
}

export function validateEventDraft(draft: EventDraft): EventDraftValidation {
  const errors: EventDraftErrors = {}
  const eventType = draft.event_type.trim().toLowerCase().replace(/[\s-]+/g, '_')
  const source = draft.source.trim()
  const description = draft.description.trim()

  if (!draft.event_type.trim() || draft.event_type.length > 100) {
    errors.event_type = 'Event type is required and must be at most 100 characters.'
  } else if (!/^[a-z][a-z0-9_]{0,99}$/.test(eventType)) {
    errors.event_type =
      'Use a letter first, followed by letters, numbers, spaces, hyphens, or underscores.'
  }

  if (!severities.includes(draft.severity as SecurityEventSeverity)) {
    errors.severity = 'Select a supported severity.'
  }

  if (!source || draft.source.length > 255) {
    errors.source = 'Source is required and must be at most 255 characters.'
  }

  if (!description || draft.description.length > 5_000) {
    errors.description =
      'Description is required and must be at most 5,000 characters.'
  }

  if (!origins.includes(draft.origin as SecurityEventOrigin)) {
    errors.origin = 'Select a supported event origin.'
  }

  let timestamp: string | undefined
  if (draft.timestamp.trim()) {
    const date = new Date(draft.timestamp)
    if (Number.isNaN(date.getTime())) {
      errors.timestamp = 'Enter a valid date and time.'
    } else if (date.getTime() > Date.now() + 5 * 60 * 1000) {
      errors.timestamp = 'Timestamp cannot be more than five minutes in the future.'
    } else {
      timestamp = date.toISOString()
    }
  }

  let metadata: Record<string, unknown> | undefined
  if (draft.metadata.trim()) {
    try {
      const parsed: unknown = JSON.parse(draft.metadata)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        errors.metadata = 'Metadata must be a JSON object.'
      } else if (isNonFinite(parsed)) {
        errors.metadata = 'Metadata must contain finite JSON numbers.'
      } else {
        metadata = parsed as Record<string, unknown>
        if (encodedPythonJsonSize(metadata) > 16_384) {
          errors.metadata = 'Metadata must not exceed 16,384 bytes.'
        }
      }
    } catch {
      errors.metadata = 'Enter valid JSON metadata.'
    }
  }

  if (Object.keys(errors).length > 0) return { payload: null, errors }

  return {
    payload: {
      event_type: eventType,
      severity: draft.severity as SecurityEventSeverity,
      source,
      description,
      ...(timestamp ? { timestamp } : {}),
      ...(metadata ? { metadata } : {}),
      origin: draft.origin as SecurityEventOrigin,
    },
    errors,
  }
}
