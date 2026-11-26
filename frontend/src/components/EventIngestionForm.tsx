import { useState, type FormEvent } from 'react'
import { LoaderCircle, X } from 'lucide-react'
import { ApiError } from '../api/client'
import { ingestSecurityEvent } from '../api/securityEvents'
import type {
  SecurityEventOrigin,
  SecurityEventSeverity,
} from '../api/types'
import {
  validateEventDraft,
  type EventDraft,
  type EventDraftErrors,
  type EventDraftField,
} from '../events/eventUtils'

interface EventIngestionFormProps {
  onIngested: () => Promise<void>
  onCancel: () => void
}

const initialDraft: EventDraft = {
  event_type: '',
  severity: 'medium',
  source: '',
  description: '',
  timestamp: '',
  metadata: '',
  origin: 'manual',
}

const severityOptions: SecurityEventSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]

const originOptions: SecurityEventOrigin[] = [
  'manual',
  'simulated',
  'integration',
]

function FieldError({
  id,
  message,
}: {
  id?: string
  message?: string
}) {
  if (!message) return null
  return (
    <p id={id} role="alert" className="mt-1.5 text-xs text-rose-300">
      {message}
    </p>
  )
}

export function EventIngestionForm({
  onIngested,
  onCancel,
}: EventIngestionFormProps) {
  const [draft, setDraft] = useState<EventDraft>(initialDraft)
  const [fieldErrors, setFieldErrors] = useState<EventDraftErrors>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  function updateField(field: EventDraftField, value: string) {
    setDraft((current) => ({ ...current, [field]: value }))
    setFieldErrors((current) => ({ ...current, [field]: undefined }))
    setFormError(null)
    setSuccess(null)
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const validation = validateEventDraft(draft)
    setFieldErrors(validation.errors)
    setFormError(null)
    setSuccess(null)
    if (!validation.payload) return

    setIsSubmitting(true)
    try {
      const created = await ingestSecurityEvent(validation.payload)
      setDraft(initialDraft)
      setFieldErrors({})
      setSuccess(`Event ${created.id} was ingested successfully.`)
      await onIngested()
    } catch (error) {
      setFormError(
        error instanceof ApiError
          ? error.message
          : 'Unable to ingest this event. Check the API connection and try again.',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <section
      aria-labelledby="event-ingestion-title"
      className="rounded-2xl border border-cyan-400/20 bg-slate-900/80 p-5 shadow-lg shadow-black/10 sm:p-6"
    >
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
            Authorized event submission
          </p>
          <h2
            id="event-ingestion-title"
            className="mt-2 text-lg font-semibold text-white"
          >
            Ingest security event
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Tenant ownership is assigned by the authenticated API identity.
          </p>
        </div>
        <button
          type="button"
          onClick={onCancel}
          aria-label="Close event ingestion form"
          className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
        >
          <X aria-hidden="true" size={18} />
        </button>
      </div>

      <form onSubmit={handleSubmit} noValidate className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label
              htmlFor="event-type"
              className="mb-1.5 block text-sm font-medium text-slate-200"
            >
              Event type <span className="text-rose-300">*</span>
            </label>
            <input
              id="event-type"
              value={draft.event_type}
              onChange={(event) => updateField('event_type', event.target.value)}
              maxLength={100}
              placeholder="failed login"
              aria-invalid={Boolean(fieldErrors.event_type)}
              aria-describedby={
                fieldErrors.event_type ? 'event-type-error' : undefined
              }
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-400/60"
            />
            <FieldError
              message={fieldErrors.event_type}
              id="event-type-error"
            />
          </div>

          <div>
            <label
              htmlFor="event-severity"
              className="mb-1.5 block text-sm font-medium text-slate-200"
            >
              Severity <span className="text-rose-300">*</span>
            </label>
            <select
              id="event-severity"
              value={draft.severity}
              onChange={(event) => updateField('severity', event.target.value)}
              aria-invalid={Boolean(fieldErrors.severity)}
              aria-describedby={
                fieldErrors.severity ? 'event-severity-error' : undefined
              }
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm capitalize text-slate-100 outline-none transition focus:border-cyan-400/60"
            >
              {severityOptions.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
            <FieldError
              id="event-severity-error"
              message={fieldErrors.severity}
            />
          </div>

          <div>
            <label
              htmlFor="event-source"
              className="mb-1.5 block text-sm font-medium text-slate-200"
            >
              Source <span className="text-rose-300">*</span>
            </label>
            <input
              id="event-source"
              value={draft.source}
              onChange={(event) => updateField('source', event.target.value)}
              maxLength={255}
              placeholder="identity-provider"
              aria-invalid={Boolean(fieldErrors.source)}
              aria-describedby={fieldErrors.source ? 'event-source-error' : undefined}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-400/60"
            />
            <FieldError id="event-source-error" message={fieldErrors.source} />
          </div>

          <div>
            <label
              htmlFor="event-origin"
              className="mb-1.5 block text-sm font-medium text-slate-200"
            >
              Origin <span className="text-rose-300">*</span>
            </label>
            <select
              id="event-origin"
              value={draft.origin}
              onChange={(event) => updateField('origin', event.target.value)}
              aria-invalid={Boolean(fieldErrors.origin)}
              aria-describedby={fieldErrors.origin ? 'event-origin-error' : undefined}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm capitalize text-slate-100 outline-none transition focus:border-cyan-400/60"
            >
              {originOptions.map((origin) => (
                <option key={origin} value={origin}>
                  {origin}
                </option>
              ))}
            </select>
            <FieldError id="event-origin-error" message={fieldErrors.origin} />
          </div>

          <div>
            <label
              htmlFor="event-timestamp"
              className="mb-1.5 block text-sm font-medium text-slate-200"
            >
              Event timestamp <span className="text-slate-500">(optional)</span>
            </label>
            <input
              id="event-timestamp"
              type="datetime-local"
              value={draft.timestamp}
              onChange={(event) => updateField('timestamp', event.target.value)}
              aria-invalid={Boolean(fieldErrors.timestamp)}
              aria-describedby={
                fieldErrors.timestamp ? 'event-timestamp-error' : undefined
              }
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none transition focus:border-cyan-400/60"
            />
            <p className="mt-1.5 text-xs text-slate-500">
              Local time is converted to a timezone-aware UTC timestamp.
            </p>
            <FieldError
              id="event-timestamp-error"
              message={fieldErrors.timestamp}
            />
          </div>

          <div className="sm:col-span-2">
            <label
              htmlFor="event-description"
              className="mb-1.5 block text-sm font-medium text-slate-200"
            >
              Description <span className="text-rose-300">*</span>
            </label>
            <textarea
              id="event-description"
              value={draft.description}
              onChange={(event) =>
                updateField('description', event.target.value)
              }
              maxLength={5_000}
              rows={3}
              placeholder="Describe the security event"
              aria-invalid={Boolean(fieldErrors.description)}
              aria-describedby={
                fieldErrors.description ? 'event-description-error' : undefined
              }
              className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-400/60"
            />
            <div className="mt-1.5 flex justify-between gap-3 text-xs text-slate-500">
              <FieldError
                id="event-description-error"
                message={fieldErrors.description}
              />
              <span className="shrink-0">{draft.description.length}/5000</span>
            </div>
          </div>

          <div className="sm:col-span-2">
            <label
              htmlFor="event-metadata"
              className="mb-1.5 block text-sm font-medium text-slate-200"
            >
              Metadata <span className="text-slate-500">(optional JSON object)</span>
            </label>
            <textarea
              id="event-metadata"
              value={draft.metadata}
              onChange={(event) => updateField('metadata', event.target.value)}
              rows={4}
              spellCheck={false}
              placeholder={'{\n  "attempt_count": 5\n}'}
              aria-invalid={Boolean(fieldErrors.metadata)}
              aria-describedby={
                fieldErrors.metadata ? 'event-metadata-error' : undefined
              }
              className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 font-mono text-xs leading-5 text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-400/60"
            />
            <p className="mt-1.5 text-xs text-slate-500">
              Must be valid JSON and no more than 16,384 encoded bytes.
            </p>
            <FieldError
              id="event-metadata-error"
              message={fieldErrors.metadata}
            />
          </div>
        </div>

        {formError ? (
          <div
            role="alert"
            className="rounded-lg border border-rose-400/20 bg-rose-400/5 px-4 py-3 text-sm text-rose-200"
          >
            {formError}
          </div>
        ) : null}
        {success ? (
          <div
            role="status"
            className="rounded-lg border border-emerald-400/20 bg-emerald-400/5 px-4 py-3 text-sm text-emerald-200"
          >
            {success}
          </div>
        ) : null}

        <div className="flex flex-col-reverse gap-3 border-t border-slate-800 pt-5 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg border border-slate-700 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-slate-800 hover:text-white"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSubmitting}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-wait disabled:opacity-60"
          >
            {isSubmitting ? (
              <>
                <LoaderCircle
                  aria-hidden="true"
                  size={16}
                  className="animate-spin"
                />
                Ingesting…
              </>
            ) : (
              'Ingest event'
            )}
          </button>
        </div>
      </form>
    </section>
  )
}
