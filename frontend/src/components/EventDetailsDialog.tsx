import { X } from 'lucide-react'
import type { SecurityEventResponse } from '../api/types'

interface EventDetailsDialogProps {
  event: SecurityEventResponse
  onClose: () => void
}

export function EventDetailsDialog({
  event,
  onClose,
}: EventDetailsDialogProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-3 sm:p-6">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="event-details-title"
        className="relative max-h-[92vh] w-full max-w-3xl overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-2xl shadow-black/50 sm:p-7"
      >
        <button
          type="button"
          onClick={onClose}
          aria-label="Close event details"
          className="absolute right-4 top-4 rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white"
        >
          <X aria-hidden="true" size={18} />
        </button>

        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
          Security event
        </p>
        <h2
          id="event-details-title"
          className="mt-2 break-all pr-10 text-xl font-semibold text-white"
        >
          {event.event_type}
        </h2>
        <p className="mt-2 text-sm leading-6 text-slate-300">
          {event.description}
        </p>

        <dl className="mt-6 grid gap-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4 sm:grid-cols-2">
          <DetailItem label="Event ID" value={event.id} />
          <DetailItem label="Tenant ID" value={event.tenant_id} />
          <DetailItem label="Severity" value={event.severity} />
          <DetailItem label="Source" value={event.source} />
          <DetailItem label="Origin" value={event.origin} />
          <DetailItem label="Event timestamp" value={event.timestamp} />
          <DetailItem label="Recorded at" value={event.created_at} />
        </dl>

        <section className="mt-6">
          <h3 className="text-sm font-semibold text-slate-200">Metadata</h3>
          <pre className="mt-2 max-h-72 overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-5 text-cyan-100">
            {JSON.stringify(event.metadata, null, 2)}
          </pre>
        </section>

        <details className="mt-4">
          <summary className="cursor-pointer text-xs font-medium text-slate-400 hover:text-slate-200">
            View complete API record
          </summary>
          <pre className="mt-2 max-h-72 overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-300">
            {JSON.stringify(event, null, 2)}
          </pre>
        </details>
      </section>
    </div>
  )
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
        {label}
      </dt>
      <dd className="mt-1 break-all text-xs text-slate-200">{value}</dd>
    </div>
  )
}
