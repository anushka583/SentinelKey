import type { LucideIcon } from 'lucide-react'

interface RoutePlaceholderProps {
  title: string
  description: string
  endpoint: string
  icon: LucideIcon
}

export function RoutePlaceholder({
  title,
  description,
  endpoint,
  icon: Icon,
}: RoutePlaceholderProps) {
  return (
    <section className="mx-auto max-w-5xl">
      <div className="mb-8">
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">
          SentinelKey / Security operations
        </p>
        <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
          {title}
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
          {description}
        </p>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-xl shadow-black/10 sm:p-9">
        <div className="flex size-12 items-center justify-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
          <Icon aria-hidden="true" size={22} />
        </div>
        <h2 className="mt-6 text-lg font-semibold text-slate-100">
          Module view not implemented
        </h2>
        <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">
          This module is intentionally a placeholder in the current frontend
          scope. No security data is mocked.
        </p>
        <div className="mt-6 inline-flex max-w-full items-center gap-2 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs text-cyan-200">
          <span className="text-slate-500">API</span>
          <span className="break-all">{endpoint}</span>
        </div>
      </div>
    </section>
  )
}
