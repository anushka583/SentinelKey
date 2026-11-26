import { useState, type FormEvent } from 'react'
import { ArrowRight, KeyRound, ShieldCheck } from 'lucide-react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'

export function LoginPage() {
  const [token, setToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const { isAuthenticated, signIn } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: { pathname?: string } } | null)?.from
    ?.pathname

  if (isAuthenticated) return <Navigate to="/" replace />

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setIsSubmitting(true)
    try {
      await signIn(token)
      setToken('')
      navigate(from ?? '/', { replace: true })
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause.message
          : 'Unable to validate this token. Try again.',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-10 text-slate-200">
      <div className="grid w-full max-w-5xl overflow-hidden rounded-3xl border border-slate-800 bg-slate-900 shadow-2xl shadow-black/30 lg:grid-cols-[1.05fr_0.95fr]">
        <section className="relative hidden flex-col justify-between overflow-hidden border-r border-slate-800 bg-slate-900/70 p-10 lg:flex">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex size-11 items-center justify-center rounded-xl border border-cyan-300/20 bg-cyan-400/10 text-cyan-300">
                <ShieldCheck aria-hidden="true" size={23} />
              </div>
              <span className="text-lg font-semibold tracking-wide text-white">
                SentinelKey
              </span>
            </div>
            <div className="mt-24 max-w-md">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">
                Security operations platform
              </p>
              <h1 className="mt-4 text-4xl font-semibold leading-tight tracking-tight text-white">
                Clarity for your security posture.
              </h1>
              <p className="mt-5 text-sm leading-7 text-slate-400">
                Review tenant-scoped events, alerts, and vulnerability
                findings from one focused workspace.
              </p>
            </div>
          </div>
          <p className="text-xs text-slate-600">
            Development interface · API authorization remains authoritative
          </p>
        </section>

        <section className="p-6 sm:p-10">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <div className="flex size-10 items-center justify-center rounded-xl border border-cyan-300/20 bg-cyan-400/10 text-cyan-300">
              <ShieldCheck aria-hidden="true" size={21} />
            </div>
            <span className="font-semibold tracking-wide text-white">
              SentinelKey
            </span>
          </div>

          <div className="mb-8">
            <div className="mb-4 flex size-10 items-center justify-center rounded-xl border border-slate-700 bg-slate-800 text-cyan-300">
              <KeyRound aria-hidden="true" size={19} />
            </div>
            <h2 className="text-2xl font-semibold tracking-tight text-white">
              Connect to your workspace
            </h2>
            <p className="mt-2 text-sm leading-6 text-slate-400">
              Paste a short-lived bearer token issued by your local SentinelKey
              development setup.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <label
              htmlFor="access-token"
              className="block text-sm font-medium text-slate-200"
            >
              JWT access token
            </label>
            <textarea
              id="access-token"
              name="access-token"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              rows={4}
              value={token}
              onChange={(event) => setToken(event.target.value)}
              placeholder="Paste token"
              className="w-full resize-y rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 font-mono text-xs leading-5 text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-cyan-400/70 focus:ring-2 focus:ring-cyan-400/10"
              required
            />

            {error && (
              <div
                role="alert"
                className="rounded-lg border border-rose-400/20 bg-rose-400/5 px-4 py-3 text-sm text-rose-200"
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting || !token.trim()}
              className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isSubmitting ? 'Validating token…' : 'Connect securely'}
              {!isSubmitting && <ArrowRight aria-hidden="true" size={16} />}
            </button>
          </form>

          <div className="mt-7 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-400">
              Local development
            </p>
            <p className="mt-2 text-xs leading-5 text-slate-500">
              Configure development mode and a private{' '}
              <code className="text-cyan-200">SENTINELKEY_JWT_SECRET</code> of
              at least 32 characters, then run this from the backend directory:
            </p>
            <code className="mt-2 block break-all rounded-lg bg-slate-900 px-3 py-2 font-mono text-[11px] leading-5 text-cyan-200">
              python -m app.security.dev_token --tenant-name "SentinelKey Local"
              --tenant-slug sentinelkey-local --email admin@example.com --role
              analyst
            </code>
            <p className="mt-2 text-xs leading-5 text-slate-500">
              The CLI prints a short-lived token. This UI does not issue
              credentials.
            </p>
          </div>
          <p className="mt-5 text-center text-xs leading-5 text-slate-600">
            The token stays in memory only and is cleared on sign out or page
            reload. Never share or log it.
          </p>
        </section>
      </div>
    </main>
  )
}
