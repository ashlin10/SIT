import { useState, useEffect, useRef, type FormEvent, type KeyboardEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/lib/utils'
import { Lock, User, ArrowLeft, ShieldCheck, KeyRound } from 'lucide-react'

type View = 'chooser' | 'local'

function ViperLogo({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Snake body — sinuous S-curve */}
      <path
        d="M32 6 C26 6, 18 10, 16 18 C14 26, 20 30, 28 30 C36 30, 42 34, 40 42 C38 50, 30 54, 24 52"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        fill="none"
        className="viper-body"
      />
      {/* Head — angular viper shape */}
      <path
        d="M32 6 C34 4, 38 3, 40 5 C42 7, 40 10, 38 11 C36 12, 34 10, 32 8"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="currentColor"
        fillOpacity="0.15"
        className="viper-head"
      />
      {/* Eye */}
      <circle
        cx="37"
        cy="7"
        r="1.2"
        fill="var(--color-accent-emerald)"
        className="viper-eye"
      />
      {/* Forked tongue */}
      <path
        d="M40 5 L44 3 M40 5 L44 7"
        stroke="var(--color-accent-emerald)"
        strokeWidth="1.2"
        strokeLinecap="round"
        className="viper-tongue"
      />
      {/* Tail taper */}
      <path
        d="M24 52 C20 50, 18 46, 20 44"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        fill="none"
        opacity="0.6"
      />
    </svg>
  )
}

export default function LoginPage() {
  const [searchParams] = useSearchParams()
  const nextUrl = searchParams.get('next') || '/dashboard'
  const ssoError = searchParams.get('error')

  const { login, isAuthenticated, isLoading, error, clearError } = useAuthStore()
  const displayError = error || ssoError

  const [view, setView] = useState<View>('chooser')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [mounted, setMounted] = useState(false)

  const usernameRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    requestAnimationFrame(() => setMounted(true))
  }, [])

  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      window.location.href = nextUrl
    }
  }, [isAuthenticated, isLoading, nextUrl])

  useEffect(() => {
    if (view === 'local') {
      setTimeout(() => usernameRef.current?.focus(), 300)
    }
  }, [view])

  useEffect(() => {
    if (displayError) {
      setView('local')
    }
  }, [displayError])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password.trim()) return
    setSubmitting(true)
    const success = await login(username.trim(), password)
    setSubmitting(false)
    if (success) {
      window.location.href = nextUrl
    }
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLFormElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      handleSubmit(e)
    }
  }

  const showLocal = () => {
    clearError()
    setView('local')
  }

  const showChooser = () => {
    clearError()
    setView('chooser')
  }

  return (
    <div className="relative min-h-screen flex items-center justify-center overflow-hidden bg-surface-950">
      {/* Animated background grid */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="login-grid absolute inset-0" />
        {/* Radial glow that pulses */}
        <div className="login-glow absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[900px] h-[900px]" />
        {/* Top edge accent line */}
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-vyper-500/40 to-transparent" />
        {/* Floating particles */}
        <div className="login-particle login-particle-1" />
        <div className="login-particle login-particle-2" />
        <div className="login-particle login-particle-3" />
      </div>

      {/* Corner status indicator */}
      <div className="pointer-events-none absolute top-6 right-6 flex items-center gap-2 text-surface-600 text-[10px] font-mono tracking-[0.2em] opacity-0 login-fade-in-delay-3">
        <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent-emerald animate-pulse" />
        SECURE
      </div>

      <div
        className={cn(
          'relative z-10 w-full max-w-[400px] mx-4 transition-all duration-700 ease-out',
          mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
        )}
      >
        {/* Logo + Branding */}
        <div className="mb-10 text-center">
          <div className="login-logo-container inline-flex items-center justify-center w-[72px] h-[72px] rounded-2xl mb-6 relative">
            {/* Glow ring */}
            <div className="absolute inset-0 rounded-2xl login-logo-ring" />
            <div className="relative z-10 bg-surface-900/80 backdrop-blur-sm rounded-2xl w-full h-full flex items-center justify-center border border-vyper-500/20">
              <ViperLogo className="w-10 h-10 text-vyper-400" />
            </div>
          </div>
          <h1
            className={cn(
              'text-[26px] font-bold tracking-[-0.02em] text-surface-0 font-[Outfit]',
              'transition-all duration-500 delay-100',
              mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2'
            )}
          >
            Vyper
          </h1>
          <p
            className={cn(
              'mt-1 text-[13px] text-surface-500 font-light tracking-[0.08em] uppercase',
              'transition-all duration-500 delay-200',
              mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2'
            )}
          >
            Network Security Toolkit
          </p>
        </div>

        {/* Card */}
        <div
          className={cn(
            'relative rounded-2xl border border-surface-800/60',
            'bg-surface-900/50 backdrop-blur-2xl',
            'shadow-[0_25px_80px_-15px_rgba(0,0,0,0.6)]',
            'overflow-hidden',
            'transition-all duration-600 delay-150',
            mounted ? 'opacity-100 translate-y-0 scale-100' : 'opacity-0 translate-y-3 scale-[0.98]'
          )}
        >
          {/* Top accent border with shimmer */}
          <div className="absolute top-0 left-0 right-0 h-px overflow-hidden">
            <div className="login-shimmer h-full" />
          </div>

          <div className="p-7">
            {/* Error message */}
            {displayError && (
              <div
                className="mb-5 flex items-start gap-3 rounded-xl bg-accent-rose/8 border border-accent-rose/15 px-4 py-3 text-sm text-accent-rose login-error-enter"
                role="alert"
                aria-live="polite"
              >
                <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{displayError}</span>
              </div>
            )}

            {/* Chooser View */}
            {view === 'chooser' && (
              <div className="space-y-3 login-view-enter">
                <p className="text-center text-surface-400 text-sm mb-6">
                  Choose how you&rsquo;d like to sign in
                </p>

                <button
                  type="button"
                  onClick={showLocal}
                  className={cn(
                    'group w-full flex items-center gap-3.5 px-4 py-3.5 rounded-xl',
                    'bg-surface-800/40 border border-surface-700/40',
                    'hover:bg-surface-800/70 hover:border-surface-600/50 hover:shadow-lg hover:shadow-vyper-500/5',
                    'text-surface-200 text-sm font-medium',
                    'transition-all duration-250 ease-out',
                    'focus-visible:ring-2 focus-visible:ring-vyper-500 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-900'
                  )}
                  aria-label="Sign in with local account"
                >
                  <span className="flex items-center justify-center w-9 h-9 rounded-lg bg-vyper-500/10 text-vyper-400 group-hover:bg-vyper-500/20 group-hover:scale-110 transition-all duration-250">
                    <KeyRound className="w-4 h-4" />
                  </span>
                  Sign in with Local Account
                </button>

                <div className="flex items-center gap-3 py-1">
                  <div className="flex-1 h-px bg-gradient-to-r from-transparent to-surface-700/50" />
                  <span className="text-[10px] text-surface-600 uppercase tracking-[0.2em] font-mono">
                    or
                  </span>
                  <div className="flex-1 h-px bg-gradient-to-l from-transparent to-surface-700/50" />
                </div>

                <a
                  href={`/sso/login?next=${encodeURIComponent(nextUrl)}`}
                  className={cn(
                    'group w-full flex items-center gap-3.5 px-4 py-3.5 rounded-xl no-underline',
                    'bg-accent-emerald/6 border border-accent-emerald/15',
                    'hover:bg-accent-emerald/12 hover:border-accent-emerald/25 hover:shadow-lg hover:shadow-accent-emerald/5',
                    'text-accent-emerald text-sm font-medium',
                    'transition-all duration-250 ease-out',
                    'focus-visible:ring-2 focus-visible:ring-accent-emerald focus-visible:ring-offset-2 focus-visible:ring-offset-surface-900'
                  )}
                  aria-label="Sign in with SSO Duo"
                >
                  <span className="flex items-center justify-center w-9 h-9 rounded-lg bg-accent-emerald/10 group-hover:bg-accent-emerald/20 group-hover:scale-110 transition-all duration-250">
                    <ShieldCheck className="w-4 h-4" />
                  </span>
                  Sign in with SSO (Duo)
                </a>
              </div>
            )}

            {/* Local Login Form */}
            {view === 'local' && (
              <div className="login-view-enter">
                <form
                  onSubmit={handleSubmit}
                  onKeyDown={handleKeyDown}
                  className="space-y-5"
                  noValidate
                >
                  <div className="login-field-stagger-1">
                    <label
                      htmlFor="username"
                      className="block text-[11px] font-medium text-surface-500 mb-1.5 tracking-[0.1em] uppercase font-mono"
                    >
                      Username
                    </label>
                    <div className="relative group">
                      <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-surface-600 group-focus-within:text-vyper-400 transition-colors duration-200">
                        <User className="w-4 h-4" />
                      </span>
                      <input
                        ref={usernameRef}
                        id="username"
                        name="username"
                        type="text"
                        required
                        autoComplete="username"
                        spellCheck={false}
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Enter username"
                        className={cn(
                          'w-full pl-10 pr-3.5 py-2.5 rounded-xl text-sm',
                          'bg-surface-800/50 border border-surface-700/40',
                          'text-surface-100 placeholder:text-surface-600',
                          'hover:border-surface-600/50',
                          'focus:outline-none focus:border-vyper-500/40 focus:ring-2 focus:ring-vyper-500/10 focus:bg-surface-800/70',
                          'transition-all duration-250'
                        )}
                      />
                    </div>
                  </div>

                  <div className="login-field-stagger-2">
                    <label
                      htmlFor="password"
                      className="block text-[11px] font-medium text-surface-500 mb-1.5 tracking-[0.1em] uppercase font-mono"
                    >
                      Password
                    </label>
                    <div className="relative group">
                      <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-surface-600 group-focus-within:text-vyper-400 transition-colors duration-200">
                        <Lock className="w-4 h-4" />
                      </span>
                      <input
                        id="password"
                        name="password"
                        type="password"
                        required
                        autoComplete="current-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter password"
                        className={cn(
                          'w-full pl-10 pr-3.5 py-2.5 rounded-xl text-sm',
                          'bg-surface-800/50 border border-surface-700/40',
                          'text-surface-100 placeholder:text-surface-600',
                          'hover:border-surface-600/50',
                          'focus:outline-none focus:border-vyper-500/40 focus:ring-2 focus:ring-vyper-500/10 focus:bg-surface-800/70',
                          'transition-all duration-250'
                        )}
                      />
                    </div>
                  </div>

                  <div className="login-field-stagger-3">
                    <button
                      type="submit"
                      disabled={submitting || !username.trim() || !password.trim()}
                      className={cn(
                        'w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold',
                        'bg-vyper-600 hover:bg-vyper-500 active:bg-vyper-700',
                        'text-white',
                        'shadow-[0_4px_20px_-4px_rgba(11,132,230,0.4)]',
                        'hover:shadow-[0_8px_30px_-4px_rgba(11,132,230,0.5)]',
                        'disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-vyper-600 disabled:shadow-none',
                        'transition-all duration-250 ease-out',
                        'focus-visible:ring-2 focus-visible:ring-vyper-400 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-900'
                      )}
                      aria-label="Sign in"
                    >
                      {submitting ? (
                        <>
                          <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                          Signing in&hellip;
                        </>
                      ) : (
                        'Sign In'
                      )}
                    </button>
                  </div>
                </form>

                <button
                  type="button"
                  onClick={showChooser}
                  className={cn(
                    'w-full mt-4 flex items-center justify-center gap-1.5 py-2 text-sm',
                    'text-surface-600 hover:text-surface-300',
                    'transition-colors duration-200',
                    'focus-visible:ring-2 focus-visible:ring-vyper-500 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-900',
                    'rounded-lg'
                  )}
                  aria-label="Back to sign-in options"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  Other sign-in options
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <p
          className={cn(
            'mt-8 text-center text-[10px] text-surface-700 font-mono tracking-[0.2em] uppercase',
            'transition-all duration-700 delay-500',
            mounted ? 'opacity-100' : 'opacity-0'
          )}
        >
          Vyper 2.0 &middot; Secure Interface
        </p>
      </div>

      {/* Animation styles */}
      <style>{`
        /* ─── Background grid ─── */
        .login-grid {
          background-image:
            linear-gradient(var(--color-vyper-500) 1px, transparent 1px),
            linear-gradient(90deg, var(--color-vyper-500) 1px, transparent 1px);
          background-size: 52px 52px;
          opacity: 0;
          animation: gridFadeIn 2s ease-out 0.3s forwards;
        }
        @keyframes gridFadeIn {
          to { opacity: 0.025; }
        }

        /* ─── Radial glow with pulse ─── */
        .login-glow {
          background: radial-gradient(circle, rgba(11,132,230,0.1) 0%, rgba(11,132,230,0.02) 45%, transparent 70%);
          animation: glowPulse 4s ease-in-out infinite;
        }
        @keyframes glowPulse {
          0%, 100% { opacity: 0.8; transform: translate(-50%, -50%) scale(1); }
          50% { opacity: 1; transform: translate(-50%, -50%) scale(1.05); }
        }

        /* ─── Floating particles ─── */
        .login-particle {
          position: absolute;
          width: 2px;
          height: 2px;
          border-radius: 50%;
          background: var(--color-vyper-400);
          opacity: 0;
          animation: particleFloat 8s ease-in-out infinite;
        }
        .login-particle-1 {
          top: 20%; left: 15%;
          animation-delay: 0s;
        }
        .login-particle-2 {
          top: 60%; right: 20%;
          animation-delay: 2.5s;
        }
        .login-particle-3 {
          bottom: 25%; left: 40%;
          animation-delay: 5s;
        }
        @keyframes particleFloat {
          0%, 100% { opacity: 0; transform: translateY(0) scale(1); }
          20% { opacity: 0.4; }
          50% { opacity: 0.6; transform: translateY(-30px) scale(1.5); }
          80% { opacity: 0.3; }
        }

        /* ─── Logo ring glow ─── */
        .login-logo-ring {
          background: conic-gradient(
            from 0deg,
            transparent 0%,
            rgba(11,132,230,0.15) 25%,
            transparent 50%,
            rgba(16,185,129,0.1) 75%,
            transparent 100%
          );
          animation: logoRingSpin 6s linear infinite;
          border-radius: inherit;
        }
        @keyframes logoRingSpin {
          to { transform: rotate(360deg); }
        }

        /* ─── Logo SVG animations ─── */
        .viper-body {
          stroke-dasharray: 200;
          stroke-dashoffset: 200;
          animation: snakeDraw 1.5s cubic-bezier(0.65,0,0.35,1) 0.5s forwards;
        }
        @keyframes snakeDraw {
          to { stroke-dashoffset: 0; }
        }

        .viper-head {
          opacity: 0;
          animation: headAppear 0.4s ease-out 1.6s forwards;
        }
        @keyframes headAppear {
          from { opacity: 0; transform: scale(0.8); }
          to { opacity: 1; transform: scale(1); }
        }

        .viper-eye {
          opacity: 0;
          animation: eyeGlow 0.3s ease-out 1.9s forwards, eyePulse 3s ease-in-out 2.2s infinite;
        }
        @keyframes eyeGlow {
          from { opacity: 0; r: 0; }
          to { opacity: 1; r: 1.2; }
        }
        @keyframes eyePulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }

        .viper-tongue {
          opacity: 0;
          animation: tongueFlick 0.15s ease-out 2s forwards, tongueRepeat 3s ease-in-out 3s infinite;
          transform-origin: left center;
        }
        @keyframes tongueFlick {
          from { opacity: 0; transform: scaleX(0); }
          to { opacity: 1; transform: scaleX(1); }
        }
        @keyframes tongueRepeat {
          0%, 85%, 100% { opacity: 1; transform: scaleX(1); }
          90% { opacity: 0.5; transform: scaleX(0.3); }
          95% { opacity: 1; transform: scaleX(1.1); }
        }

        /* ─── Shimmer accent line ─── */
        .login-shimmer {
          background: linear-gradient(
            90deg,
            transparent 0%,
            transparent 30%,
            rgba(11,132,230,0.4) 50%,
            transparent 70%,
            transparent 100%
          );
          animation: shimmerSlide 3s ease-in-out infinite;
        }
        @keyframes shimmerSlide {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }

        /* ─── View enter animations ─── */
        .login-view-enter {
          animation: viewSlideIn 0.35s cubic-bezier(0.16, 1, 0.3, 1) both;
        }
        @keyframes viewSlideIn {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }

        /* ─── Staggered field entrance ─── */
        .login-field-stagger-1 { animation: fieldEnter 0.4s cubic-bezier(0.16, 1, 0.3, 1) 0.05s both; }
        .login-field-stagger-2 { animation: fieldEnter 0.4s cubic-bezier(0.16, 1, 0.3, 1) 0.12s both; }
        .login-field-stagger-3 { animation: fieldEnter 0.4s cubic-bezier(0.16, 1, 0.3, 1) 0.19s both; }
        @keyframes fieldEnter {
          from { opacity: 0; transform: translateY(6px); }
          to { opacity: 1; transform: translateY(0); }
        }

        /* ─── Error shake ─── */
        .login-error-enter {
          animation: errorShake 0.45s cubic-bezier(0.36, 0.07, 0.19, 0.97) both;
        }
        @keyframes errorShake {
          0% { opacity: 0; transform: translateX(-10px); }
          30% { transform: translateX(6px); }
          60% { transform: translateX(-3px); }
          80% { transform: translateX(1px); }
          100% { opacity: 1; transform: translateX(0); }
        }

        /* ─── Delayed fade-in helpers ─── */
        .login-fade-in-delay-3 {
          animation: simpleFadeIn 0.6s ease-out 1.5s both;
        }
        @keyframes simpleFadeIn {
          from { opacity: 0; }
          to { opacity: 0.4; }
        }
      `}</style>
    </div>
  )
}
