import { useState, useEffect, useRef, type FormEvent, type KeyboardEvent } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/lib/utils'
import { VyperLogo } from '@/components/VyperLogo'
import { Lock, User, ArrowLeft, ShieldCheck, KeyRound } from 'lucide-react'

type View = 'chooser' | 'local'


/* ─── Immersive Space Starfield ───
   Multi-layer starfield with color-temperature stars, Milky Way band,
   nebula dust clouds, shooting stars, fireballs, meteors, and satellites.
   Each element type has unique physics, timing, and visual style. */
function StarfieldCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animId = 0
    let w = 0
    let h = 0

    // ── Types ──
    interface Star {
      x: number; y: number; r: number; brightness: number
      twinkleSpeed: number; phase: number
      color: string; layer: number
    }
    interface Spark { x: number; y: number; vx: number; vy: number; life: number; maxLife: number; color: string }
    // Covers shooting stars, fireballs, meteors
    interface Streak {
      kind: 'shoot' | 'fireball' | 'meteor'
      x: number; y: number; vx: number; vy: number
      life: number; maxLife: number; tailLen: number
      width: number; brightness: number
      hue: number; sparks: Spark[]
    }
    interface Satellite {
      x: number; y: number; vx: number; vy: number
      brightness: number; glintPhase: number; glintSpeed: number
      life: number; maxLife: number
    }
    interface DustCloud {
      x: number; y: number; rx: number; ry: number
      rotation: number; hue: number; sat: number
      alpha: number; phase: number
    }

    let stars: Star[] = []
    let streaks: Streak[] = []
    let satellites: Satellite[] = []
    let dustClouds: DustCloud[] = []

    const starColors = [
      '#aac4ff', '#cad8ff', '#f0f1ff', '#fff4ea',
      '#ffd2a1', '#ffcc6f', '#c4d4ff',
    ]

    const resize = () => {
      const dpr = window.devicePixelRatio || 1
      w = canvas.clientWidth
      h = canvas.clientHeight
      canvas.width = w * dpr
      canvas.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      init()
    }

    const init = () => {
      const area = w * h
      const farCount = Math.min(Math.floor(area / 500), 800)
      const midCount = Math.min(Math.floor(area / 1500), 300)
      const nearCount = Math.min(Math.floor(area / 4000), 80)

      const makeStar = (layer: number): Star => {
        const rRange = layer === 0 ? [0.2, 0.6] : layer === 1 ? [0.5, 1.1] : [1.0, 2.0]
        const bRange = layer === 0 ? [0.15, 0.5] : layer === 1 ? [0.4, 0.8] : [0.7, 1.0]
        return {
          x: Math.random() * w, y: Math.random() * h,
          r: rRange[0] + Math.random() * (rRange[1] - rRange[0]),
          brightness: bRange[0] + Math.random() * (bRange[1] - bRange[0]),
          twinkleSpeed: 0.3 + Math.random() * 1.5,
          phase: Math.random() * Math.PI * 2,
          color: starColors[Math.floor(Math.random() * starColors.length)],
          layer,
        }
      }

      stars = [
        ...Array.from({ length: farCount }, () => makeStar(0)),
        ...Array.from({ length: midCount }, () => makeStar(1)),
        ...Array.from({ length: nearCount }, () => makeStar(2)),
      ]

      dustClouds = [
        { x: w * 0.15, y: h * 0.1, rx: w * 0.35, ry: h * 0.08, rotation: -0.45, hue: 220, sat: 30, alpha: 0.025, phase: 0 },
        { x: w * 0.4, y: h * 0.35, rx: w * 0.3, ry: h * 0.1, rotation: -0.45, hue: 230, sat: 25, alpha: 0.03, phase: 1 },
        { x: w * 0.65, y: h * 0.55, rx: w * 0.25, ry: h * 0.09, rotation: -0.45, hue: 210, sat: 35, alpha: 0.025, phase: 2 },
        { x: w * 0.85, y: h * 0.8, rx: w * 0.2, ry: h * 0.07, rotation: -0.45, hue: 200, sat: 30, alpha: 0.02, phase: 3 },
        { x: w * 0.25, y: h * 0.65, rx: w * 0.15, ry: h * 0.12, rotation: 0.3, hue: 270, sat: 40, alpha: 0.02, phase: 4 },
        { x: w * 0.75, y: h * 0.25, rx: w * 0.12, ry: h * 0.15, rotation: -0.2, hue: 160, sat: 35, alpha: 0.018, phase: 5 },
      ]

      streaks = []
      satellites = []
    }

    let time = 0
    let nextShoot = 1.5 + Math.random() * 2
    let nextFireball = 8 + Math.random() * 10
    let nextMeteor = 4 + Math.random() * 5
    let nextSatellite = 3 + Math.random() * 6

    // ── Spawn helpers ──
    const spawnShootingStar = () => {
      const angle = Math.PI * 0.1 + Math.random() * Math.PI * 0.4
      const speed = 5 + Math.random() * 6
      streaks.push({
        kind: 'shoot', x: Math.random() * w * 0.8, y: Math.random() * h * 0.4,
        vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed,
        life: 0, maxLife: 30 + Math.random() * 30,
        tailLen: 50 + Math.random() * 70, width: 1 + Math.random() * 0.8,
        brightness: 0.6 + Math.random() * 0.4, hue: 220, sparks: [],
      })
    }

    const spawnFireball = () => {
      // Fireballs: slower, wider, warm-colored, more sparks
      const angle = Math.PI * 0.15 + Math.random() * Math.PI * 0.3
      const speed = 2.5 + Math.random() * 3
      streaks.push({
        kind: 'fireball', x: Math.random() * w * 0.6, y: Math.random() * h * 0.25,
        vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed,
        life: 0, maxLife: 60 + Math.random() * 50,
        tailLen: 30 + Math.random() * 40, width: 2.5 + Math.random() * 1.5,
        brightness: 0.8 + Math.random() * 0.2,
        hue: 20 + Math.random() * 30, // orange-amber range
        sparks: [],
      })
    }

    const spawnMeteor = () => {
      // Meteors: very fast, bright, brief, thin
      const angle = Math.PI * 0.08 + Math.random() * Math.PI * 0.5
      const speed = 12 + Math.random() * 10
      const startEdge = Math.random()
      const sx = startEdge < 0.5 ? Math.random() * w : 0
      const sy = startEdge < 0.5 ? 0 : Math.random() * h * 0.3
      streaks.push({
        kind: 'meteor', x: sx, y: sy,
        vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed,
        life: 0, maxLife: 15 + Math.random() * 20,
        tailLen: 80 + Math.random() * 100, width: 0.8 + Math.random() * 0.6,
        brightness: 0.9 + Math.random() * 0.1, hue: 200, sparks: [],
      })
    }

    const spawnSatellite = () => {
      // Satellites: steady, slow, cross entire sky, subtle glint
      const fromLeft = Math.random() < 0.5
      const sy = Math.random() * h * 0.6
      const angle = (fromLeft ? 0 : Math.PI) + (Math.random() - 0.5) * 0.3
      const speed = 0.4 + Math.random() * 0.6
      satellites.push({
        x: fromLeft ? -10 : w + 10, y: sy,
        vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed + (Math.random() - 0.5) * 0.15,
        brightness: 0.3 + Math.random() * 0.4,
        glintPhase: Math.random() * Math.PI * 2,
        glintSpeed: 1.5 + Math.random() * 2,
        life: 0, maxLife: Math.ceil((w + 40) / speed),
      })
    }

    const draw = () => {
      time += 0.016
      ctx.clearRect(0, 0, w, h)

      // ── Dust clouds / Milky Way ──
      for (const dc of dustClouds) {
        const pulse = Math.sin(time * 0.15 + dc.phase) * 0.008
        const a = dc.alpha + pulse
        ctx.save()
        ctx.translate(dc.x, dc.y)
        ctx.rotate(dc.rotation)
        const g = ctx.createRadialGradient(0, 0, 0, 0, 0, Math.max(dc.rx, dc.ry))
        g.addColorStop(0, `hsla(${dc.hue}, ${dc.sat}%, 55%, ${a})`)
        g.addColorStop(0.4, `hsla(${dc.hue}, ${dc.sat - 10}%, 45%, ${a * 0.5})`)
        g.addColorStop(0.7, `hsla(${dc.hue}, ${dc.sat - 15}%, 35%, ${a * 0.2})`)
        g.addColorStop(1, 'transparent')
        ctx.fillStyle = g
        ctx.beginPath()
        ctx.ellipse(0, 0, dc.rx, dc.ry, 0, 0, Math.PI * 2)
        ctx.fill()
        ctx.restore()
      }

      // ── Stars ──
      for (const s of stars) {
        const twinkle = (Math.sin(time * s.twinkleSpeed + s.phase) + 1) / 2
        const a = (0.2 + twinkle * 0.8) * s.brightness

        ctx.globalAlpha = a
        ctx.fillStyle = s.color
        ctx.beginPath()
        ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2)
        ctx.fill()

        if (s.layer === 2 && twinkle > 0.6) {
          ctx.globalAlpha = a * 0.3 * twinkle
          const spike = s.r * 4
          ctx.strokeStyle = s.color
          ctx.lineWidth = 0.4
          ctx.beginPath()
          ctx.moveTo(s.x - spike, s.y); ctx.lineTo(s.x + spike, s.y)
          ctx.moveTo(s.x, s.y - spike); ctx.lineTo(s.x, s.y + spike)
          ctx.stroke()
        }

        if (s.layer >= 1 && s.r > 0.8 && twinkle > 0.5) {
          ctx.globalAlpha = a * 0.08
          const g = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, s.r * 5)
          g.addColorStop(0, s.color)
          g.addColorStop(1, 'transparent')
          ctx.fillStyle = g
          ctx.beginPath()
          ctx.arc(s.x, s.y, s.r * 5, 0, Math.PI * 2)
          ctx.fill()
        }
      }
      ctx.globalAlpha = 1

      // ── Spawn checks ──
      if (time >= nextShoot) { nextShoot = time + 2 + Math.random() * 4; spawnShootingStar() }
      if (time >= nextFireball) { nextFireball = time + 12 + Math.random() * 18; spawnFireball() }
      if (time >= nextMeteor) { nextMeteor = time + 5 + Math.random() * 8; spawnMeteor() }
      if (time >= nextSatellite) { nextSatellite = time + 10 + Math.random() * 20; spawnSatellite() }

      // ── Draw streaks (shooting stars, fireballs, meteors) ──
      for (let i = streaks.length - 1; i >= 0; i--) {
        const s = streaks[i]
        s.x += s.vx; s.y += s.vy; s.life++

        // Gravity pull for fireballs
        if (s.kind === 'fireball') s.vy += 0.02

        const progress = s.life / s.maxLife
        const fadeIn = s.kind === 'meteor' ? 0.05 : 0.15
        const alpha = progress < fadeIn
          ? progress / fadeIn
          : Math.max(0, 1 - ((progress - fadeIn) / (1 - fadeIn))) ** (s.kind === 'meteor' ? 2 : 1.5)

        const norm = Math.hypot(s.vx, s.vy)
        const dx = s.vx / norm
        const dy = s.vy / norm

        // Tail
        const tLen = s.tailLen * Math.min(alpha * 1.5, 1)
        const tailX = s.x - dx * tLen
        const tailY = s.y - dy * tLen
        const g = ctx.createLinearGradient(s.x, s.y, tailX, tailY)

        if (s.kind === 'fireball') {
          g.addColorStop(0, `hsla(${s.hue}, 95%, 80%, ${alpha * s.brightness})`)
          g.addColorStop(0.2, `hsla(${s.hue + 10}, 90%, 60%, ${alpha * s.brightness * 0.6})`)
          g.addColorStop(0.5, `hsla(${s.hue + 20}, 70%, 40%, ${alpha * s.brightness * 0.15})`)
          g.addColorStop(1, 'transparent')
        } else if (s.kind === 'meteor') {
          g.addColorStop(0, `rgba(255, 255, 255, ${alpha * s.brightness})`)
          g.addColorStop(0.1, `rgba(220, 235, 255, ${alpha * s.brightness * 0.7})`)
          g.addColorStop(0.4, `rgba(160, 190, 255, ${alpha * s.brightness * 0.1})`)
          g.addColorStop(1, 'transparent')
        } else {
          g.addColorStop(0, `rgba(255, 255, 255, ${alpha * s.brightness})`)
          g.addColorStop(0.15, `rgba(200, 220, 255, ${alpha * s.brightness * 0.6})`)
          g.addColorStop(0.5, `rgba(150, 180, 255, ${alpha * s.brightness * 0.15})`)
          g.addColorStop(1, 'rgba(100, 140, 255, 0)')
        }

        ctx.strokeStyle = g
        ctx.lineWidth = s.width * (0.5 + alpha * 0.5)
        ctx.lineCap = 'round'
        ctx.beginPath()
        ctx.moveTo(s.x, s.y); ctx.lineTo(tailX, tailY)
        ctx.stroke()

        // Head glow
        const glowR = s.kind === 'fireball' ? 6 : s.kind === 'meteor' ? 3 : 4
        ctx.globalAlpha = alpha * s.brightness * (s.kind === 'fireball' ? 0.5 : 0.6)
        const hg = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, glowR)
        if (s.kind === 'fireball') {
          hg.addColorStop(0, `hsla(${s.hue}, 100%, 85%, 0.9)`)
          hg.addColorStop(0.4, `hsla(${s.hue + 10}, 80%, 50%, 0.3)`)
          hg.addColorStop(1, 'transparent')
        } else {
          hg.addColorStop(0, 'rgba(255, 255, 255, 0.9)')
          hg.addColorStop(0.5, 'rgba(180, 210, 255, 0.3)')
          hg.addColorStop(1, 'transparent')
        }
        ctx.fillStyle = hg
        ctx.beginPath()
        ctx.arc(s.x, s.y, glowR, 0, Math.PI * 2)
        ctx.fill()
        ctx.globalAlpha = 1

        // Sparks — more frequent for fireballs
        const sparkChance = s.kind === 'fireball' ? 0.5 : s.kind === 'shoot' ? 0.25 : 0.15
        const sparkColor = s.kind === 'fireball'
          ? `hsl(${s.hue + Math.random() * 30}, 90%, ${60 + Math.random() * 30}%)`
          : '#c4d4ff'

        if (Math.random() < sparkChance && alpha > 0.25) {
          const spread = s.kind === 'fireball' ? 3 : 2
          s.sparks.push({
            x: s.x - dx * 3 + (Math.random() - 0.5) * spread,
            y: s.y - dy * 3 + (Math.random() - 0.5) * spread,
            vx: (Math.random() - 0.5) * (s.kind === 'fireball' ? 2 : 1.2),
            vy: (Math.random() - 0.5) * (s.kind === 'fireball' ? 2 : 1.2) + 0.3,
            life: 0, maxLife: 8 + Math.random() * 14,
            color: sparkColor,
          })
        }

        for (let j = s.sparks.length - 1; j >= 0; j--) {
          const sp = s.sparks[j]
          sp.x += sp.vx; sp.y += sp.vy; sp.life++
          if (s.kind === 'fireball') sp.vy += 0.03 // gravity on spark
          const sa = 1 - sp.life / sp.maxLife
          ctx.globalAlpha = sa * 0.6 * s.brightness
          ctx.fillStyle = sp.color
          ctx.beginPath()
          ctx.arc(sp.x, sp.y, s.kind === 'fireball' ? 0.7 : 0.5, 0, Math.PI * 2)
          ctx.fill()
          if (sp.life >= sp.maxLife) s.sparks.splice(j, 1)
        }
        ctx.globalAlpha = 1

        if (s.life >= s.maxLife && s.sparks.length === 0) streaks.splice(i, 1)
      }

      // ── Satellites ──
      for (let i = satellites.length - 1; i >= 0; i--) {
        const sat = satellites[i]
        sat.x += sat.vx; sat.y += sat.vy; sat.life++

        // Glint: periodic brightness pulse simulating solar panel reflection
        const glint = (Math.sin(time * sat.glintSpeed + sat.glintPhase) + 1) / 2
        const bright = sat.brightness * (0.4 + glint * 0.6)

        ctx.globalAlpha = bright
        ctx.fillStyle = '#e0e8ff'
        ctx.beginPath()
        ctx.arc(sat.x, sat.y, 1, 0, Math.PI * 2)
        ctx.fill()

        // Subtle glow during glint peak
        if (glint > 0.7) {
          ctx.globalAlpha = (glint - 0.7) * 2 * sat.brightness * 0.3
          const sg = ctx.createRadialGradient(sat.x, sat.y, 0, sat.x, sat.y, 4)
          sg.addColorStop(0, '#e0e8ff')
          sg.addColorStop(1, 'transparent')
          ctx.fillStyle = sg
          ctx.beginPath()
          ctx.arc(sat.x, sat.y, 4, 0, Math.PI * 2)
          ctx.fill()
        }

        ctx.globalAlpha = 1
        if (sat.life >= sat.maxLife || sat.x < -20 || sat.x > w + 20 || sat.y < -20 || sat.y > h + 20) {
          satellites.splice(i, 1)
        }
      }

      animId = requestAnimationFrame(draw)
    }

    resize()
    window.addEventListener('resize', resize)
    animId = requestAnimationFrame(draw)

    return () => {
      window.removeEventListener('resize', resize)
      cancelAnimationFrame(animId)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full"
      style={{ display: 'block' }}
    />
  )
}

export default function LoginPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
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
      navigate(nextUrl, { replace: true })
    }
  }, [isAuthenticated, isLoading, nextUrl, navigate])

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
      navigate(nextUrl, { replace: true })
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
      {/* ─── Animated starry galaxy background ─── */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <StarfieldCanvas />
        {/* Top accent scanline */}
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-vyper-500/30 to-transparent" />
        {/* Bottom accent */}
        <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-vyper-500/15 to-transparent" />
      </div>

      {/* ─── Main column ─── */}
      <div
        className={cn(
          'relative z-10 w-full max-w-[380px] mx-4',
          'transition-all duration-800 ease-[cubic-bezier(0.16,1,0.3,1)]',
          mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
        )}
      >
        {/* ─── Branding: Logo + VYPER ─── */}
        <div className="mb-8 flex flex-col items-center">
          <div
            className={cn(
              'transition-all duration-800 delay-100 ease-[cubic-bezier(0.16,1,0.3,1)]',
              mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
            )}
          >
            <VyperLogo className="w-14 h-14 text-vyper-400" />
          </div>
          <h1
            className={cn(
              'mt-3 text-[32px] font-extrabold tracking-[0.18em] text-transparent bg-clip-text',
              'bg-gradient-to-b from-surface-0 via-surface-100 to-surface-400',
              'font-[Outfit] select-none',
              'transition-all duration-800 delay-200 ease-[cubic-bezier(0.16,1,0.3,1)]',
              mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-3'
            )}
          >
            VYPER
          </h1>
          <p
            className={cn(
              'mt-2 text-[11px] text-surface-500/70 font-light tracking-[0.2em] uppercase font-mono',
              'transition-all duration-700 delay-350 ease-[cubic-bezier(0.16,1,0.3,1)]',
              mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-2'
            )}
          >
            Network Security Toolkit
          </p>
        </div>

        {/* ─── Card ─── */}
        <div
          className={cn(
            'relative rounded-2xl',
            'bg-surface-900/40 backdrop-blur-xl',
            'border border-surface-800/40',
            'shadow-[0_24px_80px_-16px_rgba(0,0,0,0.6)]',
            'overflow-hidden',
            'transition-all duration-800 delay-150 ease-[cubic-bezier(0.16,1,0.3,1)]',
            mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-5'
          )}
        >
          {/* Shimmer top accent */}
          <div className="absolute top-0 left-0 right-0 h-px overflow-hidden">
            <div className="lg-shimmer h-full" />
          </div>

          <div className="relative px-8 py-8">
            {/* Error */}
            {displayError && (
              <div
                className="mb-6 flex items-start gap-3 rounded-xl bg-accent-rose/6 border border-accent-rose/12 px-4 py-3 text-[13px] text-accent-rose/90 lg-error-enter"
                role="alert"
                aria-live="polite"
              >
                <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0 opacity-70" />
                <span>{displayError}</span>
              </div>
            )}

            {/* ── Chooser ── */}
            {view === 'chooser' && (
              <div className="space-y-3 lg-view-enter">
                <p className="text-center text-surface-500 text-[13px] mb-7 font-light">
                  Choose how you&rsquo;d like to sign in
                </p>

                <button
                  type="button"
                  onClick={showLocal}
                  className={cn(
                    'group w-full flex items-center gap-3.5 px-4 py-3 rounded-xl',
                    'bg-surface-800/30 border border-surface-700/30',
                    'hover:bg-surface-800/50 hover:border-vyper-500/25',
                    'text-surface-200 text-[13px] font-medium',
                    'transition-all duration-300 ease-out',
                    'focus-visible:ring-2 focus-visible:ring-vyper-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-900'
                  )}
                  aria-label="Sign in with local account"
                >
                  <span className="flex items-center justify-center w-8 h-8 rounded-lg bg-vyper-500/8 text-vyper-400 group-hover:bg-vyper-500/15 group-hover:scale-105 transition-all duration-300">
                    <KeyRound className="w-3.5 h-3.5" />
                  </span>
                  Sign in with Local Account
                </button>

                <div className="flex items-center gap-3 py-1.5">
                  <div className="flex-1 h-px bg-gradient-to-r from-transparent to-surface-800/60" />
                  <span className="text-[9px] text-surface-600 uppercase tracking-[0.25em] font-mono">or</span>
                  <div className="flex-1 h-px bg-gradient-to-l from-transparent to-surface-800/60" />
                </div>

                <a
                  href={`/sso/login?next=${encodeURIComponent(nextUrl)}`}
                  className={cn(
                    'group w-full flex items-center gap-3.5 px-4 py-3 rounded-xl no-underline',
                    'bg-accent-emerald/4 border border-accent-emerald/12',
                    'hover:bg-accent-emerald/8 hover:border-accent-emerald/20',
                    'text-accent-emerald text-[13px] font-medium',
                    'transition-all duration-300 ease-out',
                    'focus-visible:ring-2 focus-visible:ring-accent-emerald/50 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-900'
                  )}
                  aria-label="Sign in with SSO Duo"
                >
                  <span className="flex items-center justify-center w-8 h-8 rounded-lg bg-accent-emerald/8 group-hover:bg-accent-emerald/15 group-hover:scale-105 transition-all duration-300">
                    <ShieldCheck className="w-3.5 h-3.5" />
                  </span>
                  Sign in with SSO (Duo)
                </a>
              </div>
            )}

            {/* ── Local Login Form ── */}
            {view === 'local' && (
              <div className="lg-view-enter">
                <form
                  onSubmit={handleSubmit}
                  onKeyDown={handleKeyDown}
                  className="space-y-5"
                  noValidate
                >
                  <div className="lg-stagger-1">
                    <label
                      htmlFor="username"
                      className="block text-[10px] font-medium text-surface-500 mb-2 tracking-[0.12em] uppercase font-mono"
                    >
                      Username
                    </label>
                    <div className="relative group">
                      <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-surface-600 group-focus-within:text-vyper-400 transition-colors duration-300">
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
                          'w-full pl-10 pr-4 py-2.5 rounded-xl text-[13px]',
                          'bg-surface-900/60 border border-surface-700/30',
                          'text-surface-100 placeholder:text-surface-600',
                          'hover:border-surface-600/40',
                          'focus:outline-none focus:border-vyper-500/35 focus:ring-1 focus:ring-vyper-500/15 focus:bg-surface-900/80',
                          'transition-all duration-300'
                        )}
                      />
                    </div>
                  </div>

                  <div className="lg-stagger-2">
                    <label
                      htmlFor="password"
                      className="block text-[10px] font-medium text-surface-500 mb-2 tracking-[0.12em] uppercase font-mono"
                    >
                      Password
                    </label>
                    <div className="relative group">
                      <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-surface-600 group-focus-within:text-vyper-400 transition-colors duration-300">
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
                          'w-full pl-10 pr-4 py-2.5 rounded-xl text-[13px]',
                          'bg-surface-900/60 border border-surface-700/30',
                          'text-surface-100 placeholder:text-surface-600',
                          'hover:border-surface-600/40',
                          'focus:outline-none focus:border-vyper-500/35 focus:ring-1 focus:ring-vyper-500/15 focus:bg-surface-900/80',
                          'transition-all duration-300'
                        )}
                      />
                    </div>
                  </div>

                  <div className="lg-stagger-3 pt-1">
                    <button
                      type="submit"
                      disabled={submitting || !username.trim() || !password.trim()}
                      className={cn(
                        'w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-[13px] font-semibold',
                        'bg-vyper-600 hover:bg-vyper-500 active:bg-vyper-700',
                        'text-white',
                        'shadow-[0_2px_16px_-2px_rgba(11,132,230,0.35)]',
                        'hover:shadow-[0_4px_24px_-2px_rgba(11,132,230,0.45)]',
                        'disabled:opacity-35 disabled:cursor-not-allowed disabled:hover:bg-vyper-600 disabled:shadow-none',
                        'transition-all duration-300 ease-out',
                        'focus-visible:ring-2 focus-visible:ring-vyper-400/60 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-900'
                      )}
                      aria-label="Sign in"
                    >
                      {submitting ? (
                        <>
                          <span className="inline-block w-4 h-4 border-2 border-white/25 border-t-white rounded-full animate-spin" />
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
                    'w-full mt-5 flex items-center justify-center gap-1.5 py-2 text-[12px]',
                    'text-surface-600 hover:text-surface-400',
                    'transition-colors duration-300',
                    'focus-visible:ring-2 focus-visible:ring-vyper-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-900',
                    'rounded-lg'
                  )}
                  aria-label="Back to sign-in options"
                >
                  <ArrowLeft className="w-3 h-3" />
                  Other sign-in options
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ═══════ CSS Animations ═══════ */}
      <style>{`

        /* ─── Shimmer ─── */
        .lg-shimmer {
          background: linear-gradient(
            90deg,
            transparent 0%,
            transparent 30%,
            rgba(11,132,230,0.3) 50%,
            transparent 70%,
            transparent 100%
          );
          animation: lg-shimmer-slide 4s ease-in-out infinite;
        }
        @keyframes lg-shimmer-slide {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }

        /* ─── View transitions ─── */
        .lg-view-enter {
          animation: lg-view-in 0.45s cubic-bezier(0.16,1,0.3,1) both;
        }
        @keyframes lg-view-in {
          from { opacity: 0; transform: translateY(12px) scale(0.98); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }

        /* ─── Staggered field reveal ─── */
        .lg-stagger-1 { animation: lg-field 0.5s cubic-bezier(0.16,1,0.3,1) 0.05s both; }
        .lg-stagger-2 { animation: lg-field 0.5s cubic-bezier(0.16,1,0.3,1) 0.12s both; }
        .lg-stagger-3 { animation: lg-field 0.5s cubic-bezier(0.16,1,0.3,1) 0.19s both; }
        @keyframes lg-field {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }

        /* ─── Error shake ─── */
        .lg-error-enter {
          animation: lg-shake 0.5s cubic-bezier(0.36,0.07,0.19,0.97) both;
        }
        @keyframes lg-shake {
          0% { opacity: 0; transform: translateX(-12px); }
          25% { transform: translateX(8px); }
          50% { transform: translateX(-4px); }
          75% { transform: translateX(2px); }
          100% { opacity: 1; transform: translateX(0); }
        }
      `}</style>
    </div>
  )
}
