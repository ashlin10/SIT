import { cn } from '@/lib/utils'

/**
 * VYPER logo — intertwined V with snake-like loops.
 * Traced from the brand reference: two mirrored serpentine strokes
 * that weave through each other forming an ornate "V".
 */
export function VyperLogo({ className, animate = false }: { className?: string; animate?: boolean }) {
  return (
    <svg
      viewBox="0 0 200 180"
      fill="none"
      className={cn(className, animate && 'vyper-logo-animated')}
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Left arm of V — serpentine stroke with interlocking loops */}
      <path
        d="
          M 52 8
          C 46 12, 38 22, 34 32
          C 28 48, 36 52, 42 44
          C 48 36, 40 28, 34 36
          C 26 48, 38 64, 48 56
          C 56 50, 44 40, 40 50
          C 34 64, 54 78, 62 70
          C 68 64, 56 54, 52 62
          C 46 76, 66 90, 76 82
          C 84 76, 70 64, 66 74
          C 60 90, 80 108, 90 100
          C 96 94, 92 86, 96 118
          L 100 140
        "
        stroke="currentColor"
        strokeWidth="5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
        className={animate ? 'vyper-stroke-left' : undefined}
      />
      {/* Right arm of V — mirrored serpentine stroke */}
      <path
        d="
          M 148 8
          C 154 12, 162 22, 166 32
          C 172 48, 164 52, 158 44
          C 152 36, 160 28, 166 36
          C 174 48, 162 64, 152 56
          C 144 50, 156 40, 160 50
          C 166 64, 146 78, 138 70
          C 132 64, 144 54, 148 62
          C 154 76, 134 90, 124 82
          C 116 76, 130 64, 134 74
          C 140 90, 120 108, 110 100
          C 104 94, 108 86, 104 118
          L 100 140
        "
        stroke="currentColor"
        strokeWidth="5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
        className={animate ? 'vyper-stroke-right' : undefined}
      />
      {/* Wing tip accents — left */}
      <path
        d="M 52 8 C 44 4, 36 6, 30 14 C 26 20, 30 22, 34 18"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
        fill="none"
        opacity="0.7"
        className={animate ? 'vyper-tip-left' : undefined}
      />
      {/* Wing tip accents — right */}
      <path
        d="M 148 8 C 156 4, 164 6, 170 14 C 174 20, 170 22, 166 18"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
        fill="none"
        opacity="0.7"
        className={animate ? 'vyper-tip-right' : undefined}
      />
      {/* Center drop detail at vertex */}
      <path
        d="M 100 140 C 98 148, 96 154, 100 162 C 104 154, 102 148, 100 140"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="currentColor"
        fillOpacity="0.15"
        className={animate ? 'vyper-drop' : undefined}
      />
    </svg>
  )
}

/**
 * Small variant of the VYPER logo for sidebar / compact use.
 * Same paths, no animation.
 */
export function VyperLogoSmall({ className }: { className?: string }) {
  return <VyperLogo className={className} />
}
