/** @type {import('tailwindcss').Config} */
// Reconner theme — a calm, dark-first security console.
//
// One committed accent: ELECTRIC TEAL/CYAN. Everything interactive (links,
// active nav, primary actions, focus) uses the accent family — no competing
// second hue, no rainbow gradient. Severity keeps its semantic hues but is
// ALWAYS paired with a text label/icon in the UI (badges), never color-alone.
// Neutrals are lifted off pure #000 with a faint cool tint to reduce eye
// strain over long triage sessions; text is never pure #fff.
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Deep, slightly cool neutrals (0 = app background, higher = raised).
        // Values pinned to the committed design spec.
        surface: {
          DEFAULT: '#07090d', // bg-app
          1: '#0a0c10',       // bg-sidebar
          2: '#0f1218',       // bg-card
          3: '#151a22',       // bg-elevated (popovers / menus)
          4: '#1b212b',
          5: '#232b37',
          alt: '#0c0f14',     // bg-input
        },
        border: {
          DEFAULT: '#1e2530',
          subtle: '#161c24',
          strong: '#2a3341',
          accent: 'rgba(139,92,246,0.25)',
        },
        // The single committed accent — teal-500.
        accent: {
          DEFAULT: '#8b5cf6',
          hover: '#a78bfa',
          muted: 'rgba(139,92,246,0.12)',
          glow: 'rgba(139,92,246,0.35)',
        },
        text: {
          primary: '#e8edf4',
          secondary: '#8b9cb3',
          muted: '#5a6a7e',
          inverse: '#04140f',
        },
        // Severity — always shown with a text label in the UI.
        severity: {
          // Severity scale by level: white → green → yellow → orange → red.
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#22c55e',
          info: '#f8fafc',
        },
        // Chart/series palette — accent-led, distinct hues for graphs.
        series: {
          1: '#8b5cf6',
          2: '#6366f1',
          3: '#a78bfa',
          4: '#f97316',
          5: '#f472b6',
          6: '#eab308',
          7: '#22c55e',
          8: '#8b9cb3',
        },
      },
      fontFamily: {
        sans: ['Space Grotesk', 'Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '8px',
        sm: '6px',
        lg: '10px',
        xl: '14px',
      },
      animation: {
        'fade-in': 'fadeIn 0.18s ease-out',
        'slide-up': 'slideUp 0.2s ease-out',
        'pulse-slow': 'pulse 3s infinite',
      },
      keyframes: {
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        slideUp: {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
