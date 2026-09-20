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
          DEFAULT: '#070a12',
          1: '#0a0e19',
          2: '#101522',
          3: '#171d2c',
          4: '#20283a',
          5: '#2a3449',
          alt: '#0c111d',
        },
        border: {
          DEFAULT: '#222b3d',
          subtle: '#182033',
          strong: '#34405a',
          accent: 'rgba(139,92,246,0.25)',
        },
        // The single committed accent — teal-500.
        accent: {
          DEFAULT: '#8b7cff',
          hover: '#aca2ff',
          muted: 'rgba(139,124,255,0.13)',
          glow: 'rgba(139,124,255,0.38)',
        },
        text: {
          primary: '#f3f5fb',
          secondary: '#a2aec3',
          muted: '#647189',
          inverse: '#0a0b16',
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
          1: '#8b7cff',
          2: '#4fd1c5',
          3: '#60a5fa',
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
        DEFAULT: '10px',
        sm: '8px',
        lg: '14px',
        xl: '18px',
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
