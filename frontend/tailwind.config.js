/** @type {import('tailwindcss').Config} */
// Reconner theme — "BLACK TERMINAL".
//
// A hacker-terminal console: true-black surfaces, a single committed AMBER
// accent (#f59e0b — HackTheBox-style), sharp corners, JetBrains Mono for
// numbers/identifiers and Vazirmatn for UI text (self-hosted, offline-safe).
// Severity keeps its semantic hues but is ALWAYS paired with a text label in
// the UI (badges), never color-alone. No competing second hue, no rainbow.
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // True-black neutral stack (0 = app background, higher = raised).
        // Warmed a touch (#0b0b0a family) so amber glows don't look neon-on-blue.
        surface: {
          DEFAULT: '#050505', // bg-app — terminal void
          1: '#030303',       // bg-sidebar
          2: '#0b0b0a',       // bg-card
          3: '#141412',       // bg-elevated (popovers / menus)
          4: '#1c1b18',
          5: '#262421',
          alt: '#080807',     // bg-input
        },
        border: {
          DEFAULT: '#262421',
          subtle: '#191817',
          strong: '#3a362e',
          accent: 'rgba(245,158,11,0.30)',
        },
        // The single committed accent — amber-500.
        accent: {
          DEFAULT: '#f59e0b',
          hover: '#fbbf24',
          muted: 'rgba(245,158,11,0.10)',
          glow: 'rgba(245,158,11,0.32)',
        },
        text: {
          primary: '#eae7e1',
          secondary: '#a3a099',
          muted: '#6b6862',
          inverse: '#140b00', // label text on amber fills
        },
        // Severity — always shown with a text label in the UI.
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#22c55e',
          info: '#38bdf8',
        },
        // Chart/series palette — amber-led, distinct hues for graphs.
        series: {
          1: '#f59e0b',
          2: '#fbbf24',
          3: '#d97706',
          4: '#92400e',
          5: '#22c55e',
          6: '#ef4444',
          7: '#a8a29e',
          8: '#57534e',
        },
      },
      fontFamily: {
        sans: ['Vazirmatn', 'Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Vazirmatn', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '4px',
        sm: '3px',
        lg: '6px',
        xl: '8px',
      },
      animation: {
        'fade-in': 'fadeIn 0.18s ease-out',
        'slide-up': 'slideUp 0.2s ease-out',
        'pulse-slow': 'pulse 3s infinite',
        blink: 'blink 1.1s steps(2, start) infinite',
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
        blink: {
          to: { visibility: 'hidden' },
        },
      },
    },
  },
  plugins: [],
}
