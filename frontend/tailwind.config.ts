import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:       '#0A0A0B',
        surface:  '#161618',
        panel:    '#1C1C1F',
        border:   '#2A2A2E',
        accent:   '#3B82F6',
        critical: '#EF4444',
        high:     '#F59E0B',
        medium:   '#EAB308',
        low:      '#10B981',
        muted:    '#71717A',
        ink:      '#E4E4E7',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config;
