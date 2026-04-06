/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Latency band colours — mirror the README spec
        'band-green':  '#16a34a',
        'band-amber':  '#d97706',
        'band-red':    '#dc2626',
        'band-missed': '#7f1d1d',
        'band-grey':   '#374151',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}
