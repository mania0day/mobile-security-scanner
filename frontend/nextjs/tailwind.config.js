/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        canvas:  '#F7F8FA',
        ink:     '#0F172A',
        muted:   '#6B7280',
        subtle:  '#9CA3AF',
        line:    '#E5E7EB',
        panel:   '#FFFFFF',
        brand: {
          DEFAULT: '#0F766E',
          soft:    '#CCFBF1',
          dark:    '#115E59',
          glow:    'rgba(15,118,110,0.15)',
        },
        pass:  { DEFAULT: '#16A34A', soft: '#DCFCE7', dark: '#14532D' },
        warn:  { DEFAULT: '#D97706', soft: '#FEF3C7', dark: '#92400E' },
        fail:  { DEFAULT: '#DC2626', soft: '#FEE2E2', dark: '#7F1D1D' },
      },
      fontFamily: {
        sans: ['var(--font-sans)', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'Menlo', 'monospace'],
      },
      boxShadow: {
        soft:  '0 1px 3px rgba(0,0,0,0.05), 0 4px 16px rgba(0,0,0,0.06)',
        card:  '0 0 0 1px rgba(0,0,0,0.05), 0 4px 24px rgba(0,0,0,0.07)',
        glow:  '0 0 0 3px rgba(15,118,110,0.18)',
        up:    '0 -2px 8px rgba(0,0,0,0.04)',
      },
      maxWidth: { content: '76rem' },
      borderRadius: { '2xl': '1rem', '3xl': '1.25rem' },
      keyframes: {
        'fade-up':  { '0%': { opacity: '0', transform: 'translateY(10px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        'fade-in':  { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        'shimmer':  { '0%': { backgroundPosition: '-200% 0' }, '100%': { backgroundPosition: '200% 0' } },
        'ping-slow':{ '0%,100%': { transform:'scale(1)', opacity:'1' }, '50%': { transform:'scale(1.4)', opacity:'0.4' } },
      },
      animation: {
        'fade-up':   'fade-up 0.4s cubic-bezier(0.16,1,0.3,1) both',
        'fade-in':   'fade-in 0.25s ease both',
        'shimmer':   'shimmer 1.6s infinite linear',
        'ping-slow': 'ping-slow 1.8s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
