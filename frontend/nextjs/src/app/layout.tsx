import type { Metadata } from 'next';
import { Sora, IBM_Plex_Mono } from 'next/font/google';
import './globals.css';
import { Navbar } from '@/components/layout/Navbar';

const sora = Sora({
  subsets: ['latin'],
  variable: '--font-sans',
  display: 'swap',
});

const plexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'Mobile Security — Admission Scanner',
  description: 'BYOD device admission scanning, history, and PDF security certificates',
  keywords: ['mobile security', 'BYOD', 'admission scan', 'Android', 'iOS', 'security audit'],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full">
      <body className={`${sora.variable} ${plexMono.variable} font-sans min-h-screen bg-canvas text-ink antialiased`}>
        {/* Subtle gradient background */}
        <div
          aria-hidden="true"
          className="pointer-events-none fixed inset-0 -z-10"
          style={{
            background: `
              radial-gradient(ellipse 80% 50% at 20% -10%, rgba(15,118,110,0.06), transparent),
              radial-gradient(ellipse 60% 40% at 80% 110%, rgba(15,118,110,0.04), transparent),
              linear-gradient(180deg, #F8FAFC 0%, #F7F8FA 50%, #F2F4F7 100%)
            `,
          }}
        />
        <Navbar />
        <main className="page-shell pb-20">{children}</main>
      </body>
    </html>
  );
}
