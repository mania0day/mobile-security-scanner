'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import { Shield, Activity } from 'lucide-react';
import { cn } from '@/lib/utils';

const links = [
  { href: '/', label: 'Dashboard' },
  { href: '/devices', label: 'History' },
  { href: '/about', label: 'About' },
];

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:5000';

export function Navbar() {
  const pathname = usePathname();
  const [scrolled, setScrolled] = useState(false);
  const [apiAlive, setApiAlive] = useState<boolean | null>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    const check = async () => {
      try {
        const r = await fetch(`${API_BASE}/api/health`, { cache: 'no-store' });
        setApiAlive(r.ok);
      } catch {
        setApiAlive(false);
      }
    };
    check();
    const id = setInterval(check, 20000);
    return () => clearInterval(id);
  }, []);

  return (
    <header
      className={cn(
        'sticky top-0 z-50 border-b transition-all duration-300',
        scrolled
          ? 'border-line/80 bg-white/90 backdrop-blur-xl shadow-soft'
          : 'border-transparent bg-white/70 backdrop-blur-sm'
      )}
    >
      <div className="mx-auto flex h-[60px] max-w-content items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand */}
        <Link href="/" className="flex items-center gap-3 group">
          <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-brand text-white shadow-soft group-hover:shadow-glow transition-shadow duration-200">
            <Shield className="h-4 w-4" />
          </span>
          <span className="leading-tight">
            <span className="block text-sm font-semibold tracking-tight text-ink">Mobile Security</span>
            <span className="block text-[10px] font-medium text-muted">Admission Scanner</span>
          </span>
        </Link>

        {/* Nav + Status */}
        <div className="flex items-center gap-4">
          <nav className="flex items-center gap-0.5">
            {links.map((item) => {
              const active =
                item.href === '/'
                  ? pathname === '/'
                  : pathname === item.href || pathname.startsWith(`${item.href}/`);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    'relative rounded-lg px-3.5 py-2 text-sm font-medium transition-colors duration-150',
                    active
                      ? 'text-brand-dark bg-brand-soft'
                      : 'text-muted hover:bg-canvas hover:text-ink'
                  )}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {/* API status */}
          <div className="flex items-center gap-1.5 rounded-full border border-line bg-white px-2.5 py-1.5 text-[11px] font-medium text-muted shadow-soft">
            {apiAlive === null ? (
              <span className="h-1.5 w-1.5 rounded-full bg-subtle animate-pulse" />
            ) : apiAlive ? (
              <>
                <span className="relative flex h-1.5 w-1.5">
                  <span className="absolute inline-flex h-full w-full animate-ping-slow rounded-full bg-pass opacity-60" />
                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-pass" />
                </span>
                <span className="text-pass hidden sm:inline">API live</span>
              </>
            ) : (
              <>
                <span className="h-1.5 w-1.5 rounded-full bg-fail" />
                <span className="text-fail hidden sm:inline">API down</span>
              </>
            )}
            <Activity className="h-3 w-3" />
          </div>
        </div>
      </div>
    </header>
  );
}
