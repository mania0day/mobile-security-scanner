'use client';

import { useEffect, useState } from 'react';
import { motion, useSpring } from 'framer-motion';
import { cn } from '@/lib/utils';

const CATEGORY_LABELS: Record<string, string> = {
  identity:       'Identity',
  root_jailbreak: 'Integrity',
  lock_encryption:'Lock & Crypto',
  installed_apps: 'Applications',
  network:        'Network',
  certificates:   'Certificates',
  management:     'MDM Ready',
  backup:         'Backup',
};

export function categoryLabel(key: string) {
  return CATEGORY_LABELS[key] || key.replace(/_/g, ' ');
}

export function riskColor(level: string) {
  const l = (level || '').toUpperCase();
  if (l === 'CRITICAL' || l === 'FAIL')   return '#DC2626';
  if (l === 'HIGH' || l === 'WARNING' || l === 'CONDITIONAL') return '#D97706';
  if (l === 'MEDIUM') return '#CA8A04';
  if (l === 'LOW' || l === 'PASS')         return '#16A34A';
  return '#6B7280';
}

export function ScoreRing({
  score,
  size = 140,
  stroke = 10,
  label = 'Risk',
  className,
}: {
  score: number;
  size?: number;
  stroke?: number;
  label?: string;
  className?: string;
}) {
  const clamped = Math.max(0, Math.min(100, score));
  const r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;
  const offset = circumference - (clamped / 100) * circumference;

  const color =
    clamped >= 75 ? '#DC2626' :
    clamped >= 50 ? '#D97706' :
    clamped >= 25 ? '#CA8A04' :
    '#16A34A';

  const glowColor =
    clamped >= 75 ? 'rgba(220,38,38,0.18)' :
    clamped >= 50 ? 'rgba(217,119,6,0.16)' :
    'rgba(22,163,74,0.14)';

  const scoreLabel =
    clamped >= 75 ? 'High Risk' :
    clamped >= 50 ? 'Medium Risk' :
    clamped >= 25 ? 'Low Risk' :
    'Minimal';

  // Animated count-up: drive a spring toward the target score and mirror its
  // rounded value into React state so the number ticks up in sync with the
  // ring arc, instead of jumping straight to the final value.
  const spring = useSpring(0, { stiffness: 55, damping: 18, mass: 0.9 });
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    spring.set(clamped);
  }, [clamped, spring]);

  useEffect(() => {
    const unsub = spring.on('change', (v) => setDisplay(Math.round(v)));
    return unsub;
  }, [spring]);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.85 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      className={cn('relative inline-flex flex-col items-center gap-2', className)}
    >
      <motion.div
        className="relative"
        style={{ width: size, height: size }}
        animate={{ filter: `drop-shadow(0 0 14px ${glowColor})` }}
        transition={{ duration: 0.8 }}
      >
        <svg width={size} height={size} className="-rotate-90">
          {/* Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="#E5E7EB"
            strokeWidth={stroke}
          />
          {/* Progress */}
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.1, ease: [0.16, 1, 0.3, 1] }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span
            key={label}
            className="text-3xl font-bold tabular-nums text-ink"
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15, duration: 0.4 }}
          >
            {display}
          </motion.span>
          <span className="text-[10px] font-semibold uppercase tracking-widest text-muted">{label}</span>
        </div>
      </motion.div>
      <motion.span
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6, duration: 0.4 }}
        className="text-xs font-medium text-muted"
      >
        {scoreLabel}
      </motion.span>
    </motion.div>
  );
}

export { CATEGORY_LABELS };
