'use client';

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
    clamped >= 75 ? 'rgba(220,38,38,0.12)' :
    clamped >= 50 ? 'rgba(217,119,6,0.12)' :
    'rgba(22,163,74,0.12)';

  const scoreLabel =
    clamped >= 75 ? 'High Risk' :
    clamped >= 50 ? 'Medium Risk' :
    clamped >= 25 ? 'Low Risk' :
    'Minimal';

  return (
    <div
      className={cn('relative inline-flex flex-col items-center gap-2', className)}
    >
      <div
        className="relative"
        style={{
          width: size,
          height: size,
          filter: `drop-shadow(0 0 12px ${glowColor})`,
        }}
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
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 1s cubic-bezier(0.4,0,0.2,1)' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold tabular-nums text-ink">{clamped}</span>
          <span className="text-[10px] font-semibold uppercase tracking-widest text-muted">{label}</span>
        </div>
      </div>
      <span className="text-xs font-medium text-muted">{scoreLabel}</span>
    </div>
  );
}

export { CATEGORY_LABELS };
