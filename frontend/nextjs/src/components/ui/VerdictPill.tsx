import { CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

const config: Record<string, { style: string; label: string; Icon: typeof CheckCircle2 }> = {
  PASS: {
    style: 'bg-pass-soft text-pass-dark border border-pass/20',
    label: 'Approved',
    Icon: CheckCircle2,
  },
  CONDITIONAL: {
    style: 'bg-warn-soft text-warn-dark border border-warn/20',
    label: 'Conditional',
    Icon: AlertTriangle,
  },
  WARNING: {
    style: 'bg-warn-soft text-warn-dark border border-warn/20',
    label: 'Warning',
    Icon: AlertTriangle,
  },
  FAIL: {
    style: 'bg-fail-soft text-fail-dark border border-fail/20',
    label: 'Rejected',
    Icon: XCircle,
  },
};

export function VerdictPill({
  verdict,
  className,
}: {
  verdict: string;
  className?: string;
}) {
  const key = verdict?.toUpperCase?.() || 'PASS';
  const c = config[key] || {
    style: 'bg-slate-100 text-slate-600 border border-slate-200',
    label: key,
    Icon: CheckCircle2,
  };
  const { style, label, Icon } = c;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold tracking-wide',
        style,
        className
      )}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" />
      {label}
    </span>
  );
}

export function StatusDot({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    PASS: 'bg-pass',
    WARNING: 'bg-warn',
    FAIL: 'bg-fail',
  };
  const color = colorMap[status?.toUpperCase()] || 'bg-subtle';
  return <span className={cn('mt-1.5 h-2 w-2 shrink-0 rounded-full', color)} />;
}
