'use client';

import { useState } from 'react';
import { ChecklistItem } from '@/lib/api';
import { StatusDot } from '@/components/ui/VerdictPill';
import { ChevronDown, Fingerprint, ShieldOff, Lock, AppWindow, Wifi, BadgeCheck, Building2, HardDrive, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { motion, AnimatePresence } from 'framer-motion';

const CATEGORY_LABELS: Record<string, string> = {
  identity:        'Device & OS Identity',
  root_jailbreak:  'Root / Jailbreak & Integrity',
  lock_encryption: 'Lock Screen & Encryption',
  installed_apps:  'Installed Applications',
  network:         'Network & Connectivity',
  certificates:    'Certificates',
  management:      'Management Readiness',
  backup:          'Data Backup Exposure',
};

const CATEGORY_ICONS: Record<string, typeof Fingerprint> = {
  identity:        Fingerprint,
  root_jailbreak:  ShieldOff,
  lock_encryption: Lock,
  installed_apps:  AppWindow,
  network:         Wifi,
  certificates:    BadgeCheck,
  management:      Building2,
  backup:          HardDrive,
};

const PRIORITY_STYLES: Record<string, string> = {
  Must:          'bg-fail-soft text-fail border-fail/20',
  Should:        'bg-warn-soft text-warn border-warn/20',
  'Nice to have':'bg-canvas text-muted border-line',
};

const STATUS_ICON: Record<string, { Icon: typeof CheckCircle2; color: string }> = {
  PASS:    { Icon: CheckCircle2,  color: 'text-pass' },
  WARNING: { Icon: AlertTriangle, color: 'text-warn' },
  FAIL:    { Icon: XCircle,       color: 'text-fail' },
};

const STATUS_BADGE_STYLES: Record<string, string> = {
  PASS:    'bg-pass-soft text-pass-dark border-pass/25',
  WARNING: 'bg-warn-soft text-warn-dark border-warn/25',
  FAIL:    'bg-fail-soft text-fail-dark border-fail/25',
};

function AccordionSection({
  catKey,
  index,
  items,
}: {
  catKey: string;
  index: number;
  items: ChecklistItem[];
}) {
  const [open, setOpen] = useState(true);
  const Icon = CATEGORY_ICONS[catKey] || Fingerprint;
  const pass = items.filter(i => i.status === 'PASS').length;
  const warn = items.filter(i => i.status === 'WARNING').length;
  const fail = items.filter(i => i.status === 'FAIL').length;

  const headerColor =
    fail > 0 ? 'border-l-fail' :
    warn > 0 ? 'border-l-warn' :
    'border-l-pass';

  return (
    <motion.section
      className="panel overflow-hidden"
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
    >
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className={cn(
          'flex w-full items-center gap-4 border-b border-line border-l-4 bg-canvas/40 px-5 py-4 text-left transition-colors hover:bg-canvas/70',
          headerColor
        )}
      >
        <span className={cn(
          'flex h-9 w-9 shrink-0 items-center justify-center rounded-xl',
          fail > 0 ? 'bg-fail-soft text-fail' : warn > 0 ? 'bg-warn-soft text-warn' : 'bg-pass-soft text-pass'
        )}>
          <Icon className="h-4 w-4" />
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-ink">
            <span className="mr-2 text-subtle">{index + 1}.</span>
            {CATEGORY_LABELS[catKey] || catKey}
          </p>
          <div className="mt-1 flex gap-3 text-[11px]">
            {pass > 0 && <span className="font-medium text-pass">{pass} passed</span>}
            {warn > 0 && <span className="font-medium text-warn">{warn} warnings</span>}
            {fail > 0 && <span className="font-medium text-fail">{fail} failed</span>}
          </div>
        </div>
        <ChevronDown
          className={cn('h-4 w-4 text-muted transition-transform duration-200', open ? 'rotate-180' : '')}
        />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <ul className="divide-y divide-line">
              {items.map((item, i) => {
                const statusInfo = STATUS_ICON[item.status] || STATUS_ICON.PASS;
                const { Icon: SIcon, color } = statusInfo;
                return (
                  <motion.li
                    key={item.id || item.check_name}
                    initial={{ opacity: 0, x: -4 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.02 }}
                    className="flex gap-4 px-5 py-4"
                  >
                    <SIcon className={cn('mt-0.5 h-4 w-4 shrink-0', color)} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <p className="text-sm font-medium text-ink">{item.check_name}</p>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <span
                            title="Priority"
                            className={cn(
                              'rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide',
                              PRIORITY_STYLES[item.priority] || PRIORITY_STYLES['Nice to have']
                            )}
                          >
                            {item.priority}
                          </span>
                          <span
                            title="Result"
                            className={cn(
                              'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide',
                              STATUS_BADGE_STYLES[item.status] || STATUS_BADGE_STYLES.PASS
                            )}
                          >
                            <SIcon className="h-3 w-3" />
                            {item.status}
                          </span>
                        </div>
                      </div>
                      {item.details && (
                        <p className="mt-1.5 text-[13px] leading-relaxed text-muted">
                          {item.details}
                        </p>
                      )}
                    </div>
                  </motion.li>
                );
              })}
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.section>
  );
}

export function ChecklistPanel({ items }: { items: ChecklistItem[] }) {
  const grouped = items.reduce<Record<string, ChecklistItem[]>>((acc, item) => {
    const key = item.category || 'general';
    (acc[key] ||= []).push(item);
    return acc;
  }, {});

  const order = Object.keys(CATEGORY_LABELS);
  const keys = [
    ...order.filter(k => grouped[k]),
    ...Object.keys(grouped).filter(k => !order.includes(k)),
  ];

  const pass = items.filter(i => i.status === 'PASS').length;
  const warn = items.filter(i => i.status === 'WARNING').length;
  const fail = items.filter(i => i.status === 'FAIL').length;

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 rounded-xl border border-pass/20 bg-pass-soft px-3 py-1.5 text-sm font-semibold text-pass">
          <CheckCircle2 className="h-4 w-4" /> {pass} passed
        </div>
        {warn > 0 && (
          <div className="flex items-center gap-2 rounded-xl border border-warn/20 bg-warn-soft px-3 py-1.5 text-sm font-semibold text-warn">
            <AlertTriangle className="h-4 w-4" /> {warn} warnings
          </div>
        )}
        {fail > 0 && (
          <div className="flex items-center gap-2 rounded-xl border border-fail/20 bg-fail-soft px-3 py-1.5 text-sm font-semibold text-fail">
            <XCircle className="h-4 w-4" /> {fail} failed
          </div>
        )}
      </div>

      {/* Accordion sections */}
      <div className="space-y-3">
        {keys.map((key, idx) => (
          <AccordionSection
            key={key}
            catKey={key}
            index={idx}
            items={grouped[key] || []}
          />
        ))}
      </div>
    </div>
  );
}
