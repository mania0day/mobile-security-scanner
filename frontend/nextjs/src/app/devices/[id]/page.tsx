'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ArrowLeft,
  Download,
  Trash2,
  ChevronRight,
  Apple,
  Smartphone,
  Search,
  ShieldCheck,
  Clock,
  BarChart3,
} from 'lucide-react';
import { DeviceDetail, ScanItem, deleteScan, fetchDeviceDetail, pdfUrl } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { VerdictPill } from '@/components/ui/VerdictPill';
import { cn } from '@/lib/utils';

export default function DeviceReportsPage() {
  const { id } = useParams<{ id: string }>();
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    const d = await fetchDeviceDetail(id);
    setDevice(d);
    setLoading(false);
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const remove = async (scanId: string) => {
    const ok = await deleteScan(scanId);
    if (ok) {
      setDevice((prev) => prev ? { ...prev, scans: prev.scans.filter((s) => s.id !== scanId) } : prev);
      setConfirmDeleteId(null);
    }
  };

  const scans = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return device?.scans || [];
    return (device?.scans || []).filter(
      (s) =>
        s.id.toLowerCase().includes(q) ||
        s.serial.toLowerCase().includes(q) ||
        `${s.manufacturer} ${s.model}`.toLowerCase().includes(q)
    );
  }, [device, query]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-24 skeleton rounded-2xl" />
        <div className="h-16 skeleton rounded-2xl" />
        <div className="h-16 skeleton rounded-2xl" />
      </div>
    );
  }

  if (!device) {
    return (
      <div className="panel flex flex-col items-center justify-center px-6 py-20 text-center">
        <p className="text-base font-semibold text-ink">Device not found</p>
        <Link href="/devices" className="mt-4 text-sm font-medium text-brand hover:underline">
          Back to all devices
        </Link>
      </div>
    );
  }

  const PlatIcon = device.platform === 'ios' ? Apple : Smartphone;

  const cleanIdent = (a?: string | null, b?: string | null) => {
    const parts = [a, b].map((v) => (v && String(v).trim() && String(v).trim() !== ',' ? String(v).trim() : '')).filter(Boolean);
    return parts.length ? parts.join(' · ') : '—';
  };

  return (
    <div className="space-y-8">
      {/* Back + header */}
      <div>
        <Link href="/devices" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink transition-colors">
          <ArrowLeft className="h-3.5 w-3.5" />
          All devices
        </Link>
        <div className="mt-3 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3.5">
            <span className={cn(
              'flex h-14 w-14 items-center justify-center rounded-2xl',
              device.platform === 'ios' ? 'bg-blue-50 text-blue-600' : 'bg-brand-soft text-brand'
            )}>
              <PlatIcon className="h-6 w-6" />
            </span>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-ink">
                {device.manufacturer} {device.model}
              </h1>
              <p className="mt-0.5 font-mono text-xs text-muted">{device.serial}</p>
            </div>
            {device.last_verdict && <VerdictPill verdict={device.last_verdict} className="sm:ml-1" />}
          </div>
          <div className="flex items-center gap-3 text-xs text-muted">
            <span className="flex items-center gap-1.5">
              <BarChart3 className="h-3.5 w-3.5" />
              {device.total_scans} report{device.total_scans !== 1 ? 's' : ''}
            </span>
            <span className="flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5" />
              Last {formatDate(device.last_scanned_at)}
            </span>
          </div>
        </div>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {[
          { label: 'Platform', value: device.platform === 'ios' ? 'iOS' : 'Android' },
          { label: 'OS version', value: device.os_version || '—' },
          { label: 'Security patch', value: device.security_patch || 'n/a' },
          { label: 'IMEI', value: device.imei || device.imei_slot2 || '—' },
          { label: 'IMEI (SIM 2)', value: device.imei_slot2 || '—' },
          { label: 'SIM', value: cleanIdent(device.phone_number, device.phone_number_slot2) },
        ].map((s) => (
          <div key={s.label} className="rounded-2xl border border-line bg-white px-4 py-3 shadow-soft">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-muted">{s.label}</p>
            <p className="mt-1 truncate font-mono text-sm font-semibold text-ink">{s.value}</p>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="text-lg font-semibold text-ink">All reports for this device</h2>
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by report ID or serial…"
            className="w-full rounded-xl border border-line bg-white py-2.5 pl-9 pr-3 text-sm text-ink placeholder:text-muted focus:border-brand/40 focus:outline-none focus:ring-2 focus:ring-brand/20"
          />
        </div>
      </div>

      {/* Reports list */}
      <div className="panel overflow-hidden">
        {scans.length === 0 ? (
          <div className="px-6 py-16 text-center">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-canvas">
              <ShieldCheck className="h-7 w-7 text-slate-300" />
            </div>
            <p className="mt-4 text-sm font-semibold text-ink">
              {device.total_scans === 0 ? 'No reports for this device yet' : 'No reports match your search'}
            </p>
            <p className="mt-1 text-sm text-muted">
              {device.total_scans === 0 ? 'Run a scan from the dashboard after connecting this device.' : 'Try a different report ID or serial.'}
            </p>
          </div>
        ) : (
          <motion.ul
            initial="hidden"
            animate="show"
            variants={{ hidden: {}, show: { transition: { staggerChildren: 0.04 } } }}
            className="divide-y divide-line max-h-[36rem] overflow-y-auto scrollbar-thin"
          >
            <AnimatePresence initial={false}>
              {scans.map((scan) => (
                <motion.li
                  key={scan.id}
                  variants={{ hidden: { opacity: 0, y: 8 }, show: { opacity: 1, y: 0 } }}
                  exit={{ opacity: 0 }}
                  className="group flex flex-col gap-3 px-5 py-4 transition-colors hover:bg-canvas/60 sm:flex-row sm:items-center sm:justify-between"
                >
                  <Link href={`/scans/${scan.id}`} className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="font-mono text-xs text-muted">{scan.id}</span>
                      <VerdictPill verdict={scan.verdict} />
                      <span className="rounded-md bg-canvas border border-line px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-muted">
                        {scan.scan_mode || 'minimal'}
                      </span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
                      <span>Score <span className="font-semibold text-ink">{scan.overall_score}</span>/100</span>
                      <span>{scan.total_apps_scanned} apps</span>
                      <span>{formatDate(scan.created_at)}</span>
                      <span title="Device IMEI (slot 1 / slot 2)">
                        <span className="font-medium text-ink">IMEI:</span> {cleanIdent(scan.imei, scan.imei_slot2)}
                      </span>
                      <span title="SIM numbers (slot 1 / slot 2)">
                        <span className="font-medium text-ink">SIM:</span> {cleanIdent(scan.phone_number, scan.phone_number_slot2)}
                      </span>
                    </div>
                  </Link>

                  <div className="flex items-center gap-2 shrink-0">
                    <div className="flex overflow-hidden rounded-xl border border-line bg-white">
                      <a
                        href={pdfUrl(scan.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-2 text-xs font-medium text-ink hover:bg-canvas transition-colors"
                        title="Full report with IMEI, phone, SIM"
                      >
                        <Download className="h-3.5 w-3.5" />
                        Full
                      </a>
                      <span className="w-px bg-line" />
                      <a
                        href={pdfUrl(scan.id, true)}
                        className="inline-flex items-center gap-1 px-2.5 py-2 text-xs font-medium text-muted hover:bg-canvas hover:text-ink transition-colors"
                        title="Safe report — no IMEI, phone, or SIM data"
                      >
                        <Download className="h-3.5 w-3.5" />
                        Safe
                      </a>
                    </div>

                    <AnimatePresence mode="wait">
                      {confirmDeleteId === scan.id ? (
                        <motion.div key="confirm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex items-center gap-1.5">
                          <button type="button" onClick={() => remove(scan.id)} className="rounded-xl bg-fail px-2.5 py-2 text-xs font-semibold text-white hover:bg-fail-dark transition-colors">
                            Confirm
                          </button>
                          <button type="button" onClick={() => setConfirmDeleteId(null)} className="rounded-xl border border-line bg-white px-2.5 py-2 text-xs font-medium text-muted hover:bg-canvas transition-colors">
                            Cancel
                          </button>
                        </motion.div>
                      ) : (
                        <button
                          key="delete"
                          type="button"
                          onClick={() => setConfirmDeleteId(scan.id)}
                          className="inline-flex items-center gap-1 rounded-xl border border-line bg-white px-2.5 py-2 text-xs font-medium text-fail hover:bg-fail-soft hover:border-fail/30 transition-colors"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </AnimatePresence>

                    <Link href={`/scans/${scan.id}`} className="inline-flex items-center gap-1 rounded-xl bg-ink px-2.5 py-2 text-xs font-semibold text-white hover:bg-ink/80 transition-colors">
                      Open
                      <ChevronRight className="h-3.5 w-3.5" />
                    </Link>
                  </div>
                </motion.li>
              ))}
            </AnimatePresence>
          </motion.ul>
        )}
      </div>
    </div>
  );
}
