'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { Smartphone, Trash2, ChevronRight, Apple, Clock, BarChart3, Search } from 'lucide-react';
import { DeviceItem, deleteDevice, fetchAllDevices } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { VerdictPill } from '@/components/ui/VerdictPill';
import { cn } from '@/lib/utils';

export default function DevicesPage() {
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  const filteredDevices = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return devices;
    return devices.filter((d) =>
      (d.manufacturer || '').toLowerCase().includes(q) ||
      (d.model || '').toLowerCase().includes(q) ||
      (d.serial || '').toLowerCase().includes(q)
    );
  }, [devices, query]);

  const load = async () => {
    setLoading(true);
    setDevices(await fetchAllDevices());
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const remove = async (id: string) => {
    const ok = await deleteDevice(id);
    if (ok) {
      setDevices((prev) => prev.filter((d) => d.id !== id));
      setConfirmDeleteId(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold tracking-tight text-ink">Device history</h1>
        <p className="mt-2 max-w-xl text-[15px] leading-relaxed text-muted">
          Every scanned device stays here for auditing. Delete a device to wipe all its reports from the database.
        </p>
      </motion.div>

      {!loading && devices.length > 0 && (
        <div className="relative max-w-sm">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search manufacturer, model, serial…"
            className="w-full rounded-xl border border-line bg-white py-2.5 pl-9 pr-3 text-sm text-ink placeholder:text-muted focus:border-brand/40 focus:outline-none focus:ring-2 focus:ring-brand/20"
          />
        </div>
      )}

      {loading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="h-48 skeleton rounded-2xl" />
          ))}
        </div>
      ) : devices.length === 0 ? (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="panel flex flex-col items-center justify-center px-6 py-20 text-center"
        >
          <div className="flex h-20 w-20 items-center justify-center rounded-3xl bg-canvas shadow-soft">
            <Smartphone className="h-9 w-9 text-slate-300" />
          </div>
          <p className="mt-5 text-base font-semibold text-ink">No devices in history</p>
          <p className="mt-1 text-sm text-muted">Run a scan from the dashboard to see devices here.</p>
          <Link href="/" className="mt-5 btn-primary text-sm">
            Go to dashboard
          </Link>
        </motion.div>
      ) : filteredDevices.length === 0 ? (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="panel flex flex-col items-center justify-center px-6 py-20 text-center"
        >
          <div className="flex h-20 w-20 items-center justify-center rounded-3xl bg-canvas shadow-soft">
            <Search className="h-9 w-9 text-slate-300" />
          </div>
          <p className="mt-5 text-base font-semibold text-ink">No devices match your search</p>
          <p className="mt-1 text-sm text-muted">Try a different manufacturer, model, or serial.</p>
        </motion.div>
      ) : (
        <motion.div
          className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3"
          initial="hidden"
          animate="show"
          variants={{ hidden: {}, show: { transition: { staggerChildren: 0.06 } } }}
        >
          {filteredDevices.map((device) => {
            const PlatIcon = device.platform === 'ios' ? Apple : Smartphone;
            return (
              <motion.div
                key={device.id}
                variants={{
                  hidden: { opacity: 0, y: 12 },
                  show: { opacity: 1, y: 0, transition: { duration: 0.3 } },
                }}
                className="panel flex flex-col gap-4 p-5"
              >
                {/* Device header */}
                <div className="flex items-start gap-3">
                  <div className={cn(
                    'flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl',
                    device.platform === 'ios' ? 'bg-blue-50 text-blue-600' : 'bg-brand-soft text-brand'
                  )}>
                    <PlatIcon className="h-5 w-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <h2 className="font-semibold text-ink truncate">
                      {device.manufacturer} {device.model}
                    </h2>
                    <p className="font-mono text-[11px] text-muted truncate">{device.serial}</p>
                  </div>
                  {device.last_verdict && <VerdictPill verdict={device.last_verdict} className="shrink-0" />}
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-xl bg-canvas p-3">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-muted">OS</p>
                    <p className="mt-0.5 text-sm font-medium text-ink">{device.os_version || '—'}</p>
                  </div>
                  <div className="rounded-xl bg-canvas p-3">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-muted">Patch</p>
                    <p className="mt-0.5 text-sm font-medium text-ink truncate">{device.security_patch || 'n/a'}</p>
                  </div>
                  <div className="rounded-xl bg-canvas p-3">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-muted">IMEI</p>
                    <p className="mt-0.5 text-sm font-medium text-ink truncate">{device.imei || device.imei_slot2 || '—'}</p>
                  </div>
                  <div className="rounded-xl bg-canvas p-3">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-muted">SIM</p>
                    <p className="mt-0.5 text-sm font-medium text-ink truncate">
                      {[device.phone_number, device.phone_number_slot2].filter(Boolean).join(' · ') || device.sim_operator || '—'}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 text-xs text-muted">
                  <span className="flex items-center gap-1.5">
                    <BarChart3 className="h-3.5 w-3.5" />
                    {device.total_scans} report{device.total_scans !== 1 ? 's' : ''}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5" />
                    {formatDate(device.last_scanned_at)}
                  </span>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 border-t border-line pt-3">
                  <Link
                    href={`/devices/${device.id}`}
                    className="flex flex-1 items-center justify-center gap-1.5 rounded-xl border border-line bg-white px-3 py-2 text-xs font-medium text-ink hover:border-brand/30 hover:bg-canvas transition-colors"
                  >
                    View reports
                    <ChevronRight className="h-3.5 w-3.5" />
                  </Link>

                  <AnimatePresence mode="wait">
                    {confirmDeleteId === device.id ? (
                      <motion.div
                        key="confirm"
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        className="flex items-center gap-1.5"
                      >
                        <button
                          type="button"
                          onClick={() => remove(device.id)}
                          className="rounded-xl bg-fail px-3 py-2 text-xs font-semibold text-white hover:bg-fail-dark transition-colors"
                        >
                          Confirm
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmDeleteId(null)}
                          className="rounded-xl border border-line bg-white px-3 py-2 text-xs font-medium text-muted hover:bg-canvas transition-colors"
                        >
                          Cancel
                        </button>
                      </motion.div>
                    ) : (
                      <motion.button
                        key="delete"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        type="button"
                        onClick={() => setConfirmDeleteId(device.id)}
                        className="flex items-center gap-1.5 rounded-xl border border-line bg-white px-3 py-2 text-xs font-medium text-fail hover:bg-fail-soft hover:border-fail/30 transition-colors"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Delete
                      </motion.button>
                    )}
                  </AnimatePresence>
                </div>
              </motion.div>
            );
          })}
        </motion.div>
      )}
    </div>
  );
}
