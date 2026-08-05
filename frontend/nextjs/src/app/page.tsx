'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Cable,
  Download,
  Play,
  RefreshCw,
  Smartphone,
  StopCircle,
  Trash2,
  Usb,
  ChevronRight,
  AlertCircle,
  Zap,
  Search,
  Apple,
  MonitorSmartphone,
  BarChart3,
  CheckCircle2,
  Clock,
  Shield,
  Gauge,
} from 'lucide-react';
import {
  ConnectedDevice,
  ScanItem,
  cancelLiveScan,
  deleteScan,
  fetchAllScans,
  fetchConnectedDevices,
  fetchScanLogs,
  fetchScanStatus,
  pdfUrl,
  triggerLiveScan,
} from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { VerdictPill } from '@/components/ui/VerdictPill';

const stagger = {
  container: { hidden: {}, show: { transition: { staggerChildren: 0.05 } } },
  item: { hidden: { opacity: 0, y: 10 }, show: { opacity: 1, y: 0, transition: { duration: 0.3 } } },
};

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [connected, setConnected] = useState<ConnectedDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [mode, setMode] = useState<'quick' | 'minimal' | 'deep'>('minimal');
  const [vtEnabled, setVtEnabled] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [jobInfo, setJobInfo] = useState<{ pid?: number } | null>(null);
  const [elapsedSec, setElapsedSec] = useState(0);
  const [logs, setLogs] = useState('');
  const [showLogs, setShowLogs] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);
  const [query, setQuery] = useState('');

  useEffect(() => { setMounted(true); }, []);

  const load = useCallback(async (soft = false) => {
    if (soft) setRefreshing(true);
    else setLoading(true);
    const [scanData, live] = await Promise.all([fetchAllScans(), fetchConnectedDevices()]);
    setScans(scanData);
    setConnected(live);
    setLoading(false);
    setRefreshing(false);
  }, []);

  // Auto-select a device only once, the first time the list goes from empty to non-empty.
  // Guarded by a ref (not just `!selected`) so the 8s poll below can never silently
  // re-trigger this and clobber a manual selection made after the initial auto-pick.
  const hasAutoSelected = useRef(false);
  useEffect(() => {
    if (hasAutoSelected.current) return;
    if (selected || connected.length === 0) return;
    const ready = connected.find((d) => d.ready) || connected[0];
    setSelected(ready.serial);
    hasAutoSelected.current = true;
  }, [connected, selected]);

  // If the currently-selected device disconnects, clear the selection so the
  // effect above can auto-select one of the remaining devices.
  useEffect(() => {
    if (selected && connected.length > 0 && !connected.some((d) => d.serial === selected)) {
      setSelected(null);
      hasAutoSelected.current = false;
    }
  }, [connected, selected]);

  useEffect(() => {
    fetchScanStatus().then((s) => {
      if (s.running) {
        setScanning(true);
        setMessage(s.message || 'Scan in progress…');
        setJobInfo({ pid: s.pid });
        if (s.mode === 'quick' || s.mode === 'minimal' || s.mode === 'deep') setMode(s.mode as 'quick' | 'minimal' | 'deep');
        if (s.started_at) setElapsedSec(Math.floor((Date.now() - new Date(s.started_at).getTime()) / 1000));
      }
    });
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(() => load(true), 8000);
    return () => clearInterval(id);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!scanning) { setElapsedSec(0); return; }
    const id = setInterval(() => setElapsedSec((p) => p + 1), 1000);
    return () => clearInterval(id);
  }, [scanning]);

  useEffect(() => {
    if (!scanning) return;
    const id = setInterval(async () => {
      const s = await fetchScanStatus();
      setJobInfo({ pid: s.pid });
      setMessage(s.message || 'Scan in progress…');
      if (s.mode === 'quick' || s.mode === 'minimal' || s.mode === 'deep') setMode(s.mode as 'quick' | 'minimal' | 'deep');
      if (s.started_at) setElapsedSec(Math.floor((Date.now() - new Date(s.started_at).getTime()) / 1000));
      if (!s.running) {
        setScanning(false);
        setJobInfo(null);
        setShowLogs(false);
        load(true);
      }
      if (showLogs) {
        const l = await fetchScanLogs();
        if (l) setLogs(l);
      }
    }, 3000);
    return () => clearInterval(id);
  }, [scanning, showLogs]); // eslint-disable-line react-hooks/exhaustive-deps

  const active = connected.find((d) => d.serial === selected) || connected[0];
  const canScan = Boolean(active?.ready);

  const startScan = async () => {
    if (!canScan) { setMessage('Connect a phone over USB and allow debugging first.'); return; }
    setScanning(true);
    setMessage(null);
    setJobInfo(null);
    const platform = active?.platform === 'ios' ? 'ios' : active?.platform === 'android' ? 'android' : 'auto';
    const res = await triggerLiveScan(mode, platform, active?.serial, vtEnabled);
    if (res.error) { setMessage(res.error); setScanning(false); return; }
    setMessage(`Scan started (PID ${res.pid})`);
    setJobInfo({ pid: res.pid });
  };

  const cancelScan = async () => {
    const res = await cancelLiveScan();
    setMessage(res.message || 'Scan cancelled');
    setScanning(false);
    setJobInfo(null);
    load(true);
  };

  const removeScan = async (id: string) => {
    const ok = await deleteScan(id);
    if (ok) {
      setScans((prev) => prev.filter((s) => s.id !== id));
      setConfirmDeleteId(null);
    }
  };

  const approved = scans.filter((s) => s.verdict === 'PASS').length;
  const conditional = scans.filter((s) => s.verdict === 'CONDITIONAL').length;
  const rejected = scans.filter((s) => s.verdict === 'FAIL').length;

  const scanCountBySerial = useMemo(() => {
    const m = new Map<string, number>();
    for (const s of scans) m.set(s.serial, (m.get(s.serial) || 0) + 1);
    return m;
  }, [scans]);

  const grouped = useMemo(() => {
    const bySerial = new Map<string, ScanItem[]>();
    for (const s of scans) {
      const arr = bySerial.get(s.serial) || [];
      arr.push(s);
      bySerial.set(s.serial, arr);
    }
    return Array.from(bySerial.entries()).map(([serial, items]) => ({
      serial,
      items,
      latest: items[0],
    }));
  }, [scans]);

  const filteredGrouped = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return grouped;
    return grouped.filter((g) =>
      g.serial.toLowerCase().includes(q) ||
      g.items.some((s) => s.id.toLowerCase().includes(q) || `${s.manufacturer} ${s.model}`.toLowerCase().includes(q))
    );
  }, [grouped, query]);

  const activeCount = active ? scanCountBySerial.get(active.serial) || 0 : 0;

  return (
    <div className="space-y-8">
      {/* ── Hero ── */}
      <motion.section
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between"
      >
        <div>
          <div className="inline-flex items-center gap-2 rounded-full bg-brand-soft px-3 py-1.5 text-xs font-semibold text-brand-dark">
            <Shield className="h-3.5 w-3.5" />
            BYOD Admission Scanner
          </div>
          <h1 className="mt-3 text-3xl font-bold tracking-tight text-ink sm:text-4xl">
            Mobile Security
          </h1>
          <p className="mt-2 max-w-lg text-[15px] leading-relaxed text-muted">
            Connect a phone, run an 8-category compliance audit, review findings, and download the PDF admission certificate.
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-2 xl:grid-cols-4">
          <StatCard icon={BarChart3} label="Reports" value={scans.length} color="text-brand" bg="bg-brand-soft" />
          <StatCard icon={CheckCircle2} label="Approved" value={approved} color="text-pass" bg="bg-pass-soft" />
          <StatCard icon={Clock} label="Conditional" value={conditional} color="text-warn" bg="bg-warn-soft" />
          <StatCard icon={AlertCircle} label="Rejected" value={rejected} color="text-fail" bg="bg-fail-soft" />
        </div>
      </motion.section>

      {/* ── Device + Scan panel ── */}
      <motion.section
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.06 }}
        className="panel overflow-hidden"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-line px-6 py-4">
          <div>
            <h2 className="text-base font-semibold text-ink flex items-center gap-2">
              <MonitorSmartphone className="h-4 w-4 text-brand" />
              Connected devices
            </h2>
            <p className="mt-0.5 text-sm text-muted">USB phones detected via ADB / usbmux</p>
          </div>
          <button
            type="button"
            onClick={() => load(true)}
            className="btn-ghost py-2 text-xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        <div className="grid lg:grid-cols-[1.15fr_0.85fr]">
          {/* Device list */}
          <div className="border-b border-line p-5 lg:border-b-0 lg:border-r">
            {loading ? (
              <div className="space-y-3">
                {[1, 2].map(i => (
                  <div key={i} className="h-20 skeleton rounded-xl" />
                ))}
              </div>
            ) : connected.length === 0 ? (
              <EmptyConnect />
            ) : (
              <ul className="space-y-2.5">
                <AnimatePresence initial={false}>
                  {connected.map((device) => {
                    const isActive = active?.serial === device.serial;
                    const PlatIcon = device.platform === 'ios' ? Apple : Smartphone;
                    const historyCount = scanCountBySerial.get(device.serial) || 0;
                    return (
                      <motion.li
                        key={device.serial}
                        layout
                        initial={{ opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                      >
                        <button
                          type="button"
                          onClick={() => setSelected(device.serial)}
                          className={`flex w-full items-center gap-4 rounded-2xl border px-4 py-3.5 text-left transition-all duration-150 ${
                            isActive
                              ? 'border-brand/30 bg-brand-soft/40 ring-1 ring-brand/20 shadow-soft'
                              : 'border-line bg-white hover:border-brand/20 hover:bg-canvas'
                          }`}
                        >
                          <span className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl ${
                            device.ready
                              ? 'bg-gradient-to-br from-brand-soft to-brand/10 text-brand'
                              : 'bg-warn-soft text-warn'
                          }`}>
                            <PlatIcon className="h-5 w-5" />
                          </span>
                          <span className="min-w-0 flex-1">
                            <span className="block truncate font-semibold text-ink">{device.label}</span>
                            <span className="mt-0.5 block truncate font-mono text-xs text-muted">{device.serial}</span>
                            {device.os_version && (
                              <span className="mt-0.5 block text-xs text-subtle">
                                {device.platform === 'ios' ? 'iOS' : 'Android'} {device.os_version}
                              </span>
                            )}
                          </span>
                          <span className="flex shrink-0 flex-col items-end gap-1.5">
                            <span className={`rounded-full px-2.5 py-1 text-[11px] font-semibold ${
                              device.ready
                                ? 'bg-pass-soft text-pass'
                                : 'bg-warn-soft text-warn'
                            }`}>
                              {device.ready ? 'Ready' : device.state}
                            </span>
                            {historyCount > 0 && (
                              <Link
                                href={`/devices/dev_${device.serial}`}
                                className="rounded-full border border-line bg-white px-2.5 py-0.5 text-[11px] font-medium text-brand hover:bg-brand-soft transition-colors"
                              >
                                {historyCount} report{historyCount > 1 ? 's' : ''}
                              </Link>
                            )}
                          </span>
                        </button>
                      </motion.li>
                    );
                  })}
                </AnimatePresence>
              </ul>
            )}
          </div>

          {/* Scan controls */}
          <div className="flex flex-col gap-5 bg-canvas/40 p-5">
            <div>
              <h3 className="text-sm font-semibold text-ink">One-click scan</h3>
              <p className="mt-1 text-sm leading-relaxed text-muted">
                {loading || !mounted
                  ? 'Checking connected devices…'
                  : canScan
                    ? `${active?.label} — runs the full 8-category admission checklist.`
                    : 'Plug in a phone, enable USB debugging, then tap scan.'}
              </p>
            </div>

            {/* Mode toggle */}
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted">Scan mode</p>
              <div className="flex gap-2">
                {(['quick', 'minimal', 'deep'] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    disabled={scanning}
                    onClick={() => setMode(m)}
                    className={`flex-1 rounded-xl px-3 py-2.5 text-sm font-semibold capitalize transition-all duration-150 ${
                      mode === m
                        ? 'bg-ink text-white shadow-soft'
                        : 'bg-white text-muted border border-line hover:border-brand/30 hover:text-ink'
                    } ${scanning ? 'cursor-not-allowed opacity-40' : ''}`}
                  >
                    {m === 'quick'
                      ? <><Gauge className="mr-1.5 inline-block h-3.5 w-3.5" />Quick</>
                      : m === 'minimal'
                        ? <><Zap className="mr-1.5 inline-block h-3.5 w-3.5" />Minimal</>
                        : <><Search className="mr-1.5 inline-block h-3.5 w-3.5" />Deep</>}
                  </button>
                ))}
              </div>
              <p className="mt-1.5 text-xs text-muted">
                {mode === 'quick'
                  ? 'Device info, root & lock-screen checks only — fastest triage (best-effort, ~seconds)'
                  : mode === 'minimal'
                    ? 'Offline inventory & integrity checks (~5–15 min)'
                    : 'Minimal + cloud analysis via MobSF (~20–40 min)'}
              </p>
              {mode === 'deep' && (
                <label className="mt-2 flex items-center gap-2 text-xs text-muted">
                  <input
                    type="checkbox"
                    checked={vtEnabled}
                    onChange={(e) => setVtEnabled(e.target.checked)}
                    disabled={scanning}
                    className="rounded border-line text-brand focus:ring-brand/30"
                  />
                  Include VirusTotal lookup (requires API key/quota — opt-in)
                </label>
              )}
            </div>

            {/* Scan action */}
            <div className="space-y-3 mt-auto">
              {scanning ? (
                <div className="space-y-3">
                  {/* Progress indicator */}
                  <div className="rounded-xl border border-warn/20 bg-warn-soft px-4 py-3">
                    <div className="flex items-center gap-3">
                      <span className="relative flex h-3 w-3 shrink-0">
                        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-warn opacity-60" />
                        <span className="relative inline-flex h-3 w-3 rounded-full bg-warn" />
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-warn">
                          {mode === 'deep' ? 'Deep' : mode === 'quick' ? 'Quick' : 'Minimal'} scan running · {formatElapsed(elapsedSec)}
                        </p>
                        {message && <p className="mt-0.5 truncate text-xs text-warn/80">{message}</p>}
                      </div>
                      {jobInfo?.pid && <span className="shrink-0 font-mono text-[11px] text-warn/70">PID {jobInfo.pid}</span>}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button disabled className="flex-1 btn-primary cursor-not-allowed opacity-40">
                      <Play className="h-4 w-4 animate-pulse" />
                      Scanning…
                    </button>
                    <button type="button" onClick={cancelScan} className="btn-danger">
                      <StopCircle className="h-4 w-4" />
                      Cancel
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => { setShowLogs(!showLogs); if (!showLogs) fetchScanLogs().then(setLogs); }}
                    className="flex w-full items-center justify-center gap-1.5 text-xs font-medium text-muted hover:text-ink transition-colors"
                  >
                    <ChevronRight className={`h-3.5 w-3.5 transition-transform ${showLogs ? 'rotate-90' : ''}`} />
                    {showLogs ? 'Hide' : 'Show'} live logs
                  </button>
                  <AnimatePresence>
                    {showLogs && (
                      <motion.pre
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="max-h-48 overflow-auto rounded-xl bg-ink p-3 text-[11px] leading-relaxed text-emerald-300 font-mono whitespace-pre-wrap scrollbar-thin"
                      >
                        {logs || 'Waiting for log output…'}
                      </motion.pre>
                    )}
                  </AnimatePresence>
                </div>
              ) : (
                <>
                  <button
                    type="button"
                    disabled={!canScan}
                    onClick={startScan}
                    className="btn-primary w-full py-3"
                  >
                    <Play className="h-4 w-4" />
                    {loading || !mounted ? 'Checking…' : canScan ? 'Start admission scan' : 'Waiting for device…'}
                  </button>
                  {message && (
                    <p className="rounded-xl bg-white border border-line px-3 py-2 text-xs text-muted leading-relaxed">
                      {message}
                    </p>
                  )}
                  {!canScan && connected.length === 0 && !loading && mounted && (
                    <p className="flex items-start gap-2 text-xs text-warn">
                      <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      No ready device. Enable USB debugging → Allow this computer.
                    </p>
                  )}
                  {canScan && activeCount > 0 && (
                    <p className="flex items-start gap-2 text-xs text-muted">
                      <Clock className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      This device was scanned {activeCount} time{activeCount > 1 ? 's' : ''} already —{' '}
                      <Link href={`/devices/dev_${active.serial}`} className="font-medium text-brand hover:underline">
                        view all reports
                      </Link>
                    </p>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      </motion.section>

      {/* ── Recent reports ── */}
      <motion.section
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.12 }}
        className="space-y-4"
      >
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-ink">Recent reports</h2>
            <p className="mt-0.5 text-sm text-muted">Latest scan per device — open a device to see all its reports.</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="relative w-full sm:w-64">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search report ID, serial, model…"
                className="w-full rounded-xl border border-line bg-white py-2.5 pl-9 pr-3 text-sm text-ink placeholder:text-muted focus:border-brand/40 focus:outline-none focus:ring-2 focus:ring-brand/20"
              />
            </div>
            <Link href="/devices" className="whitespace-nowrap text-sm font-medium text-brand hover:underline hover:text-brand-dark">
              All devices →
            </Link>
          </div>
        </div>

        <div className="panel overflow-hidden">
          {loading ? (
            <div className="divide-y divide-line">
              {[1, 2, 3].map(i => (
                <div key={i} className="flex items-center gap-4 px-5 py-4">
                  <div className="h-4 w-40 skeleton" />
                  <div className="h-6 w-20 skeleton" />
                  <div className="ml-auto h-4 w-24 skeleton" />
                </div>
              ))}
            </div>
          ) : filteredGrouped.length === 0 ? (
            <div className="px-6 py-16 text-center">
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-canvas">
                <Search className="h-7 w-7 text-slate-300" />
              </div>
              <p className="mt-4 text-sm font-semibold text-ink">No reports match your search</p>
              <p className="mt-1 text-sm text-muted">Try a report ID, serial, or model.</p>
            </div>
          ) : (
            <motion.ul
              variants={stagger.container}
              initial="hidden"
              animate="show"
              className="divide-y divide-line max-h-[32rem] overflow-y-auto scrollbar-thin"
            >
              {filteredGrouped.map((g) => {
                const scan = g.latest;
                return (
                  <motion.li
                    key={g.serial}
                    variants={stagger.item}
                    className="group flex flex-col gap-3 px-5 py-4 transition-colors hover:bg-canvas/60 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <Link href={`/scans/${scan.id}`} className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-3">
                        <span className="font-semibold text-ink">
                          {scan.manufacturer} {scan.model}
                        </span>
                        <VerdictPill verdict={scan.verdict} />
                        <span className="rounded-md bg-canvas border border-line px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-muted">
                          {scan.scan_mode || 'minimal'}
                        </span>
                        <span className="rounded-md bg-brand-soft px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-brand">
                          {g.items.length} report{g.items.length > 1 ? 's' : ''}
                        </span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
                        <span className="font-mono">{scan.serial}</span>
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

                      <Link
                        href={`/devices/dev_${g.serial}`}
                        className="inline-flex items-center gap-1 rounded-xl border border-brand/20 bg-brand-soft/50 px-2.5 py-2 text-xs font-semibold text-brand hover:bg-brand-soft transition-colors"
                        title="All reports for this device"
                      >
                        All {g.items.length}
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Link>

                      {/* Inline delete confirm */}
                      <AnimatePresence mode="wait">
                        {confirmDeleteId === scan.id ? (
                          <motion.div
                            key="confirm"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="flex items-center gap-1.5"
                          >
                            <button
                              type="button"
                              onClick={() => removeScan(scan.id)}
                              className="rounded-xl bg-fail px-2.5 py-2 text-xs font-semibold text-white hover:bg-fail-dark transition-colors"
                            >
                              Confirm
                            </button>
                            <button
                              type="button"
                              onClick={() => setConfirmDeleteId(null)}
                              className="rounded-xl border border-line bg-white px-2.5 py-2 text-xs font-medium text-muted hover:bg-canvas transition-colors"
                            >
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

                      <Link
                        href={`/scans/${scan.id}`}
                        className="inline-flex items-center gap-1 rounded-xl bg-ink px-2.5 py-2 text-xs font-semibold text-white hover:bg-ink/80 transition-colors"
                      >
                        Open
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Link>
                    </div>
                  </motion.li>
                );
              })}
            </motion.ul>
          )}
        </div>
      </motion.section>
    </div>
  );
}

function formatElapsed(sec: number): string {
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function cleanIdent(a?: string | null, b?: string | null): string {
  const parts = [a, b].map((v) => (v && String(v).trim() && String(v).trim() !== ',' ? String(v).trim() : '')).filter(Boolean);
  return parts.length ? parts.join(' · ') : '—';
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  bg,
}: {
  icon: typeof BarChart3;
  label: string;
  value: number;
  color: string;
  bg: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-2xl border border-line bg-white px-4 py-3.5 shadow-soft">
      <div className={`flex h-9 w-9 items-center justify-center rounded-xl ${bg}`}>
        <Icon className={`h-4 w-4 ${color}`} />
      </div>
      <div>
        <div className="text-xl font-bold tabular-nums text-ink">{value}</div>
        <div className="text-[11px] font-medium text-muted">{label}</div>
      </div>
    </div>
  );
}

function EmptyConnect() {
  return (
    <div className="rounded-2xl border border-dashed border-line bg-canvas/50 px-6 py-12 text-center">
      <span className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-white shadow-soft">
        <Cable className="h-7 w-7 text-brand" />
      </span>
      <h3 className="mt-4 text-base font-semibold text-ink">Connect a device</h3>
      <p className="mx-auto mt-2 max-w-sm text-sm leading-relaxed text-muted">
        Plug in an Android or iPhone over USB. Enable USB debugging on Android and trust this computer when prompted.
      </p>
      <ol className="mx-auto mt-4 max-w-xs space-y-1.5 text-left text-sm text-muted">
        <li className="flex items-start gap-2">
          <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-soft text-[10px] font-bold text-brand">1</span>
          Connect the phone with a data cable
        </li>
        <li className="flex items-start gap-2">
          <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-soft text-[10px] font-bold text-brand">2</span>
          Allow USB debugging / trust prompt
        </li>
        <li className="flex items-start gap-2">
          <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-soft text-[10px] font-bold text-brand">3</span>
          Press Refresh — device will appear here
        </li>
      </ol>
    </div>
  );
}
