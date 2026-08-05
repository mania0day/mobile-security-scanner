'use client';

import { useMemo, useState, useRef, useEffect, type ReactNode } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ArrowLeft,
  Download,
  Trash2,
  ShieldAlert,
  Activity,
  Network,
  FileSearch,
  Tags,
  Clock3,
  ChevronRight,
  Apple,
  Smartphone,
  Cpu,
  Calendar,
  Hash,
  Layers,
  AlertCircle,
  CheckCircle2,
  Fingerprint,
  Bug,
} from 'lucide-react';
import { ScanDetails, pdfUrl } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { VerdictPill } from '@/components/ui/VerdictPill';
import { ScoreRing, categoryLabel } from '@/components/report/ScoreRing';
import { ChecklistPanel } from '@/components/checklist/ChecklistPanel';

const RiskDistributionChart = dynamic(
  () => import('@/components/report/ReportCharts').then((m) => m.RiskDistributionChart),
  { ssr: false, loading: () => <ChartSkeleton /> }
);
const CategoryHealthChart = dynamic(
  () => import('@/components/report/ReportCharts').then((m) => m.CategoryHealthChart),
  { ssr: false, loading: () => <ChartSkeleton /> }
);
const TopAppsChart = dynamic(
  () => import('@/components/report/ReportCharts').then((m) => m.TopAppsChart),
  { ssr: false, loading: () => <ChartSkeleton /> }
);

function ChartSkeleton() {
  return <div className="h-52 w-full animate-shimmer rounded-xl bg-gradient-to-r from-slate-100 via-slate-50 to-slate-100 bg-[length:200%_100%]" />;
}

const stagger = {
  container: { hidden: {}, show: { transition: { staggerChildren: 0.04 } } },
  item: { hidden: { opacity: 0, x: -8 }, show: { opacity: 1, x: 0, transition: { duration: 0.25 } } },
};

type Tab = 'overview' | 'checklist' | 'apps' | 'findings';

const TAB_DEFS: { id: Tab; label: string; icon: typeof Activity }[] = [
  { id: 'overview',  label: 'Overview',      icon: Activity },
  { id: 'checklist', label: 'Checklist',     icon: ShieldAlert },
  { id: 'apps',      label: 'Applications',  icon: Network },
  { id: 'findings',  label: 'Findings',      icon: FileSearch },
];

export function ProfessionalReport({
  scan,
  onDelete,
}: {
  scan: ScanDetails;
  onDelete: () => void;
}) {
  const [tab, setTab] = useState<Tab>('overview');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const [indicator, setIndicator] = useState({ left: 0, width: 0 });

  // Animate tab indicator
  useEffect(() => {
    const activeIdx = TAB_DEFS.findIndex(t => t.id === tab);
    const el = tabRefs.current[activeIdx];
    if (el) {
      setIndicator({ left: el.offsetLeft, width: el.offsetWidth });
    }
  }, [tab]);

  const stats = useMemo(() => {
    const checklist = scan.checklist || [];
    const apps = scan.app_findings || [];
    const pass = checklist.filter((c) => c.status === 'PASS').length;
    const warn = checklist.filter((c) => c.status === 'WARNING').length;
    const fail = checklist.filter((c) => c.status === 'FAIL').length;
    const mustFails = checklist.filter((c) => c.priority === 'Must' && c.status === 'FAIL');
    const byLevel = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const a of apps) {
      const k = (a.risk_level || 'LOW').toUpperCase() as keyof typeof byLevel;
      if (k in byLevel) byLevel[k] += 1;
    }
    return { pass, warn, fail, mustFails, byLevel, apps, checklist };
  }, [scan]);

  const riskyApps = useMemo(
    () => [...(scan.app_findings || [])].filter((a) => a.risk_score > 0).sort((a, b) => b.risk_score - a.risk_score),
    [scan]
  );

  // Apps flagged as genuine potential threats, not just "has some risk score".
  // Two independent signals, both evidence-based rather than permission-count
  // noise: (1) a YARA rule matched at high/critical severity — an actual
  // malware-pattern hit, not a permission declaration; (2) the app combines
  // Accessibility-service binding with Device Admin or Overlay — the classic
  // screen-read + auto-click + draw-over-UI combination used by real Android
  // banking trojans/spyware (Anubis, Cerberus, etc.), mirroring the same
  // combination rule the backend's Must-fail checklist check uses.
  const threats = useMemo(() => {
    return (scan.app_findings || [])
      .map((a) => {
        const factors = a.risk_factors || [];
        const yaraHits = factors.filter((f) => /^YARA:.*\((critical|high)\)/i.test(f));
        const perms = (a.critical_permissions || []).join(' ').toUpperCase();
        const hasAccessibility = perms.includes('ACCESSIBILITY');
        const hasCompanion = perms.includes('DEVICE_ADMIN') || perms.includes('SYSTEM_ALERT') || perms.includes('OVERLAY');
        const spywareCombo = hasAccessibility && hasCompanion;
        const reasons = [
          ...yaraHits.map((h) => h.replace(/^YARA:\s*/, '')),
          ...(spywareCombo ? ['Accessibility-service binding combined with Device Admin/Overlay — spyware-like pattern'] : []),
        ];
        return { app: a, reasons };
      })
      .filter((t) => t.reasons.length > 0)
      .sort((a, b) => b.app.risk_score - a.app.risk_score);
  }, [scan]);

  const tags = useMemo(
    () => buildTags(scan, stats.mustFails.length, stats.warn, stats.fail, threats.length),
    [scan, stats, threats]
  );

  const cve = useMemo(() => {
    const raw = scan.cve_findings;
    if (!raw || typeof raw !== 'object') return null;
    return {
      meta: raw,
      cves: Array.isArray(raw.cves) ? raw.cves : [],
    };
  }, [scan.cve_findings]);

  const findings = useMemo(() => {
    const rows: { severity: string; title: string; detail: string; category: string }[] = [];
    for (const c of scan.checklist || []) {
      if (c.status === 'PASS') continue;
      rows.push({ severity: c.status === 'FAIL' ? 'CRITICAL' : 'MEDIUM', title: c.check_name, detail: c.details || '', category: categoryLabel(c.category) });
    }
    for (const a of riskyApps.slice(0, 15)) {
      if ((a.risk_level || '').toUpperCase() === 'LOW') continue;
      rows.push({ severity: a.risk_level, title: a.package_name, detail: (a.risk_factors || []).slice(0, 3).join(' · ') || `Score ${a.risk_score}`, category: 'Application' });
    }
    const order = { CRITICAL: 0, HIGH: 1, FAIL: 0, MEDIUM: 2, WARNING: 2, LOW: 3 };
    return rows.sort((a, b) => (order[a.severity.toUpperCase() as keyof typeof order] ?? 9) - (order[b.severity.toUpperCase() as keyof typeof order] ?? 9));
  }, [scan, riskyApps]);

  const verdictBg =
    scan.verdict === 'FAIL'        ? 'from-fail-soft to-white border-fail/20' :
    scan.verdict === 'CONDITIONAL' ? 'from-warn-soft to-white border-warn/20' :
    'from-pass-soft to-white border-pass/20';

  const PlatIcon = scan.platform === 'ios' ? Apple : Smartphone;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">

      {/* ── Top bar ── */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <Link href="/" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink transition-colors">
            <ArrowLeft className="h-3.5 w-3.5" />
            Dashboard
          </Link>
          <h1 className="mt-2 text-2xl font-bold tracking-tight text-ink sm:text-3xl">Analysis report</h1>
          <p className="mt-1 flex items-center gap-2 text-sm text-muted">
            <PlatIcon className="h-4 w-4 text-brand" />
            {scan.manufacturer} {scan.model}
            <span className="text-line">·</span>
            <span className="font-mono text-xs">{scan.serial}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <a
            href={pdfUrl(scan.id, false, true)}
            className="btn-primary"
          >
            <Download className="h-4 w-4" />
            One-pager PDF
          </a>
          <a
            href={pdfUrl(scan.id)}
            className="btn-secondary"
          >
            <Download className="h-4 w-4" />
            Full PDF
          </a>
          <a
            href={pdfUrl(scan.id, true)}
            className="btn-secondary"
          >
            <Download className="h-4 w-4" />
            Safe PDF
          </a>
          <AnimatePresence mode="wait">
            {confirmDelete ? (
              <motion.div
                key="confirm"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="flex items-center gap-2"
              >
                <button
                  type="button"
                  onClick={onDelete}
                  className="rounded-xl bg-fail px-4 py-2.5 text-sm font-semibold text-white hover:bg-fail-dark transition-colors"
                >
                  Confirm delete
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmDelete(false)}
                  className="btn-ghost"
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
                onClick={() => setConfirmDelete(true)}
                className="btn-danger"
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </motion.button>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* ── Hero card ── */}
      <section className={`panel overflow-hidden border bg-gradient-to-br ${verdictBg}`}>
        <div className="grid gap-0 lg:grid-cols-[200px_1fr]">
          {/* Score ring */}
          <div className="flex flex-col items-center justify-center gap-4 border-b border-line/60 bg-white/60 px-6 py-8 lg:border-b-0 lg:border-r">
            <ScoreRing score={scan.overall_score} label="Score" size={148} />
            <VerdictPill verdict={scan.verdict} className="text-sm px-4 py-1.5" />
          </div>

          {/* Metadata */}
          <div className="p-6 space-y-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="section-label">Device</p>
                <p className="mt-1 text-xl font-bold text-ink">{scan.manufacturer} {scan.model}</p>
                <p className="mt-0.5 font-mono text-xs text-muted">{scan.id}</p>
              </div>
              <div className="flex items-center gap-1.5 rounded-xl bg-white/70 border border-line px-3 py-2 text-xs text-muted shadow-soft">
                <Clock3 className="h-3.5 w-3.5" />
                {formatDate(scan.created_at)}
              </div>
            </div>

            {/* Tags */}
            <div className="flex flex-wrap items-center gap-2">
              <Tags className="h-4 w-4 text-muted shrink-0" />
              {tags.map((tag) => (
                <span
                  key={tag.label}
                  className="rounded-md px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide"
                  style={{ background: tag.bg, color: tag.fg }}
                >
                  {tag.label}
                </span>
              ))}
            </div>

            {/* Metadata grid */}
            <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <MetaItem icon={PlatIcon} label="Platform" value={scan.platform} />
              <MetaItem icon={Cpu} label="OS version" value={scan.os_version || '—'} />
              <MetaItem icon={Calendar} label="Security patch" value={scan.security_patch || '—'} />
              <MetaItem icon={Layers} label="Scan mode" value={scan.scan_mode} />
              <MetaItem icon={Network} label="Apps audited" value={String(scan.total_apps_scanned)} />
              <MetaItem icon={AlertCircle} label="Critical apps" value={String(scan.critical_apps_count)} />
              <MetaItem icon={CheckCircle2} label="Checks passed" value={`${stats.pass}/${stats.checklist.length}`} />
              <MetaItem icon={Hash} label="Must failures" value={String(stats.mustFails.length)} />
            </dl>

            {/* Device identity — IMEI / SIM (only when collected) */}
            {(() => {
              const clean = (v?: string | null) =>
                v == null || !String(v).trim() || String(v).trim() === ',' ? undefined : String(v).trim();
              const identity = {
                imei: clean(scan.imei),
                imei_slot2: clean(scan.imei_slot2),
                meid: clean(scan.meid),
                phone_number: clean(scan.phone_number),
                sim_operator: clean(scan.sim_operator),
                sim_serial: clean(scan.sim_serial),
              };
              if (!Object.values(identity).some(Boolean)) return null;
              return (
                <div className="rounded-xl border border-line bg-white/50 p-3.5 shadow-soft">
                  <dt className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted">
                    <Fingerprint className="h-3 w-3 shrink-0" />
                    Device identity
                  </dt>
                  <dl className="mt-2 grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                    <IdentityItem label="IMEI" value={identity.imei} />
                    <IdentityItem label="IMEI (SIM 2)" value={identity.imei_slot2} />
                    <IdentityItem label="MEID" value={identity.meid} />
                    <IdentityItem label="Phone number" value={identity.phone_number} />
                    <IdentityItem label="SIM operator" value={identity.sim_operator} />
                    <IdentityItem label="SIM serial" value={identity.sim_serial} />
                  </dl>
                </div>
              );
            })()}

            {/* CVE exposure summary */}
            {cve && (
              <div className="rounded-xl border border-line bg-white/50 p-3.5 shadow-soft">
                <dt className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted">
                  <AlertCircle className="h-3 w-3 shrink-0" />
                  CVE exposure · patch {cve.meta.security_patch || scan.security_patch || '—'}
                </dt>
                <dl className="mt-2 grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                  <IdentityItem label="Unpatched" value={String(cve.meta.total_unpatched ?? '—')} />
                  <IdentityItem label="Critical" value={String(cve.meta.critical_count ?? '—')} />
                  <IdentityItem label="High" value={String(cve.meta.high_count ?? '—')} />
                  <IdentityItem label="Level" value={cve.meta.overall_level || '—'} />
                </dl>
              </div>
            )}

            {/* Executive summary */}
            <div className="rounded-xl border border-line bg-white/70 px-4 py-3.5 text-sm leading-relaxed text-muted shadow-soft">
              <span className="font-semibold text-ink">Executive summary. </span>
              {executiveSummary(scan, stats)}
            </div>
          </div>
        </div>
      </section>

      {/* ── Tab bar with sliding indicator ── */}
      <div className="relative flex rounded-2xl border border-line bg-panel p-1 shadow-soft">
        {/* Sliding pill */}
        <motion.div
          className="absolute top-1 bottom-1 rounded-xl bg-ink shadow-soft"
          animate={{ left: indicator.left, width: indicator.width }}
          transition={{ type: 'spring', stiffness: 400, damping: 30 }}
          style={{ left: indicator.left, width: indicator.width }}
        />
        {TAB_DEFS.map((t, i) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              ref={(el) => { tabRefs.current[i] = el; }}
              type="button"
              onClick={() => setTab(t.id)}
              className={`relative z-10 inline-flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2.5 text-sm font-medium whitespace-nowrap transition-colors duration-150 ${
                active ? 'text-white' : 'text-muted hover:text-ink'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">{t.label}</span>
              {t.id === 'apps' && threats.length > 0 && (
                <motion.span
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 500, damping: 20 }}
                  className={`ml-0.5 flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[10px] font-bold ${
                    active ? 'bg-white text-fail' : 'bg-fail text-white'
                  }`}
                >
                  {threats.length}
                </motion.span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Tab content ── */}
      <AnimatePresence mode="wait">
        {tab === 'overview' && (
          <motion.div key="overview" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-6">
            {/* Potential threats — evidence-based apps only (YARA critical/high hit,
                or Accessibility-service binding combined with Device Admin/Overlay) */}
            {threats.length > 0 && (
              <motion.section
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}
                className="panel overflow-hidden border-fail/20"
              >
                <div className="flex items-center gap-3 border-b border-fail/15 bg-fail-soft/40 px-5 py-4">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-fail-soft text-fail">
                    <Bug className="h-4.5 w-4.5" />
                  </span>
                  <div>
                    <h3 className="text-sm font-semibold text-fail-dark">Potential threats · {threats.length} app{threats.length > 1 ? 's' : ''}</h3>
                    <p className="mt-0.5 text-xs text-muted">
                      Spyware-like permission combinations or high/critical malware-pattern matches — review before admission
                    </p>
                  </div>
                </div>
                <motion.ul
                  variants={stagger.container}
                  initial="hidden"
                  animate="show"
                  className="divide-y divide-line"
                >
                  {threats.slice(0, 12).map(({ app, reasons }) => (
                    <motion.li key={app.id} variants={stagger.item} className="flex items-start gap-3 px-5 py-3.5">
                      <SeverityBadge level={app.risk_level} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-mono text-xs font-semibold text-ink">{app.package_name}</p>
                        <ul className="mt-1 space-y-0.5">
                          {reasons.map((r, i) => (
                            <li key={i} className="text-xs text-muted">· {r}</li>
                          ))}
                        </ul>
                      </div>
                      <span className="shrink-0 tabular-nums text-xs font-bold text-fail">{app.risk_score}</span>
                    </motion.li>
                  ))}
                </motion.ul>
                {threats.length > 12 && (
                  <p className="border-t border-line px-5 py-2.5 text-xs text-muted">
                    +{threats.length - 12} more — see the Applications tab, sorted by risk score.
                  </p>
                )}
              </motion.section>
            )}

            {/* Charts grid */}
            <div className="grid gap-5 lg:grid-cols-2">
              <ChartCard title="Application risk distribution" subtitle="Severity distribution across inventoried packages">
                <RiskDistributionChart apps={stats.apps} />
              </ChartCard>
              <ChartCard title="Category health" subtitle="Admission checklist health score by category (0–100%)">
                <CategoryHealthChart checklist={stats.checklist} />
              </ChartCard>
            </div>

            <ChartCard title="Top-risk packages" subtitle="Highest-scoring applications by risk score">
              <TopAppsChart apps={riskyApps} />
            </ChartCard>

            {/* CVE exposure panel */}
            {cve && (
              <section className="panel overflow-hidden">
                <div className="border-b border-line px-5 py-4">
                  <h3 className="text-sm font-semibold text-ink">Known CVEs beyond security patch</h3>
                  <p className="mt-0.5 text-xs text-muted">
                    {cve.meta.os_eol
                      ? `OS is end-of-life (${cve.meta.android_version || scan.os_version}) — ${cve.meta.os_eol_details || 'no longer receives security updates'}.`
                      : `Vulnerability level ${cve.meta.overall_level || '—'} · ${cve.meta.total_unpatched ?? 0} unpatched CVE(s) against patch ${cve.meta.security_patch || '—'}.`}
                  </p>
                </div>
                <CveTable cves={cve.cves.slice(0, 10)} />
              </section>
            )}

            {/* Decision graph */}
            <section className="panel p-6">
              <h3 className="text-sm font-semibold text-ink">Admission decision graph</h3>
              <p className="mt-1 text-sm text-muted">Category outcomes feeding the final verdict</p>
              <div className="mt-6 flex flex-col items-stretch gap-4 lg:flex-row lg:items-center">
                <div className="grid flex-1 gap-2.5 sm:grid-cols-2 xl:grid-cols-4">
                  {aggregateCategories(stats.checklist).map((node) => (
                    <div
                      key={node.key}
                      className="rounded-2xl border bg-white px-4 py-3 shadow-soft"
                      style={{ borderLeftWidth: 3, borderLeftColor: node.color, borderColor: '#E5E7EB' }}
                    >
                      <p className="text-xs font-semibold text-ink">{node.label}</p>
                      <p className="mt-1 text-[11px] font-bold uppercase tracking-wide" style={{ color: node.color }}>
                        {node.status}
                      </p>
                      <p className="mt-1 text-[11px] text-muted">
                        {node.pass}P · {node.warn}W · {node.fail}F
                      </p>
                    </div>
                  ))}
                </div>
                <ChevronRight className="mx-auto hidden h-6 w-6 text-slate-300 lg:block shrink-0" />
                <div
                  className="rounded-2xl border-2 px-6 py-5 text-center lg:min-w-[150px] shadow-soft"
                  style={{
                    borderColor: scan.verdict === 'FAIL' ? '#FECACA' : scan.verdict === 'CONDITIONAL' ? '#FDE68A' : '#BBF7D0',
                    background:  scan.verdict === 'FAIL' ? '#FEF2F2' : scan.verdict === 'CONDITIONAL' ? '#FFFBEB' : '#F0FDF4',
                  }}
                >
                  <p className="section-label">Final</p>
                  <p className="mt-1 text-2xl font-black text-ink">{scan.verdict}</p>
                  <p className="mt-1 text-xs text-muted">score {scan.overall_score}/100</p>
                </div>
              </div>
            </section>

            {/* Priority findings preview */}
            <section className="panel overflow-hidden">
              <div className="border-b border-line px-5 py-4">
                <h3 className="text-sm font-semibold text-ink">Priority findings</h3>
                <p className="mt-0.5 text-xs text-muted">Top 10 actionable items — see the Findings tab for full list</p>
              </div>
              <FindingsTable rows={findings.slice(0, 10)} />
            </section>
          </motion.div>
        )}

        {tab === 'checklist' && (
          <motion.div key="checklist" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <div className="mb-4">
              <h2 className="text-lg font-semibold text-ink">8-category admission checklist</h2>
              <p className="mt-0.5 text-sm text-muted">Full evaluation across all security control categories</p>
            </div>
            <ChecklistPanel items={stats.checklist} />
          </motion.div>
        )}

        {tab === 'apps' && (
          <motion.div key="apps" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <section className="panel overflow-hidden">
              <div className="border-b border-line px-5 py-4 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-ink">Application inventory · risk ranked</h3>
                  <p className="mt-0.5 text-xs text-muted">{riskyApps.length} packages with risk score &gt; 0</p>
                </div>
              </div>
              <div className="max-h-[40rem] overflow-y-auto scrollbar-thin">
                <table className="w-full text-left text-sm">
                  <thead className="sticky top-0 z-10 bg-canvas text-xs uppercase tracking-wide text-muted border-b border-line">
                    <tr>
                      <th className="px-5 py-3 font-semibold">Package</th>
                      <th className="px-5 py-3 font-semibold">Score</th>
                      <th className="px-5 py-3 font-semibold">Level</th>
                      <th className="px-5 py-3 font-semibold">Signals</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {riskyApps.slice(0, 50).map((app) => (
                      <tr key={app.id} className="hover:bg-canvas/60 transition-colors">
                        <td className="px-5 py-3 font-mono text-xs text-ink">{app.package_name}</td>
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-100">
                              <div
                                className="h-full rounded-full transition-all duration-500"
                                style={{
                                  width: `${Math.min(100, app.risk_score)}%`,
                                  background: app.risk_level === 'CRITICAL' ? '#DC2626' : app.risk_level === 'HIGH' ? '#D97706' : '#CA8A04',
                                }}
                              />
                            </div>
                            <span className="tabular-nums font-bold text-ink">{app.risk_score}</span>
                          </div>
                        </td>
                        <td className="px-5 py-3">
                          <SeverityBadge level={app.risk_level} />
                        </td>
                        <td className="px-5 py-3 text-xs text-muted max-w-xs truncate">
                          {(app.risk_factors || []).slice(0, 3).join(' · ') || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </motion.div>
        )}

        {tab === 'findings' && (
          <motion.div key="findings" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-6">
            <section className="panel overflow-hidden">
              <div className="border-b border-line px-5 py-4">
                <h3 className="text-sm font-semibold text-ink">Structured findings · IOC style</h3>
                <p className="mt-0.5 text-xs text-muted">{findings.length} actionable items across all categories</p>
              </div>
              <FindingsTable rows={findings} />
            </section>

            {cve && (
              <section className="panel overflow-hidden">
                <div className="border-b border-line px-5 py-4">
                  <h3 className="text-sm font-semibold text-ink">CVE inventory</h3>
                  <p className="mt-0.5 text-xs text-muted">
                    {cve.meta.total_unpatched ?? 0} unpatched CVE(s) · {cve.meta.critical_count ?? 0} critical · {cve.meta.high_count ?? 0} high
                    {cve.meta.os_eol ? ` · ${cve.meta.os_eol_details || 'OS end-of-life'}` : ''}
                  </p>
                </div>
                <CveTable cves={cve.cves} />
              </section>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function IdentityItem({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="rounded-lg bg-canvas/70 px-2.5 py-2">
      <dt className="text-[9px] font-semibold uppercase tracking-wider text-muted">{label}</dt>
      <dd className="mt-0.5 truncate font-mono text-[11px] text-ink">{value || '—'}</dd>
    </div>
  );
}

function MetaItem({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-xl bg-white/60 border border-line px-3 py-2.5">
      <dt className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted">
        <Icon className="h-3 w-3 shrink-0" />
        {label}
      </dt>
      <dd className="mt-1 text-sm font-semibold capitalize text-ink truncate">{value}</dd>
    </div>
  );
}

function ChartCard({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 16, scale: 0.98 }}
      whileInView={{ opacity: 1, y: 0, scale: 1 }}
      viewport={{ once: true, margin: '-40px' }}
      transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
      whileHover={{ y: -2 }}
      className="panel p-5"
    >
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
      <p className="mt-0.5 text-xs text-muted">{subtitle}</p>
      <div className="mt-5">{children}</div>
    </motion.section>
  );
}

function FindingsTable({ rows }: { rows: { severity: string; title: string; detail: string; category: string }[] }) {
  if (!rows.length) {
    return (
      <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
        <CheckCircle2 className="h-10 w-10 text-pass-soft" />
        <p className="mt-3 text-sm font-medium text-ink">Clean admission profile</p>
        <p className="mt-1 text-xs text-muted">No open findings across all scanned categories</p>
      </div>
    );
  }
  return (
    <div className="max-h-[36rem] overflow-y-auto scrollbar-thin">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 bg-canvas border-b border-line text-xs uppercase tracking-wide text-muted">
          <tr>
            <th className="px-5 py-3 font-semibold">Severity</th>
            <th className="px-5 py-3 font-semibold">Finding</th>
            <th className="px-5 py-3 font-semibold">Category</th>
            <th className="px-5 py-3 font-semibold">Evidence</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {rows.map((r, i) => (
            <tr key={`${r.title}-${i}`} className="hover:bg-canvas/50 transition-colors align-top">
              <td className="px-5 py-3">
                <SeverityBadge level={r.severity} />
              </td>
              <td className="px-5 py-3 font-medium text-ink max-w-xs break-words">{r.title}</td>
              <td className="px-5 py-3 text-muted whitespace-nowrap">{r.category}</td>
              <td className="px-5 py-3 text-xs text-muted max-w-xs">{r.detail || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CveTable({ cves }: { cves: { id?: string; title?: string; severity?: string; cvss?: number; bulletin?: string }[] }) {
  const sorted = [...cves].sort((a, b) => {
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (order[(a.severity || 'LOW').toUpperCase()] ?? 9) - (order[(b.severity || 'LOW').toUpperCase()] ?? 9);
  });
  if (!sorted.length) {
    return (
      <div className="flex flex-col items-center justify-center px-6 py-10 text-center">
        <CheckCircle2 className="h-9 w-9 text-pass-soft" />
        <p className="mt-3 text-sm font-medium text-ink">No known unpatched CVEs</p>
        <p className="mt-1 text-xs text-muted">Device patch level has no recorded CVE exposure</p>
      </div>
    );
  }
  return (
    <div className="max-h-[32rem] overflow-y-auto scrollbar-thin">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 bg-canvas border-b border-line text-xs uppercase tracking-wide text-muted">
          <tr>
            <th className="px-5 py-3 font-semibold">CVE</th>
            <th className="px-5 py-3 font-semibold">Severity</th>
            <th className="px-5 py-3 font-semibold">CVSS</th>
            <th className="px-5 py-3 font-semibold">Title</th>
            <th className="px-5 py-3 font-semibold">Bulletin</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {sorted.map((c, i) => (
            <tr key={`${c.id}-${i}`} className="hover:bg-canvas/50 transition-colors align-top">
              <td className="px-5 py-3 font-mono text-xs text-ink">{c.id || '—'}</td>
              <td className="px-5 py-3"><SeverityBadge level={c.severity || 'LOW'} /></td>
              <td className="px-5 py-3 tabular-nums text-ink">{c.cvss != null ? Number(c.cvss).toFixed(1) : '—'}</td>
              <td className="px-5 py-3 text-ink max-w-xs break-words">{c.title || '—'}</td>
              <td className="px-5 py-3 text-xs text-muted whitespace-nowrap">{c.bulletin || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SeverityBadge({ level }: { level: string }) {
  const l = level.toUpperCase();
  const map: Record<string, string> = {
    CRITICAL: 'bg-fail-soft text-fail border border-fail/20',
    FAIL:     'bg-fail-soft text-fail border border-fail/20',
    HIGH:     'bg-orange-50 text-orange-700 border border-orange-200',
    MEDIUM:   'bg-warn-soft text-warn border border-warn/20',
    WARNING:  'bg-warn-soft text-warn border border-warn/20',
    LOW:      'bg-pass-soft text-pass border border-pass/20',
  };
  return (
    <span className={`inline-flex items-center rounded-lg px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${map[l] || 'bg-canvas text-muted border border-line'}`}>
      {l}
    </span>
  );
}

function buildTags(scan: ScanDetails, mustFails: number, warn: number, fail: number, threatCount: number) {
  const tags: { label: string; bg: string; fg: string }[] = [
    {
      label: scan.verdict,
      bg: scan.verdict === 'FAIL' ? '#FEE2E2' : scan.verdict === 'CONDITIONAL' ? '#FEF3C7' : '#DCFCE7',
      fg: scan.verdict === 'FAIL' ? '#DC2626' : scan.verdict === 'CONDITIONAL' ? '#D97706' : '#16A34A',
    },
    { label: scan.platform, bg: '#EFF6FF', fg: '#1D4ED8' },
    { label: `${scan.scan_mode} scan`, bg: '#F8FAFC', fg: '#475569' },
  ];
  if (scan.scan_mode !== 'quick' && scan.severity_tier) {
    const sevColors: Record<string, [string, string]> = {
      safe: ['#DCFCE7', '#16A34A'],
      'low risk': ['#FEF9C3', '#CA8A04'],
      vulnerable: ['#FEF3C7', '#D97706'],
      compromisable: ['#FFEDD5', '#C2410C'],
      critical: ['#FEE2E2', '#DC2626'],
    };
    const [bg, fg] = sevColors[scan.severity_tier.toLowerCase()] || ['#F8FAFC', '#475569'];
    tags.push({ label: scan.severity_tier, bg, fg });
  }
  if (threatCount) tags.push({ label: `${threatCount} potential threat${threatCount > 1 ? 's' : ''}`, bg: '#FEE2E2', fg: '#B91C1C' });
  if (mustFails) tags.push({ label: `${mustFails} must fail`, bg: '#FEE2E2', fg: '#DC2626' });
  if (warn)     tags.push({ label: `${warn} warnings`,   bg: '#FEF3C7', fg: '#D97706' });
  if (scan.critical_apps_count) tags.push({ label: `${scan.critical_apps_count} critical apps`, bg: '#FFF7ED', fg: '#C2410C' });
  if ((scan.os_version || '').startsWith('1') && Number(scan.os_version) < 12 && scan.platform === 'android') {
    tags.push({ label: 'EOL OS', bg: '#FEF3C7', fg: '#D97706' });
  }
  return tags;
}

function executiveSummary(
  scan: ScanDetails,
  stats: { pass: number; warn: number; fail: number; mustFails: { check_name: string }[]; checklist: unknown[] }
) {
  if (scan.verdict === 'FAIL') {
    const reasons = stats.mustFails.map((m) => m.check_name).slice(0, 2).join('; ');
    return `Device is REJECTED for BYOD admission. ${stats.fail} checklist item(s) failed (${stats.mustFails.length} Must-priority). ${reasons ? `Primary blockers: ${reasons}.` : ''} Risk score ${scan.overall_score}/100 across ${scan.total_apps_scanned} packages.`;
  }
  if (scan.verdict === 'CONDITIONAL') {
    return `Device may be admitted with caution. All Must checks passed, but ${stats.warn} warning(s) require follow-up before full admission. Risk score ${scan.overall_score}/100.`;
  }
  return `Device is APPROVED for BYOD admission. ${stats.pass}/${stats.checklist.length} checks passed cleanly with no blocking violations. Risk score ${scan.overall_score}/100.`;
}

function aggregateCategories(checklist: ScanDetails['checklist']) {
  const map = new Map<string, { pass: number; warn: number; fail: number }>();
  for (const c of checklist || []) {
    const row = map.get(c.category) || { pass: 0, warn: 0, fail: 0 };
    if (c.status === 'FAIL') row.fail += 1;
    else if (c.status === 'WARNING') row.warn += 1;
    else row.pass += 1;
    map.set(c.category, row);
  }
  return [...map.entries()].map(([key, v]) => {
    const status = v.fail ? 'FAIL' : v.warn ? 'WARNING' : 'PASS';
    const color = status === 'FAIL' ? '#DC2626' : status === 'WARNING' ? '#D97706' : '#16A34A';
    return { key, label: categoryLabel(key), status, color, ...v };
  });
}
