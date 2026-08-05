'use client';

import { motion } from 'framer-motion';
import {
  Shield,
  Smartphone,
  Apple,
  Wifi,
  Lock,
  ShieldCheck,
  Bell,
  Database,
  Server,
  FileText,
  ChevronRight,
} from 'lucide-react';

const categories = [
  {
    icon: Smartphone,
    label: '1. Device & OS Identity',
    checks: ['Make, model & serial recorded', 'OS version identified', 'Security patch age (<90 days)', 'OS still supported (not EOL)'],
  },
  {
    icon: Shield,
    label: '2. Root / Jailbreak & Integrity',
    checks: ['Root (Android: su execution + Magisk artifacts) or jailbreak (iOS: installed-app bundle ID scan) detection', 'Bootloader lock status & OEM unlock allowed', 'USB debugging / ADB status', 'Custom ROM / test-keys detection'],
  },
  {
    icon: Lock,
    label: '3. Lock Screen & Encryption',
    checks: ['Screen lock enabled (PIN / biometric)', 'Full-disk / file-based encryption'],
  },
  {
    icon: Bell,
    label: '4. Installed Applications',
    checks: ['Full APK inventory pulled', 'High-risk permissions (Accessibility, Admin)', 'YARA malware signature scan', 'Obfuscated / packed app detection'],
  },
  {
    icon: Wifi,
    label: '5. Network & Connectivity',
    checks: ['Unauthorized VPN / proxy profiles', 'Insecure Wi-Fi review', 'Bluetooth discoverability'],
  },
  {
    icon: FileText,
    label: '6. Certificates',
    checks: ['User-installed / untrusted root CAs', 'App signing cert weaknesses'],
  },
  {
    icon: Server,
    label: '7. Management Readiness',
    checks: ['MDM / enterprise enrollment support', 'SIM / eSIM carrier match'],
  },
  {
    icon: Database,
    label: '8. Data Backup Exposure',
    checks: ['Cloud backup destinations reviewed'],
  },
];

const platforms = [
  {
    id: 'android',
    name: 'Android',
    icon: Smartphone,
    desc: 'Connected via USB debugging (ADB). APKs are pulled off-device for static analysis.',
    modes: [
      {
        name: 'Quick',
        color: 'text-teal-600',
        bg: 'bg-teal-50',
        time: 'seconds (best effort)',
        api_keys: 'None required',
        pipeline: [
          'Device detection (model, Android version, patch level)',
          'IMEI / SIM / phone number collection',
          'Root detection (su execution confirm, Magisk artifacts, overlay mounts)',
          'Bootloader unlock status',
          'Screen lock & encryption status',
          'Risk scoring & report (no app/certificate inventory in this tier)',
        ],
      },
      {
        name: 'Minimal',
        color: 'text-brand',
        bg: 'bg-brand-soft',
        time: '5–15 min',
        api_keys: 'None required',
        pipeline: [
          'Device detection (model, Android version, patch level)',
          'List & extract installed apps (APKs)',
          'APKiD — packed / obfuscated app detection',
          'Androguard — manifest analysis (permissions, activities, services)',
          'App signature & certificate verification',
          'Risky permission identification',
          'Root detection',
          'CVE vulnerability check vs security patch',
          'SHA-256 hash generation',
          'YARA malware rule scan',
          'Risk scoring & report',
        ],
      },
      {
        name: 'Deep',
        color: 'text-amber-600',
        bg: 'bg-amber-50',
        time: '20–40 min',
        api_keys: 'VT_API_KEY, MOBSF_API_KEY',
        pipeline: [
          'Everything in Minimal +',
          'MobSF — full static analysis (hardcoded secrets, insecure code, OWASP issues)',
          'MVT — spyware IOC check (e.g. Pegasus-related traces)',
          'Hash-based app inventory and integrity checks',
        ],
      },
    ],
  },
  {
    id: 'ios',
    name: 'iOS',
    icon: Apple,
    desc: 'Connected over USB (usbmux). Scans the device, its configuration profiles and Mach-O binaries.',
    modes: [
      {
        name: 'Quick',
        color: 'text-teal-600',
        bg: 'bg-teal-50',
        time: 'seconds (best effort)',
        api_keys: 'None required',
        pipeline: [
          'Device detection (iPhone / iPad via usbmux)',
          'Jailbreak detection (installed-app bundle ID scan)',
          'Risk scoring & report (no plist / Mach-O / certificate inventory in this tier)',
        ],
      },
      {
        name: 'Minimal',
        color: 'text-brand',
        bg: 'bg-brand-soft',
        time: '5–10 min',
        api_keys: 'None required',
        pipeline: [
          'Device detection (iPhone / iPad via usbmux)',
          'plist_analyzer — Info.plist, permissions & entitlements',
          'macho_analyzer — binary mitigations (PIE, ARC, Canaries)',
          'iOS certificate & provisioning profile analysis',
          'Jailbreak detection (installed-app bundle ID scan for Cydia/Sileo/Zebra/etc)',
          'Risk scoring & report',
        ],
      },
      {
        name: 'Deep',
        color: 'text-amber-600',
        bg: 'bg-amber-50',
        time: '20–40 min',
        api_keys: 'MOBSF_API_KEY',
        pipeline: [
          'Everything in Minimal +',
          'YARA — malware signature scan',
          'MVT — mvt-ios spyware IOC check (e.g. Pegasus traces)',
          'MobSF — iOS app static analysis',
        ],
      },
    ],
  },
];

export default function AboutPage() {
  return (
    <div className="space-y-12">
      {/* Hero */}
      <motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="max-w-3xl">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-brand text-white shadow-soft mb-4">
          <Shield className="h-6 w-6" />
        </div>
        <h1 className="text-3xl font-bold tracking-tight text-ink sm:text-4xl">
          What is Mobile Security Scanner?
        </h1>
        <p className="mt-4 text-[15px] leading-relaxed text-muted max-w-2xl">
          A workstation-based forensic BYOD admission scanner. Connect any Android or iOS device via USB,
          run an automated 8-category compliance audit, and get a pass/fail admission verdict with a downloadable PDF certificate.
        </p>
      </motion.section>

      {/* How it works */}
      <motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="space-y-4">
        <h2 className="text-xl font-semibold text-ink">How it works</h2>
        <div className="grid gap-4 sm:grid-cols-3">
          {[
            { step: '1', title: 'Connect', desc: 'Plug in a phone via USB. Enable USB debugging (Android) or trust this computer (iOS).' },
            { step: '2', title: 'Scan', desc: 'Choose Minimal (offline) or Deep (adds cloud analysis). The pipeline runs 10–15 Docker containers automatically.' },
            { step: '3', title: 'Review', desc: 'Get a PASS / CONDITIONAL / FAIL verdict. Download the PDF certificate or share a safe version without IMEI or phone number.' },
          ].map((s) => (
            <div key={s.step} className="panel p-5">
              <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-brand text-sm font-bold text-white">{s.step}</span>
              <h3 className="mt-3 font-semibold text-ink">{s.title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-muted">{s.desc}</p>
            </div>
          ))}
        </div>
      </motion.section>

      {/* Scan modes */}
      <motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }} className="space-y-6">
        <div>
          <h2 className="text-xl font-semibold text-ink">Scan modes</h2>
          <p className="mt-1 text-sm text-muted">
            Both platforms support Minimal (offline) and Deep (adds cloud analysis). The pipeline is different per platform — Android analyzes pulled APKs, iOS analyzes the device over usbmux.
          </p>
        </div>

        {platforms.map((platform) => (
          <div key={platform.id} className="space-y-3">
            <div className="flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-canvas text-brand">
                <platform.icon className="h-4 w-4" />
              </span>
              <div>
                <h3 className="font-semibold text-ink">{platform.name}</h3>
                <p className="text-xs text-muted">{platform.desc}</p>
              </div>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              {platform.modes.map((mode) => (
                <div key={mode.name} className="panel p-5">
                  <h4 className={`text-lg font-semibold ${mode.color}`}>{mode.name}</h4>
                  <p className="mt-1 text-sm text-muted">
                    Est. {mode.time} · {mode.api_keys}
                  </p>
                  <ul className="mt-4 space-y-1.5">
                    {mode.pipeline.map((item) => (
                      <li key={item} className="flex items-start gap-2 text-sm text-muted">
                        <ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        ))}
      </motion.section>

      {/* 8 categories */}
      <motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="space-y-4">
        <h2 className="text-xl font-semibold text-ink">The 8-category admission checklist</h2>
        <p className="text-sm text-muted">
          Every scan evaluates the device against these categories. A single Must-priority failure → FAIL verdict (reject admission).
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          {categories.map((cat) => {
            const Icon = cat.icon;
            return (
              <div key={cat.label} className="panel p-5">
                <div className="flex items-center gap-3">
                  <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-canvas text-brand">
                    <Icon className="h-4.5 w-4.5" />
                  </span>
                  <div>
                    <h3 className="font-semibold text-ink text-sm">{cat.label}</h3>
                  </div>
                </div>
                <ul className="mt-3 space-y-1">
                  {cat.checks.map((c) => (
                    <li key={c} className="flex items-start gap-2 text-sm text-muted">
                      <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-pass" />
                      {c}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      </motion.section>

      {/* Architecture */}
      <motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.12 }} className="space-y-4">
        <h2 className="text-xl font-semibold text-ink">Architecture</h2>
        <div className="panel p-5 space-y-3 text-sm text-muted leading-relaxed">
          <p>
            Each analysis service runs in its own Docker container. Services communicate through JSON files in <code className="rounded bg-canvas px-1.5 py-0.5 font-mono text-xs">backend/output/</code> — no direct service-to-service calls.
          </p>
          <p>
            The orchestrator (Python on the host) runs collection services sequentially, then analysis services in parallel (up to 6 workers), then aggregation and report generation.
          </p>
          <p>
            Results are stored in SQLite (<code className="rounded bg-canvas px-1.5 py-0.5 font-mono text-xs">backend/output/mobile_security.db</code>) and viewable via the REST API or web dashboard.
          </p>
          <div className="flex flex-wrap gap-2 pt-2">
            {['Docker', 'Python 3', 'Next.js', 'SQLite', 'ReportLab', 'ADB', 'usbmux'].map((t) => (
              <span key={t} className="rounded-full bg-canvas px-3 py-1 text-xs font-medium text-muted">{t}</span>
            ))}
          </div>
        </div>
      </motion.section>
    </div>
  );
}
