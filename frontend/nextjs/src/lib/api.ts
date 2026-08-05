const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:5000/api';

export interface ScanItem {
  id: string;
  device_id: string;
  scan_mode: string;
  verdict: 'PASS' | 'CONDITIONAL' | 'FAIL';
  overall_score: number;
  device_risk_level: string;
  total_apps_scanned: number;
  critical_apps_count: number;
  high_apps_count: number;
  created_at: string;
  serial: string;
  manufacturer: string;
  model: string;
  platform: 'android' | 'ios';
  os_version: string;
  imei?: string;
  imei_slot2?: string;
  phone_number?: string;
  phone_number_slot2?: string;
  sim_operator?: string;
  sim_operator_slot2?: string;
}

export interface ChecklistItem {
  id: string;
  category: string;
  check_name: string;
  priority: 'Must' | 'Should' | 'Nice to have';
  status: 'PASS' | 'WARNING' | 'FAIL';
  details: string;
}

export interface AppFinding {
  id: string;
  package_name: string;
  app_name: string;
  risk_score: number;
  risk_level: string;
  risk_factors: string[];
  apkid_flags: string[];
  critical_permissions: string[];
  cert_issues: string[];
}

export interface CveFinding {
  id: string;
  title: string;
  severity: string;
  cvss: number;
  bulletin: string;
}

export interface CveData {
  android_version?: string;
  security_patch?: string;
  overall_level?: string;
  os_eol?: boolean;
  os_eol_details?: string;
  total_unpatched?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  vulnerable?: boolean;
  cves?: CveFinding[];
  error?: string;
  [key: string]: unknown;
}

export interface ScanDetails extends ScanItem {
  checklist: ChecklistItem[];
  app_findings: AppFinding[];
  cve_findings?: CveData | null;
  sdk_version?: string;
  security_patch?: string;
  build_id?: string;
  hardware?: string;
  bootloader?: string;
  radio_version?: string;
  imei?: string;
  imei_slot2?: string;
  meid?: string;
  phone_number?: string;
  phone_number_slot2?: string;
  sim_operator?: string;
  sim_operator_slot2?: string;
  sim_operator_numeric?: string;
  sim_serial?: string;
  sim_serial_slot2?: string;
  subscriber_id?: string;
  subscriber_id_slot2?: string;
  screen_lock_enabled?: number | null;
  encryption_enabled?: number | null;
  severity_tier?: string;
  oem_unlock_allowed?: number | null;
}

export interface DeviceItem {
  id: string;
  serial: string;
  platform: string;
  manufacturer: string;
  model: string;
  os_version: string;
  security_patch: string;
  imei?: string;
  imei_slot2?: string;
  phone_number?: string;
  phone_number_slot2?: string;
  sim_operator?: string;
  total_scans: number;
  last_verdict: string;
  last_scanned_at: string;
}

export interface DeviceDetail extends DeviceItem {
  imei?: string;
  imei_slot2?: string;
  meid?: string;
  phone_number?: string;
  phone_number_slot2?: string;
  sim_operator?: string;
  sim_operator_slot2?: string;
  sim_serial?: string;
  sim_serial_slot2?: string;
  subscriber_id?: string;
  subscriber_id_slot2?: string;
  hardware?: string;
  build_id?: string;
  bootloader?: string;
  screen_lock_enabled?: number | null;
  encryption_enabled?: number | null;
  scans: ScanItem[];
}

export async function fetchDeviceDetail(id: string): Promise<DeviceDetail | null> {
  const data = await safeJson<{ device: DeviceDetail }>(`${API_BASE}/devices/${id}`);
  return data?.device || null;
}

export interface ConnectedDevice {
  platform: 'android' | 'ios';
  serial: string;
  state: string;
  manufacturer: string;
  model: string;
  os_version: string;
  label: string;
  ready: boolean;
  hint: string;
}

async function safeJson<T>(url: string, init?: RequestInit): Promise<T | null> {
  try {
    const res = await fetch(url, { cache: 'no-store', ...init });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export async function fetchAllScans(): Promise<ScanItem[]> {
  const data = await safeJson<{ scans: ScanItem[] }>(`${API_BASE}/scans`);
  return data?.scans || [];
}

export async function fetchScanDetails(id: string): Promise<ScanDetails | null> {
  const data = await safeJson<{ scan: ScanDetails }>(`${API_BASE}/scans/${id}`);
  return data?.scan || null;
}

export async function fetchAllDevices(): Promise<DeviceItem[]> {
  const data = await safeJson<{ devices: DeviceItem[] }>(`${API_BASE}/devices`);
  return data?.devices || [];
}

export async function fetchConnectedDevices(): Promise<ConnectedDevice[]> {
  const data = await safeJson<{ devices: ConnectedDevice[] }>(`${API_BASE}/connected`);
  return data?.devices || [];
}

export interface ScanJobStatus {
  running: boolean;
  status: string;
  pid?: number;
  mode?: string;
  platform?: string;
  started_at?: string;
  finished_at?: string;
  message?: string;
  error?: string;
}

export async function fetchScanStatus(): Promise<ScanJobStatus> {
  const data = await safeJson<ScanJobStatus>(`${API_BASE}/scan/status`);
  return data || { running: false, status: 'idle' };
}

export async function triggerLiveScan(
  mode: 'quick' | 'minimal' | 'deep' = 'minimal',
  platform: 'auto' | 'android' | 'ios' = 'auto',
  serial?: string,
  vtEnabled?: boolean
): Promise<ScanJobStatus> {
  try {
    const res = await fetch(`${API_BASE}/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, platform, serial: serial || undefined, vt_enabled: !!vtEnabled }),
      cache: 'no-store',
    });
    const data = (await res.json()) as ScanJobStatus;
    if (!res.ok) {
      return { ...data, running: !!(data.running), status: data.status || 'error', error: data.error || 'Failed to start scan' };
    }
    return data;
  } catch {
    return { running: false, status: 'error', error: 'Failed to start scan' };
  }
}

export async function fetchScanLogs(limit = 200): Promise<string> {
  const data = await safeJson<{ logs: string }>(`${API_BASE}/scan/logs?limit=${limit}`);
  return data?.logs || '';
}

export async function cancelLiveScan(): Promise<ScanJobStatus> {
  return (
    (await safeJson<ScanJobStatus>(`${API_BASE}/scan/cancel`, { method: 'POST' })) || {
      running: false,
      status: 'idle',
      message: 'Cancel request failed',
    }
  );
}

export async function deleteScan(id: string): Promise<boolean> {
  const data = await safeJson<{ status?: string }>(`${API_BASE}/scans/${id}`, { method: 'DELETE' });
  return data?.status === 'deleted';
}

export async function deleteDevice(id: string): Promise<boolean> {
  const data = await safeJson<{ status?: string }>(`${API_BASE}/devices/${id}`, { method: 'DELETE' });
  return data?.status === 'deleted';
}

export function pdfUrl(scanId: string, safe = false, onePager = false) {
  const suffix = onePager ? '/one-pager' : '';
  return `${API_BASE}/scans/${scanId}/pdf${suffix}${safe ? '?safe=true' : ''}`;
}
