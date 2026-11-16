import { useEffect, useRef, useState } from 'react';

// Requests go to the same origin; in development CRA proxies /api to the backend
// (see "proxy" in package.json).

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type AlertStatus = 'open' | 'investigating' | 'resolved';
export type TimeRange = '1h' | '24h' | '7d' | '30d';

export interface StatsResponse {
  database_connected: boolean;
  total_events: number;
  total_events_trend: number | null;
  active_alerts: number;
  active_alerts_trend: number | null;
  failed_logins: number;
  failed_logins_trend: number | null;
  unique_source_ips: number;
  severity_counts: Record<Severity, number>;
  threat_score: number;
  threat_level: Severity;
  rule_alerts: number;
  ml_alerts: number;
}

export interface Alert {
  id: string;
  timestamp: string;
  severity: Severity;
  type: string;
  log_source: string;
  source: string;
  destination: string;
  username: string | null;
  description: string;
  status: AlertStatus;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  mitre_name: string | null;
}

export interface AlertsResponse {
  alerts: Alert[];
  total: number;
  limit: number;
  offset: number;
}

export interface Threat {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  source: string;
  target: string;
  timestamp: string;
  status: AlertStatus;
}

export interface ThreatsResponse {
  threats: Threat[];
  total: number;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  severity: Severity;
  title: string;
  description: string;
}

export interface TimelineResponse {
  timeline: TimelineEvent[];
}

export interface EventTypesResponse {
  event_types: { name: string; count: number; percentage: number }[];
  log_sources: { name: string; count: number }[];
}

export interface SourceIpsResponse {
  source_ips: { ip: string; location: string; event_count: number; threat_level: string }[];
}

export interface VolumeBucket {
  time: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  ml: number;
}

export interface VolumeResponse {
  bucket_minutes: number;
  buckets: VolumeBucket[];
}

export interface AttackTypesResponse {
  attack_types: { name: string; count: number }[];
}

export interface Explanation {
  feature: string;
  label: string;
  value: number;
  typical: number;
  weight: number;
}

export interface Anomaly {
  id: string;
  timestamp: string;
  entity_type: 'ip' | 'user';
  entity: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  anomaly_score: number;
  explanation: Explanation[];
  cluster: string | null;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  baseline_z: number | null;
  model_version: string;
  resolved: boolean;
}

export interface AnomaliesResponse {
  anomalies: Anomaly[];
  total: number;
}

export interface EntityRisk {
  id: string;
  entity_type: 'ip' | 'user';
  entity: string;
  risk_score: number;
  components: { ml: number; baseline: number; rules: number; coordinated: number };
  anomalous_windows: number;
  windows: number;
  events: number;
  top_reasons: string[];
  last_seen: string;
}

export interface EntitiesResponse {
  entities: EntityRisk[];
}

export interface LogEntry {
  id: string;
  timestamp: string;
  source_ip: string | null;
  username: string | null;
  event_type: string;
  log_source: string;
  message: string;
  raw: string;
  host: string | null;
  dest_ip: string | null;
  dest_port: number | null;
}

export interface LogsResponse {
  logs: LogEntry[];
  total: number;
}

export interface EntityProfile {
  entity_type: 'ip' | 'user';
  entity: string;
  risk: EntityRisk | null;
  baseline: { windows: number; mean: Record<string, number> } | null;
  anomalies: Anomaly[];
  recent_logs: LogEntry[];
  total_logs: number;
}

export interface ModelVersion {
  version: string;
  trained_at: string;
  params: { contamination: number; n_estimators: number };
  samples: Record<string, number>;
  note: string;
}

export interface ModelsResponse {
  active: string | null;
  versions: ModelVersion[];
}

export interface MitreTechnique {
  id: string;
  name: string;
  rules: boolean;
  ml: boolean;
  rule_alerts: number;
  ml_alerts: number;
}

export interface MitreResponse {
  tactics: { id: string; name: string; alerts: number; techniques: MitreTechnique[] }[];
  techniques_covered: number;
  techniques_seen: number;
  tactics_covered: number;
}

export interface StoryStage {
  technique: string;
  name: string;
  tactic: string;
  count: number;
  first_seen: string;
  last_seen: string;
  severity: Severity;
  detections: string[];
  example: string;
}

export interface StoryResponse {
  stages: StoryStage[];
  tactics: string[];
  alerts: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface EntityRef {
  type: 'ip' | 'user';
  id: string;
}

type Params = Record<string, string | number | boolean | undefined | null>;

export const buildUrl = (path: string, params: Params = {}): string => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  const text = query.toString();
  return text ? `${path}?${text}` : path;
};

export async function request<T>(url: string, method: 'GET' | 'POST' | 'PATCH' = 'GET'): Promise<T> {
  const response = await fetch(url, { method });
  if (!response.ok) {
    throw new Error(`${method} ${url} failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const setAlertStatus = (id: string, action: 'acknowledge' | 'resolve' | 'reopen') =>
  request<{ alert_id: string; status: AlertStatus }>(`/api/alerts/${id}/${action}`, 'POST');

/**
 * Fetch a URL and fetch it again whenever the URL or refreshKey changes.
 * The previous data stays visible while a refresh is in flight.
 */
export function useApi<T>(url: string, refreshKey: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const latest = useRef(0);

  useEffect(() => {
    const call = ++latest.current;
    setLoading(true);
    request<T>(url)
      .then((result) => {
        if (call === latest.current) {
          setData(result);
          setError(null);
        }
      })
      .catch((err: Error) => {
        if (call === latest.current) {
          setError(err.message);
        }
      })
      .finally(() => {
        if (call === latest.current) {
          setLoading(false);
        }
      });
  }, [url, refreshKey]);

  return { data, error, loading };
}

export const formatNumber = (value: number): string => value.toLocaleString('en-US');

export const formatTime = (iso: string): string => {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleTimeString('en-GB');
};

export const formatDateTime = (iso: string): string => {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return `${date.toLocaleDateString('en-CA')} ${date.toLocaleTimeString('en-GB')}`;
};

export const timeAgo = (iso: string): string => {
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) {
    return iso;
  }
  if (seconds < 60) {
    return 'just now';
  }
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) {
    return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  }
  const hours = Math.round(minutes / 60);
  if (hours < 48) {
    return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  }
  return `${Math.round(hours / 24)} days ago`;
};

/** "login_failed" -> "Login Failed" */
export const titleCase = (name: string): string =>
  name.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());

export const riskLevel = (score: number): Severity => {
  if (score >= 70) {
    return 'critical';
  }
  if (score >= 50) {
    return 'high';
  }
  return score >= 25 ? 'medium' : 'low';
};

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f2526b',
  high: '#f79a3e',
  medium: '#e8c547',
  low: '#3fbf8f',
  ml: '#a889ff',
  accent: '#6c8cff'
};

export interface PageProps {
  timeRange: TimeRange;
  refreshKey: number;
  refresh: () => void;
  openEntity: (entity: EntityRef) => void;
}

export const RANGE_LABELS: Record<TimeRange, string> = {
  '1h': 'last hour',
  '24h': 'last 24 hours',
  '7d': 'last 7 days',
  '30d': 'last 30 days'
};
