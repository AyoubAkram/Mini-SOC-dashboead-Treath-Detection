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

type Params = Record<string, string | number | undefined | null>;

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

export async function request<T>(url: string, method: 'GET' | 'POST' = 'GET'): Promise<T> {
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
