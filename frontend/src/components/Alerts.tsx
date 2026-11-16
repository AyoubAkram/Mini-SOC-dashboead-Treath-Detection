import React, { useEffect, useState } from 'react';
import Icon from './Icons';
import {
  Alert, AlertsResponse, PageProps, buildUrl, formatDateTime, formatNumber, setAlertStatus, useApi
} from '../api';
import '../styles/alerts.css';

interface AlertsProps extends PageProps {
  pageSize?: number;
  title?: string;
}

// Filter dropdown value -> query parameters of GET /api/alerts
const FILTERS: Record<string, { label: string; severity?: string; status?: string }> = {
  all: { label: 'All alerts' },
  unresolved: { label: 'Unresolved', status: 'unresolved' },
  critical: { label: 'Critical only', severity: 'critical' },
  high: { label: 'High only', severity: 'high' },
  medium: { label: 'Medium only', severity: 'medium' },
  investigating: { label: 'Investigating', status: 'investigating' },
  resolved: { label: 'Resolved', status: 'resolved' }
};

const csvCell = (value: string | null): string => `"${String(value ?? '').replace(/"/g, '""')}"`;

const isIp = (value: string): boolean => /^[0-9a-fA-F:.]+$/.test(value) && /[.:]/.test(value);

const Alerts = ({ timeRange, refreshKey, refresh, openEntity, pageSize = 10, title = 'Security alerts' }: AlertsProps) => {
  const [selectedAlerts, setSelectedAlerts] = useState<string[]>([]);
  const [searchText, setSearchText] = useState<string>('');
  const [search, setSearch] = useState<string>('');
  const [filter, setFilter] = useState<string>('all');
  const [page, setPage] = useState<number>(0);
  const [actionError, setActionError] = useState<string | null>(null);

  // Wait until the user stops typing before querying
  useEffect(() => {
    const timer = setTimeout(() => setSearch(searchText.trim()), 300);
    return () => clearTimeout(timer);
  }, [searchText]);

  // A new query starts again from the first page
  useEffect(() => {
    setPage(0);
    setSelectedAlerts([]);
  }, [search, filter, timeRange]);

  const url = buildUrl('/api/alerts', {
    limit: pageSize,
    offset: page * pageSize,
    time_range: timeRange,
    severity: FILTERS[filter].severity,
    status: FILTERS[filter].status,
    search
  });
  const { data, error, loading } = useApi<AlertsResponse>(url, refreshKey);
  const alerts: Alert[] = data?.alerts ?? [];
  const total = data?.total ?? 0;
  const first = total === 0 ? 0 : page * pageSize + 1;
  const last = Math.min((page + 1) * pageSize, total);
  const pageIds = alerts.map((alert) => alert.id);
  const allSelected = pageIds.length > 0 && pageIds.every((id) => selectedAlerts.includes(id));

  // Resolving alerts can leave the current page empty
  useEffect(() => {
    if (data && page > 0 && page * pageSize >= data.total) {
      setPage(Math.max(Math.ceil(data.total / pageSize) - 1, 0));
    }
  }, [data, page, pageSize]);

  const toggleAlert = (id: string) => {
    setSelectedAlerts(prev =>
      prev.includes(id) ? prev.filter(a => a !== id) : [...prev, id]
    );
  };

  const updateStatus = async (ids: string[], action: 'acknowledge' | 'resolve' | 'reopen') => {
    try {
      await Promise.all(ids.map((id) => setAlertStatus(id, action)));
      setActionError(null);
      setSelectedAlerts(prev => prev.filter((id) => !ids.includes(id)));
    } catch (err) {
      setActionError((err as Error).message);
    }
    refresh();
  };

  const exportCsv = () => {
    const header = ['timestamp', 'severity', 'type', 'source', 'destination', 'username', 'description', 'status'];
    const rows = alerts.map((alert) => [
      alert.timestamp, alert.severity, alert.type, alert.source, alert.destination,
      alert.username, alert.description, alert.status
    ].map(csvCell).join(','));
    const blob = new Blob([[header.join(','), ...rows].join('\n')], { type: 'text/csv' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'alerts.csv';
    link.click();
    URL.revokeObjectURL(link.href);
  };

  return (
    <div className="card">
      <div className="toolbar">
        <h2>{title}</h2>
        {selectedAlerts.length > 0 && (
          <>
            <button className="btn small" onClick={() => updateStatus(selectedAlerts, 'acknowledge')}>
              Acknowledge {selectedAlerts.length}
            </button>
            <button className="btn small" onClick={() => updateStatus(selectedAlerts, 'resolve')}>
              Resolve {selectedAlerts.length}
            </button>
          </>
        )}
        <input
          type="text"
          placeholder="Search IP, user, message…"
          className="input"
          value={searchText}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchText(e.target.value)}
        />
        <select
          className="select"
          value={filter}
          onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilter(e.target.value)}
        >
          {Object.entries(FILTERS).map(([key, item]) => (
            <option key={key} value={key}>{item.label}</option>
          ))}
        </select>
        <button className="btn" onClick={exportCsv} disabled={alerts.length === 0}>
          <Icon name="download" size={15} /> Export
        </button>
      </div>

      {(error || actionError) && (
        <div className="banner" style={{ margin: '0 18px 12px' }}>Could not reach the API: {error || actionError}</div>
      )}

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 36 }}>
                <input
                  type="checkbox"
                  className="checkbox"
                  checked={allSelected}
                  onChange={() => setSelectedAlerts(allSelected ? [] : pageIds)}
                  disabled={alerts.length === 0}
                  aria-label="Select all"
                />
              </th>
              <th>Time</th>
              <th>Severity</th>
              <th>Type</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Description</th>
              <th>Status</th>
              <th style={{ width: 80 }}></th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td>
                  <input
                    type="checkbox"
                    className="checkbox"
                    checked={selectedAlerts.includes(alert.id)}
                    onChange={() => toggleAlert(alert.id)}
                    aria-label="Select alert"
                  />
                </td>
                <td className="mono muted nowrap">{formatDateTime(alert.timestamp)}</td>
                <td><span className={`badge ${alert.severity}`}>{alert.severity}</span></td>
                <td className="nowrap">
                  {alert.type}
                  {alert.mitre_technique && (
                    <div className="list-sub" title={`${alert.mitre_tactic}: ${alert.mitre_name}`}>
                      {alert.mitre_technique} · {alert.mitre_tactic}
                    </div>
                  )}
                </td>
                <td>
                  {isIp(alert.source) ? (
                    <button className="link" onClick={() => openEntity({ type: 'ip', id: alert.source })}>
                      {alert.source}
                    </button>
                  ) : (
                    <span className="mono">{alert.source}</span>
                  )}
                </td>
                <td className="mono muted">{alert.destination}</td>
                <td className="truncate" title={alert.description}>{alert.description}</td>
                <td><span className={`badge ${alert.status}`}>{alert.status}</span></td>
                <td>
                  <div className="row-actions">
                    {alert.status === 'open' && (
                      <button className="icon-btn" title="Acknowledge and investigate" onClick={() => updateStatus([alert.id], 'acknowledge')}>
                        <Icon name="eye" size={15} />
                      </button>
                    )}
                    {alert.status !== 'resolved' ? (
                      <button className="icon-btn" title="Resolve" onClick={() => updateStatus([alert.id], 'resolve')}>
                        <Icon name="check" size={15} />
                      </button>
                    ) : (
                      <button className="icon-btn" title="Reopen" onClick={() => updateStatus([alert.id], 'reopen')}>
                        <Icon name="undo" size={15} />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {alerts.length === 0 && !error && (
          <div className="empty">
            {loading ? 'Loading alerts…' : 'No alerts match this time range and filter.'}
          </div>
        )}
      </div>

      <div className="table-footer">
        <span>Showing {first}–{last} of {formatNumber(total)}</span>
        <div className="pager">
          <button className="btn small" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <button className="btn small" disabled={last >= total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </div>
    </div>
  );
};

export default Alerts;
