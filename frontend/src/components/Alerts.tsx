import React, { useEffect, useState } from 'react';
import {
  Alert, AlertsResponse, TimeRange, buildUrl, formatDateTime, formatNumber, setAlertStatus, useApi
} from '../api';
import '../styles/alerts.css';

interface AlertsProps {
  timeRange: TimeRange;
  refreshKey: number;
  onChange: () => void;
}

const PAGE_SIZE = 10;

// Filter dropdown value -> query parameters of GET /api/alerts
const FILTERS: Record<string, { label: string; severity?: string; status?: string }> = {
  all: { label: 'All Alerts' },
  unresolved: { label: 'Unresolved', status: 'unresolved' },
  critical: { label: 'Critical Only', severity: 'critical' },
  high: { label: 'High Only', severity: 'high' },
  medium: { label: 'Medium Only', severity: 'medium' },
  resolved: { label: 'Resolved', status: 'resolved' }
};

const csvCell = (value: string | null): string => `"${String(value ?? '').replace(/"/g, '""')}"`;

const Alerts = ({ timeRange, refreshKey, onChange }: AlertsProps) => {
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
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    time_range: timeRange,
    severity: FILTERS[filter].severity,
    status: FILTERS[filter].status,
    search
  });
  const { data, error, loading } = useApi<AlertsResponse>(url, refreshKey);
  const alerts: Alert[] = data?.alerts ?? [];
  const total = data?.total ?? 0;
  const first = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const last = Math.min((page + 1) * PAGE_SIZE, total);
  const pageIds = alerts.map((alert) => alert.id);
  const allSelected = pageIds.length > 0 && pageIds.every((id) => selectedAlerts.includes(id));

  // Resolving alerts can leave the current page empty
  useEffect(() => {
    if (data && page > 0 && page * PAGE_SIZE >= data.total) {
      setPage(Math.max(Math.ceil(data.total / PAGE_SIZE) - 1, 0));
    }
  }, [data, page]);

  const toggleAlert = (id: string) => {
    setSelectedAlerts(prev =>
      prev.includes(id) ? prev.filter(a => a !== id) : [...prev, id]
    );
  };

  const toggleAll = () => {
    setSelectedAlerts(allSelected ? [] : pageIds);
  };

  const updateStatus = async (ids: string[], action: 'acknowledge' | 'resolve' | 'reopen') => {
    try {
      await Promise.all(ids.map((id) => setAlertStatus(id, action)));
      setActionError(null);
      setSelectedAlerts(prev => prev.filter((id) => !ids.includes(id)));
    } catch (err) {
      setActionError((err as Error).message);
    }
    onChange();
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

  const getSeverityColor = (severity: string): string => {
    const colors: Record<string, string> = {
      critical: '#ff3333',
      high: '#ff9933',
      medium: '#ffcc33',
      low: '#33cc33'
    };
    return colors[severity] || '#999';
  };

  const getStatusBadge = (status: string): { text: string; class: string } => {
    const badges: Record<string, { text: string; class: string }> = {
      open: { text: 'Open', class: 'badge-open' },
      investigating: { text: 'Investigating', class: 'badge-investigating' },
      resolved: { text: 'Resolved', class: 'badge-resolved' }
    };
    return badges[status] || { text: status, class: 'badge-default' };
  };

  return (
    <div className="alerts-container">
      <div className="alerts-header">
        <h2>🔔 Recent Security Alerts</h2>
        <div className="alerts-controls">
          {selectedAlerts.length > 0 && (
            <>
              <button className="btn-secondary" onClick={() => updateStatus(selectedAlerts, 'acknowledge')}>
                Acknowledge ({selectedAlerts.length})
              </button>
              <button className="btn-secondary" onClick={() => updateStatus(selectedAlerts, 'resolve')}>
                Resolve ({selectedAlerts.length})
              </button>
            </>
          )}
          <input
            type="text"
            placeholder="Search alerts..."
            className="search-input"
            value={searchText}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchText(e.target.value)}
          />
          <select
            className="filter-select"
            value={filter}
            onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFilter(e.target.value)}
          >
            {Object.entries(FILTERS).map(([key, item]) => (
              <option key={key} value={key}>{item.label}</option>
            ))}
          </select>
          <button className="btn-secondary" onClick={exportCsv} disabled={alerts.length === 0}>
            Export
          </button>
        </div>
      </div>

      {(error || actionError) && (
        <div className="data-message error">Could not reach the API: {error || actionError}</div>
      )}

      <div className="alerts-table-wrapper">
        <table className="alerts-table">
          <thead>
            <tr>
              <th style={{width: '40px'}}>
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={toggleAll}
                  disabled={alerts.length === 0}
                />
              </th>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Alert Type</th>
              <th>Source IP</th>
              <th>Destination</th>
              <th>Description</th>
              <th>Status</th>
              <th style={{width: '100px'}}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id} className={`alert-row severity-${alert.severity}`}>
                <td>
                  <input
                    type="checkbox"
                    checked={selectedAlerts.includes(alert.id)}
                    onChange={() => toggleAlert(alert.id)}
                  />
                </td>
                <td className="timestamp">{formatDateTime(alert.timestamp)}</td>
                <td>
                  <span
                    className="severity-badge"
                    style={{backgroundColor: getSeverityColor(alert.severity)}}
                  >
                    {alert.severity.toUpperCase()}
                  </span>
                </td>
                <td className="alert-type">{alert.type}</td>
                <td className="ip">{alert.source}</td>
                <td className="ip">{alert.destination}</td>
                <td className="description" title={alert.description}>
                  {alert.description}
                </td>
                <td>
                  <span className={`status-badge ${getStatusBadge(alert.status).class}`}>
                    {getStatusBadge(alert.status).text}
                  </span>
                </td>
                <td className="actions">
                  {alert.status === 'open' && (
                    <button
                      className="btn-action-sm"
                      title="Acknowledge and investigate"
                      onClick={() => updateStatus([alert.id], 'acknowledge')}
                    >
                      🔍
                    </button>
                  )}
                  {alert.status !== 'resolved' ? (
                    <button
                      className="btn-action-sm"
                      title="Resolve"
                      onClick={() => updateStatus([alert.id], 'resolve')}
                    >
                      ✓
                    </button>
                  ) : (
                    <button
                      className="btn-action-sm"
                      title="Reopen"
                      onClick={() => updateStatus([alert.id], 'reopen')}
                    >
                      ↺
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {alerts.length === 0 && !error && (
          <div className="data-message">
            {loading ? 'Loading alerts...' : 'No alerts match this time range and filter.'}
          </div>
        )}
      </div>

      <div className="alerts-pagination">
        <span>Showing {first}-{last} of {formatNumber(total)} alerts</span>
        <div className="pagination-controls">
          <button disabled={page === 0} onClick={() => setPage(page - 1)}>← Previous</button>
          <button disabled={last >= total} onClick={() => setPage(page + 1)}>Next →</button>
        </div>
      </div>
    </div>
  );
};

export default Alerts;
