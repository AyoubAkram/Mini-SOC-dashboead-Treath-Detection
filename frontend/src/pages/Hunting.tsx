import React, { useEffect, useState } from 'react';
import {
  EventTypesResponse, LogsResponse, PageProps, buildUrl, formatDateTime, formatNumber, titleCase, useApi
} from '../api';
import '../styles/alerts.css';

const PAGE_SIZE = 25;
const LOG_SOURCES = ['linux_auth', 'windows_event', 'firewall', 'ids', 'web', 'cloudtrail', 'zeek', 'syslog'];

/** Threat hunting: search every normalized log, whatever its source. */
const Hunting = ({ refreshKey, openEntity }: PageProps) => {
  const [form, setForm] = useState({ search: '', source_ip: '', username: '', log_source: '', event_type: '' });
  const [query, setQuery] = useState(form);
  const [page, setPage] = useState<number>(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  // Results do not follow the auto-refresh: rows must not move while they are being read
  const [searchKey, setSearchKey] = useState<number>(0);

  useEffect(() => {
    const timer = setTimeout(() => { setQuery(form); setPage(0); }, 300);
    return () => clearTimeout(timer);
  }, [form]);

  const logs = useApi<LogsResponse>(
    buildUrl('/api/logs', { ...query, limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    searchKey
  );
  const eventTypes = useApi<EventTypesResponse>(buildUrl('/api/event-types', { time_range: '30d', limit: 30 }), refreshKey);

  const rows = logs.data?.logs ?? [];
  const total = logs.data?.total ?? 0;
  const last = Math.min((page + 1) * PAGE_SIZE, total);
  const update = (field: keyof typeof form) =>
    (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm({ ...form, [field]: event.target.value.trim() });
  const pivot = (field: 'source_ip' | 'username', value: string) => setForm({ ...form, [field]: value });

  return (
    <div className="card">
      <div className="toolbar">
        <h2>Log search</h2>
        <input className="input" placeholder="Text in message…" defaultValue={form.search} onChange={update('search')} />
        <input className="input" style={{ width: 150 }} placeholder="Source IP" value={form.source_ip} onChange={update('source_ip')} />
        <input className="input" style={{ width: 130 }} placeholder="User" value={form.username} onChange={update('username')} />
        <select className="select" value={form.log_source} onChange={update('log_source')}>
          <option value="">All sources</option>
          {LOG_SOURCES.map((source) => <option key={source} value={source}>{source}</option>)}
        </select>
        <select className="select" value={form.event_type} onChange={update('event_type')}>
          <option value="">All event types</option>
          {(eventTypes.data?.event_types ?? []).map((item) => (
            <option key={item.name} value={item.name}>{titleCase(item.name)}</option>
          ))}
        </select>
        <button className="btn" onClick={() => setSearchKey(searchKey + 1)}>Run again</button>
      </div>

      {logs.error && <div className="banner" style={{ margin: '0 18px 12px' }}>Could not reach the API: {logs.error}</div>}

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Event</th>
              <th>Source IP</th>
              <th>User</th>
              <th>Host</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((log) => (
              <React.Fragment key={log.id}>
                <tr
                  className={`clickable ${expanded === log.id ? 'expanded' : ''}`}
                  onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                >
                  <td className="mono muted nowrap">{formatDateTime(log.timestamp)}</td>
                  <td><span className="badge neutral plain">{log.log_source}</span></td>
                  <td className="nowrap">{titleCase(log.event_type)}</td>
                  <td>
                    {log.source_ip ? (
                      <button className="link" onClick={(e) => { e.stopPropagation(); openEntity({ type: 'ip', id: log.source_ip as string }); }}>
                        {log.source_ip}
                      </button>
                    ) : <span className="muted">—</span>}
                  </td>
                  <td>
                    {log.username ? (
                      <button className="link" onClick={(e) => { e.stopPropagation(); openEntity({ type: 'user', id: log.username as string }); }}>
                        {log.username}
                      </button>
                    ) : <span className="muted">—</span>}
                  </td>
                  <td className="mono muted">{log.host ?? '—'}</td>
                  <td className="truncate" title={log.message}>{log.message}</td>
                </tr>
                {expanded === log.id && (
                  <tr className="expanded">
                    <td colSpan={7}>
                      <div className="raw">{log.raw}</div>
                      <div className="row-actions" style={{ marginTop: 10 }}>
                        {log.source_ip && (
                          <button className="btn small" onClick={() => pivot('source_ip', log.source_ip as string)}>
                            All logs from {log.source_ip}
                          </button>
                        )}
                        {log.username && (
                          <button className="btn small" onClick={() => pivot('username', log.username as string)}>
                            All logs for {log.username}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && !logs.error && (
          <div className="empty">{logs.loading ? 'Searching…' : 'No logs match these filters.'}</div>
        )}
      </div>

      <div className="table-footer">
        <span>Showing {total === 0 ? 0 : page * PAGE_SIZE + 1}–{last} of {formatNumber(total)} logs</span>
        <div className="pager">
          <button className="btn small" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <button className="btn small" disabled={last >= total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </div>
    </div>
  );
};

export default Hunting;
