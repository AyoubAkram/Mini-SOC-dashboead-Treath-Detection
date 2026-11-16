import React, { useState } from 'react';
import Alerts from '../components/Alerts';
import Icon from '../components/Icons';
import {
  AnomaliesResponse, PageProps, SEVERITY_COLORS, StatsResponse, buildUrl, formatDateTime, formatNumber,
  request, useApi
} from '../api';
import '../styles/alerts.css';

interface AlertsPageProps extends PageProps {
  stats: StatsResponse | null;
}

const PAGE_SIZE = 15;

/** ML-detected alerts: what was unusual, compared with what is typical. */
const Anomalies = ({ timeRange, refreshKey, refresh, openEntity }: PageProps) => {
  const [page, setPage] = useState<number>(0);
  const [showResolved, setShowResolved] = useState<boolean>(false);
  const url = buildUrl('/api/ml/anomalies', {
    time_range: timeRange,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    resolved: showResolved ? undefined : false
  });
  const { data, error, loading } = useApi<AnomaliesResponse>(url, refreshKey);
  const anomalies = data?.anomalies ?? [];
  const total = data?.total ?? 0;
  const last = Math.min((page + 1) * PAGE_SIZE, total);

  const setResolved = async (id: string, resolved: boolean) => {
    try {
      await request(buildUrl(`/api/ml/anomalies/${id}/resolve`, { resolved }), 'PATCH');
    } finally {
      refresh();
    }
  };

  return (
    <>
      <div className="toolbar">
        <h2>Behaviour the model found unusual</h2>
        <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 13 }}>
          <input
            type="checkbox"
            className="checkbox"
            checked={showResolved}
            onChange={() => { setShowResolved(!showResolved); setPage(0); }}
          />
          Show resolved
        </label>
      </div>
      {error && <div className="banner" style={{ margin: '0 18px 12px' }}>Could not reach the API: {error}</div>}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Window</th>
              <th>Severity</th>
              <th>Entity</th>
              <th>Anomaly score</th>
              <th>Why it stands out</th>
              <th>Model</th>
              <th style={{ width: 50 }}></th>
            </tr>
          </thead>
          <tbody>
            {anomalies.map((anomaly) => (
              <tr key={anomaly.id}>
                <td className="mono muted nowrap">{formatDateTime(anomaly.timestamp)}</td>
                <td><span className={`badge ${anomaly.severity.toLowerCase()}`}>{anomaly.severity}</span></td>
                <td>
                  <button className="link" onClick={() => openEntity({ type: anomaly.entity_type, id: anomaly.entity })}>
                    {anomaly.entity}
                  </button>
                  <div className="list-sub">
                    {anomaly.entity_type === 'ip' ? 'IP' : 'User'}
                    {anomaly.cluster ? ` · coordinated (${anomaly.cluster})` : ''}
                  </div>
                </td>
                <td>
                  <div className="score">
                    <b>{anomaly.anomaly_score.toFixed(2)}</b>
                    <div className="bar">
                      <span style={{ width: `${100 * anomaly.anomaly_score}%`, background: SEVERITY_COLORS.ml }} />
                    </div>
                  </div>
                </td>
                <td>
                  <div className="reasons">
                    {anomaly.explanation.map((reason) => (
                      <span key={reason.feature} className="chip" title={`Typical: ${reason.typical}`}>
                        {reason.label} <b>{formatNumber(reason.value)}</b>
                      </span>
                    ))}
                    {anomaly.explanation.length === 0 && <span className="muted">unusual combination</span>}
                  </div>
                </td>
                <td className="mono muted">{anomaly.model_version}</td>
                <td>
                  <button
                    className="icon-btn"
                    title={anomaly.resolved ? 'Reopen' : 'Resolve'}
                    onClick={() => setResolved(anomaly.id, !anomaly.resolved)}
                  >
                    <Icon name={anomaly.resolved ? 'undo' : 'check'} size={15} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {anomalies.length === 0 && !error && (
          <div className="empty">
            {loading ? 'Loading…' : 'No ML alerts in this time range. Train a model and run detection on the Entities page.'}
          </div>
        )}
      </div>
      <div className="table-footer">
        <span>Showing {total === 0 ? 0 : page * PAGE_SIZE + 1}–{last} of {formatNumber(total)}</span>
        <div className="pager">
          <button className="btn small" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <button className="btn small" disabled={last >= total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      </div>
    </>
  );
};

const AlertsPage = (props: AlertsPageProps) => {
  const [tab, setTab] = useState<'rules' | 'ml'>('rules');
  return (
    <>
      <div className="card">
        <div className="tabs">
          <button className={`tab ${tab === 'rules' ? 'active' : ''}`} onClick={() => setTab('rules')}>
            Rule-based
            <span className="nav-count">{formatNumber(props.stats?.rule_alerts ?? 0)}</span>
          </button>
          <button className={`tab ${tab === 'ml' ? 'active' : ''}`} onClick={() => setTab('ml')}>
            ML-detected
            <span className="nav-count">{formatNumber(props.stats?.ml_alerts ?? 0)}</span>
          </button>
        </div>
        {tab === 'ml' && <Anomalies {...props} />}
      </div>
      {tab === 'rules' && <Alerts {...props} pageSize={15} title="Security events raised as alerts" />}
    </>
  );
};

export default AlertsPage;
