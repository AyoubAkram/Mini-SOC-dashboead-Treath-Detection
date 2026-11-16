import React, { useEffect } from 'react';
import Icon from './Icons';
import {
  EntityProfile, EntityRef, SEVERITY_COLORS, buildUrl, formatDateTime, formatNumber, riskLevel, titleCase, useApi
} from '../api';

interface EntityDrawerProps {
  entity: EntityRef;
  refreshKey: number;
  onClose: () => void;
}

const COMPONENTS: { key: 'ml' | 'baseline' | 'rules' | 'coordinated'; label: string; color: string }[] = [
  { key: 'ml', label: 'ML anomaly score', color: SEVERITY_COLORS.ml },
  { key: 'baseline', label: 'Deviation from own past', color: SEVERITY_COLORS.accent },
  { key: 'rules', label: 'Rule-based alerts', color: SEVERITY_COLORS.high },
  { key: 'coordinated', label: 'Coordinated activity', color: SEVERITY_COLORS.critical }
];

/** Entity profile: risk score and what it is made of, baseline, ML alerts, recent logs. */
const EntityDrawer = ({ entity, refreshKey, onClose }: EntityDrawerProps) => {
  const url = buildUrl(`/api/entities/${entity.type}/${encodeURIComponent(entity.id)}`);
  const { data, error, loading } = useApi<EntityProfile>(url, refreshKey);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const risk = data?.risk;
  const level = riskLevel(risk?.risk_score ?? 0);
  const baseline = data?.baseline ? Object.entries(data.baseline.mean).sort((a, b) => b[1] - a[1]).slice(0, 8) : [];

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Entity profile">
        <div className="drawer-header">
          <div>
            <span className="badge neutral plain">{entity.type === 'ip' ? 'IP address' : 'User'}</span>
            <h2 style={{ marginTop: 8 }}>{entity.id}</h2>
            {data && <p className="muted" style={{ fontSize: 12.5 }}>{formatNumber(data.total_logs)} logs in total</p>}
          </div>
          <button className="icon-btn" onClick={onClose} title="Close"><Icon name="close" size={16} /></button>
        </div>

        <div className="drawer-body">
          {error && <div className="banner info">Nothing is known about this entity yet.</div>}
          {loading && !data && <div className="empty">Loading profile…</div>}

          {data && (
            <>
              <section className="drawer-section">
                <h3>Risk score</h3>
                {risk ? (
                  <>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 10 }}>
                      <span style={{ fontSize: 36, fontWeight: 680, color: SEVERITY_COLORS[level], lineHeight: 1 }}>
                        {risk.risk_score.toFixed(0)}
                      </span>
                      <span className="muted">/ 100 · {risk.anomalous_windows} of {risk.windows} windows anomalous</span>
                    </div>
                    {COMPONENTS.map((component) => (
                      <div key={component.key} className="component-row">
                        <span>{component.label}</span>
                        <div className="bar">
                          <span style={{ width: `${100 * risk.components[component.key]}%`, background: component.color }} />
                        </div>
                        <b>{(100 * risk.components[component.key]).toFixed(0)}%</b>
                      </div>
                    ))}
                  </>
                ) : (
                  <p className="muted">Not scored yet. Scores appear after the next ML detection run.</p>
                )}
              </section>

              {data.anomalies.length > 0 && (
                <section className="drawer-section">
                  <h3>ML alerts</h3>
                  {data.anomalies.slice(0, 5).map((anomaly) => (
                    <div key={anomaly.id} className="mini-log">
                      <div className="meta">
                        <span className={`badge ${anomaly.severity.toLowerCase()}`}>{anomaly.severity}</span>
                        <span>{formatDateTime(anomaly.timestamp)}</span>
                        <span>score {anomaly.anomaly_score.toFixed(2)}</span>
                        {anomaly.cluster && <span className="badge ml plain">cluster {anomaly.cluster}</span>}
                      </div>
                      <div className="reasons" style={{ marginTop: 6 }}>
                        {anomaly.explanation.map((reason) => (
                          <span key={reason.feature} className="chip">
                            {reason.label} <b>{formatNumber(reason.value)}</b> · typical {formatNumber(reason.typical)}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </section>
              )}

              {baseline.length > 0 && (
                <section className="drawer-section">
                  <h3>Usual behaviour · average per 10 minutes over {data.baseline?.windows} windows</h3>
                  <div className="reasons">
                    {baseline.map(([name, value]) => (
                      <span key={name} className="chip">{titleCase(name)} <b>{formatNumber(value)}</b></span>
                    ))}
                  </div>
                </section>
              )}

              <section className="drawer-section">
                <h3>Recent logs</h3>
                {data.recent_logs.length === 0 && <p className="muted">No logs for this entity.</p>}
                {data.recent_logs.slice(0, 12).map((log) => (
                  <div key={log.id} className="mini-log">
                    <div className="meta">
                      <span className="mono">{formatDateTime(log.timestamp)}</span>
                      <span className="badge neutral plain">{log.log_source}</span>
                      <span>{titleCase(log.event_type)}</span>
                    </div>
                    <div style={{ wordBreak: 'break-word' }}>{log.message}</div>
                  </div>
                ))}
              </section>
            </>
          )}
        </div>
      </aside>
    </>
  );
};

export default EntityDrawer;
