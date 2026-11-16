import React from 'react';
import { MitreResponse, PageProps, RANGE_LABELS, buildUrl, formatNumber, useApi } from '../api';
import '../styles/alerts.css';
import '../styles/stats.css';

/** MITRE ATT&CK matrix: what the platform can detect, how, and what it has seen. */
const Mitre = ({ timeRange, refreshKey }: PageProps) => {
  const { data, error, loading } = useApi<MitreResponse>(buildUrl('/api/mitre', { time_range: timeRange }), refreshKey);
  const tactics = data?.tactics ?? [];
  const totalAlerts = tactics.reduce((sum, tactic) => sum + tactic.alerts, 0);

  const cards = [
    { label: 'Techniques covered', value: data?.techniques_covered, note: 'Detectable by rules or ML', color: 'var(--accent)' },
    { label: 'Tactics covered', value: data ? `${data.tactics_covered} / ${tactics.length}` : undefined, note: 'Of the enterprise tactics', color: 'var(--ml)' },
    { label: 'Techniques seen', value: data?.techniques_seen, note: `With alerts in the ${RANGE_LABELS[timeRange]}`, color: 'var(--critical)' },
    { label: 'Tagged alerts', value: data ? formatNumber(totalAlerts) : undefined, note: 'Alerts mapped to a technique', color: 'var(--high)' }
  ];

  return (
    <>
      <div className="kpis">
        {cards.map((card) => (
          <div key={card.label} className="card kpi" style={{ '--kpi-color': card.color } as React.CSSProperties}>
            <span className="kpi-label">{card.label}</span>
            <div className="kpi-value">{card.value ?? '—'}</div>
            <div className="kpi-note">{card.note}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="toolbar">
          <h2>Coverage matrix</h2>
          <span className="badge neutral plain">rules</span>
          <span className="badge ml plain">ML</span>
          <span className="muted" style={{ fontSize: 12.5 }}>Highlighted techniques have alerts in the {RANGE_LABELS[timeRange]}</span>
        </div>
        {error && <div className="banner" style={{ margin: '0 18px 12px' }}>Could not reach the API: {error}</div>}
        {loading && !data && <div className="empty">Loading…</div>}
        <div className="matrix">
          {tactics.map((tactic) => (
            <div key={tactic.id} className="matrix-column">
              <div className={`matrix-tactic ${tactic.techniques.length === 0 ? 'empty' : ''}`}>
                {tactic.name}
                <span>{tactic.id}{tactic.alerts > 0 ? ` · ${formatNumber(tactic.alerts)} alerts` : ''}</span>
              </div>
              {tactic.techniques.map((technique) => {
                const count = technique.rule_alerts + technique.ml_alerts;
                return (
                  <div key={technique.id} className={`technique ${count > 0 ? 'seen' : ''}`}>
                    <div className="technique-id">{technique.id}</div>
                    <div className="technique-name">{technique.name}</div>
                    {count > 0 && (
                      <div className="technique-count" title={`${technique.rule_alerts} rule-based, ${technique.ml_alerts} ML`}>
                        {formatNumber(count)}
                      </div>
                    )}
                    <div className="reasons">
                      {technique.rules && <span className="badge neutral plain">rules</span>}
                      {technique.ml && <span className="badge ml plain">ML</span>}
                    </div>
                  </div>
                );
              })}
              {tactic.techniques.length === 0 && <div className="matrix-gap">No detection yet</div>}
            </div>
          ))}
        </div>
      </div>
    </>
  );
};

export default Mitre;
