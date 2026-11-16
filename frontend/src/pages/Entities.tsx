import React, { useState } from 'react';
import Icon from '../components/Icons';
import {
  EntitiesResponse, ModelsResponse, PageProps, SEVERITY_COLORS, buildUrl, formatDateTime, formatNumber,
  request, riskLevel, useApi
} from '../api';
import '../styles/alerts.css';

interface DetectSummary {
  ran: boolean;
  reason?: string;
  anomalies: number;
  clusters: number;
  windows: number;
}

/** Entities ranked by risk, and the ML model that scores them. */
const Entities = ({ refreshKey, refresh, openEntity }: PageProps) => {
  const [entityType, setEntityType] = useState<string>('all');
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);

  const entities = useApi<EntitiesResponse>(
    buildUrl('/api/ml/entities', { limit: 50, entity_type: entityType === 'all' ? undefined : entityType }),
    refreshKey
  );
  const models = useApi<ModelsResponse>('/api/ml/models', refreshKey);
  const versions = models.data?.versions ?? [];
  const active = versions.find((version) => version.version === models.data?.active);
  const rows = entities.data?.entities ?? [];

  const run = async (label: string, action: () => Promise<string>) => {
    setBusy(label);
    try {
      setMessage({ text: await action(), error: false });
    } catch (err) {
      setMessage({ text: `${label} failed. ${(err as Error).message}`, error: true });
    }
    setBusy(null);
    refresh();
  };

  const train = () => run('Training', async () => {
    const version = await request<{ version: string }>('/api/ml/train', 'POST');
    return `Model ${version.version} trained on the last 24 hours and activated.`;
  });

  const detect = () => run('Detection', async () => {
    const summary = await request<DetectSummary>('/api/ml/detect', 'POST');
    if (!summary.ran) {
      return `Detection did not run: ${summary.reason}.`;
    }
    return `Scored ${formatNumber(summary.windows)} entity windows: ${summary.anomalies} anomalies, ${summary.clusters} coordinated clusters.`;
  });

  const activate = (version: string) => run('Activation', async () => {
    await request(`/api/ml/models/${version}/activate`, 'POST');
    return `Model ${version} is now active.`;
  });

  return (
    <>
      <div className="card">
        <div className="toolbar">
          <h2>Detection model</h2>
          <button className="btn" onClick={train} disabled={busy !== null}>
            <Icon name="cpu" size={15} /> {busy === 'Training' ? 'Training…' : 'Train new version'}
          </button>
          <button className="btn primary" onClick={detect} disabled={busy !== null || !active}>
            <Icon name="refresh" size={15} /> {busy === 'Detection' ? 'Scoring…' : 'Run detection now'}
          </button>
        </div>
        <div className="card-body" style={{ paddingTop: 0 }}>
          {message && (
            <div className={`banner ${message.error ? '' : 'info'}`} style={{ marginBottom: 14 }}>{message.text}</div>
          )}
          {active ? (
            <div className="model-grid">
              <div className="fact"><span>Active version</span><strong>{active.version}</strong></div>
              <div className="fact"><span>Trained</span><strong>{formatDateTime(active.trained_at)}</strong></div>
              <div className="fact">
                <span>Training windows</span>
                <strong>{formatNumber(active.samples.ip ?? 0)} IP · {formatNumber(active.samples.user ?? 0)} user</strong>
              </div>
              <div className="fact">
                <span>Isolation Forest</span>
                <strong>{active.params.n_estimators} trees · {(100 * active.params.contamination).toFixed(1)}%</strong>
              </div>
            </div>
          ) : (
            <div className="empty">
              {models.loading ? 'Loading…' : 'No model yet. Train one once some normal traffic has been ingested.'}
            </div>
          )}
          {versions.length > 1 && (
            <div className="reasons" style={{ marginTop: 14, alignItems: 'center' }}>
              <span className="muted" style={{ fontSize: 12.5 }}>Versions:</span>
              {versions.map((version) => (
                <button
                  key={version.version}
                  className={`btn small ${version.version === models.data?.active ? 'primary' : ''}`}
                  title={`${version.note} · ${formatDateTime(version.trained_at)}`}
                  disabled={busy !== null || version.version === models.data?.active}
                  onClick={() => activate(version.version)}
                >
                  {version.version}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="toolbar">
          <h2>Entities by risk</h2>
          <div className="segmented">
            {[['all', 'All'], ['ip', 'IPs'], ['user', 'Users']].map(([value, label]) => (
              <button key={value} className={entityType === value ? 'active' : ''} onClick={() => setEntityType(value)}>
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Risk</th>
                <th>Entity</th>
                <th>ML</th>
                <th>Own baseline</th>
                <th>Rules</th>
                <th>Why</th>
                <th>Events</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((entity) => (
                <tr
                  key={entity.id}
                  className="clickable"
                  onClick={() => openEntity({ type: entity.entity_type, id: entity.entity })}
                >
                  <td><span className={`risk-pill ${riskLevel(entity.risk_score)}`} style={{ display: 'inline-block' }}>{entity.risk_score.toFixed(0)}</span></td>
                  <td>
                    <span className="link">{entity.entity}</span>
                    <div className="list-sub">
                      {entity.entity_type === 'ip' ? 'IP' : 'User'}
                      {entity.components.coordinated ? ' · coordinated' : ''}
                    </div>
                  </td>
                  {(['ml', 'baseline', 'rules'] as const).map((key) => (
                    <td key={key}>
                      <div className="score" style={{ minWidth: 90 }}>
                        <div className="bar">
                          <span style={{
                            width: `${100 * entity.components[key]}%`,
                            background: key === 'ml' ? SEVERITY_COLORS.ml : key === 'baseline' ? SEVERITY_COLORS.accent : SEVERITY_COLORS.high
                          }} />
                        </div>
                      </div>
                    </td>
                  ))}
                  <td>
                    <div className="reasons">
                      {entity.top_reasons.slice(0, 2).map((reason) => <span key={reason} className="chip">{reason}</span>)}
                    </div>
                  </td>
                  <td className="mono muted">{formatNumber(entity.events)}</td>
                  <td className="mono muted nowrap">{formatDateTime(entity.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && (
            <div className="empty">{entities.loading ? 'Loading…' : 'No entities scored yet. Run detection to rank them.'}</div>
          )}
        </div>
      </div>
    </>
  );
};

export default Entities;
