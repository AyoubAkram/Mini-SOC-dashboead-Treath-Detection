import React, { useState } from 'react';
import Stats from '../components/Stats';
import Alerts from '../components/Alerts';
import { AlertVolumeChart, AttackTypesChart, DetectionSplit, ThreatGauge, VolumeLegend } from '../components/Charts';
import {
  AttackTypesResponse, EntitiesResponse, PageProps, RANGE_LABELS, SourceIpsResponse, StatsResponse,
  ThreatsResponse, TimelineResponse, VolumeResponse, buildUrl, formatNumber, formatTime, request,
  riskLevel, timeAgo, useApi
} from '../api';
import '../styles/dashboard.css';

interface DashboardProps extends PageProps {
  stats: StatsResponse | null;
}

const Dashboard = (props: DashboardProps) => {
  const { timeRange, refreshKey, refresh, openEntity, stats } = props;
  const [filterLevel, setFilterLevel] = useState<string>('all');

  const range = { time_range: timeRange };
  const volume = useApi<VolumeResponse>(buildUrl('/api/alert-volume', range), refreshKey);
  const attackTypes = useApi<AttackTypesResponse>(buildUrl('/api/attack-types', range), refreshKey);
  const threats = useApi<ThreatsResponse>(
    buildUrl('/api/threats', { ...range, limit: 5, severity: filterLevel === 'all' ? undefined : filterLevel }),
    refreshKey
  );
  const timeline = useApi<TimelineResponse>(buildUrl('/api/timeline', { ...range, limit: 6 }), refreshKey);
  const sourceIps = useApi<SourceIpsResponse>(buildUrl('/api/source-ips', { ...range, limit: 6 }), refreshKey);
  const entities = useApi<EntitiesResponse>(buildUrl('/api/ml/entities', { limit: 6, min_score: 1 }), refreshKey);

  const investigate = async (id: string) => {
    try {
      await request(`/api/threats/${id}/investigate`, 'POST');
    } finally {
      refresh();
    }
  };

  const buckets = volume.data?.buckets ?? [];
  const sources = sourceIps.data?.source_ips ?? [];
  const topSource = Math.max(1, ...sources.map((source) => source.event_count));
  const threatList = threats.data?.threats ?? [];
  const riskyEntities = entities.data?.entities ?? [];

  return (
    <>
      <Stats stats={stats} rangeLabel={RANGE_LABELS[timeRange]} />

      <div className="grid wide-narrow">
        <div className="card">
          <div className="card-header">
            <h2>Alert volume</h2>
            <VolumeLegend buckets={buckets} />
          </div>
          <div className="card-body">
            {buckets.length > 0 ? (
              <AlertVolumeChart buckets={buckets} bucketMinutes={volume.data?.bucket_minutes ?? 60} />
            ) : (
              <div className="empty chart">{volume.loading ? 'Loading…' : 'No data.'}</div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2>Threat level</h2>
            <span className="hint">unresolved alerts</span>
          </div>
          <div className="card-body">
            <ThreatGauge stats={stats} />
            <div style={{ marginTop: 22 }}>
              <div className="card-header" style={{ padding: 0, marginBottom: 12 }}>
                <h2>Detection source</h2>
              </div>
              <DetectionSplit rule={stats?.rule_alerts ?? 0} ml={stats?.ml_alerts ?? 0} />
            </div>
          </div>
        </div>
      </div>

      <div className="grid cols-3">
        <div className="card">
          <div className="card-header">
            <h2>Attack types</h2>
          </div>
          <div className="card-body">
            {(attackTypes.data?.attack_types.length ?? 0) > 0 ? (
              <AttackTypesChart types={attackTypes.data?.attack_types ?? []} />
            ) : (
              <div className="empty">No alerts in the {RANGE_LABELS[timeRange]}.</div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2>Top source IPs</h2>
            <span className="hint">by events</span>
          </div>
          <div className="card-body">
            {sources.map((source) => (
              <div key={source.ip} className="rank-row">
                <div className="rank-label">
                  <button className="link" onClick={() => openEntity({ type: 'ip', id: source.ip })}>{source.ip}</button>
                  <span className={`badge plain ${source.location === 'External' ? 'high' : 'neutral'}`}>
                    {source.location === 'External' ? 'external' : 'internal'}
                  </span>
                </div>
                <span className="count">{formatNumber(source.event_count)}</span>
                <div className="bar"><span style={{ width: `${100 * source.event_count / topSource}%` }} /></div>
              </div>
            ))}
            {sourceIps.data && sources.length === 0 && <div className="empty">No source IPs.</div>}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2>Highest risk entities</h2>
            <span className="hint">ML + rules</span>
          </div>
          <div className="card-body list">
            {riskyEntities.map((entity) => (
              <div key={entity.id} className="list-row">
                <span className={`risk-pill ${riskLevel(entity.risk_score)}`}>{entity.risk_score.toFixed(0)}</span>
                <div className="list-main">
                  <button className="link" onClick={() => openEntity({ type: entity.entity_type, id: entity.entity })}>
                    {entity.entity}
                  </button>
                  <div className="list-sub">
                    {entity.entity_type === 'ip' ? 'IP' : 'User'}
                    {entity.top_reasons.length > 0 ? ` · ${entity.top_reasons.slice(0, 2).join(', ')}` : ''}
                  </div>
                </div>
              </div>
            ))}
            {entities.data && riskyEntities.length === 0 && (
              <div className="empty">No scores yet. Train a model on the Entities page.</div>
            )}
          </div>
        </div>
      </div>

      <div className="grid wide-narrow">
        <div className="card">
          <div className="card-header">
            <h2>Active threats</h2>
            <div className="segmented">
              {['all', 'critical', 'high'].map((level) => (
                <button key={level} className={filterLevel === level ? 'active' : ''} onClick={() => setFilterLevel(level)}>
                  {level === 'all' ? 'All' : level === 'critical' ? 'Critical' : 'High'}
                </button>
              ))}
            </div>
          </div>
          <div className="card-body list">
            {/* Unresolved alerts raised by the IDS sensor */}
            {threatList.map((threat) => (
              <div key={threat.id} className="list-row">
                <span className={`sev-stripe ${threat.severity}`} />
                <div className="list-main">
                  <div className="list-title">{threat.title}</div>
                  <div className="list-sub">
                    <span className="mono">{threat.source} → {threat.target}</span> · {timeAgo(threat.timestamp)}
                    {threat.description ? ` · ${threat.description}` : ''}
                  </div>
                </div>
                <span className={`badge ${threat.severity}`}>{threat.severity}</span>
                <button
                  className="btn small"
                  disabled={threat.status === 'investigating'}
                  onClick={() => investigate(threat.id)}
                >
                  {threat.status === 'investigating' ? 'Investigating' : 'Investigate'}
                </button>
              </div>
            ))}
            {threatList.length === 0 && (
              <div className="empty">
                {threats.loading ? 'Loading threats…' : `No active threats in the ${RANGE_LABELS[timeRange]}.`}
              </div>
            )}
            {(threats.data?.total ?? 0) > threatList.length && (
              <div className="list-sub" style={{ paddingTop: 12 }}>
                {formatNumber((threats.data?.total ?? 0) - threatList.length)} more in the Alerts view
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2>Latest high-severity events</h2>
          </div>
          <div className="card-body list">
            {/* TODO: Replace polling with the WebSocket alert feed */}
            {(timeline.data?.timeline ?? []).map((event) => (
              <div key={event.id} className="list-row">
                <span className={`sev-stripe ${event.severity}`} />
                <div className="list-main">
                  <div className="list-title">{event.description}</div>
                  <div className="list-sub">{event.title} · {formatTime(event.timestamp)}</div>
                </div>
              </div>
            ))}
            {timeline.data?.timeline.length === 0 && <div className="empty">Nothing high or critical.</div>}
          </div>
        </div>
      </div>

      <Alerts {...props} pageSize={8} title="Recent security alerts" />
    </>
  );
};

export default Dashboard;
