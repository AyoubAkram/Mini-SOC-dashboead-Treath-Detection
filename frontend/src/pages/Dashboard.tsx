import React, { useCallback, useEffect, useState } from 'react';
import Stats from '../components/Stats';
import Alerts from '../components/Alerts';
import {
  EventTypesResponse, SourceIpsResponse, StatsResponse, ThreatsResponse, TimeRange,
  TimelineResponse, buildUrl, formatNumber, formatTime, request, timeAgo, titleCase, useApi
} from '../api';
import '../styles/dashboard.css';

const REFRESH_SECONDS = 10;
const THREAT_PAGE = 5;

const RANGE_LABELS: Record<TimeRange, string> = {
  '1h': 'last hour',
  '24h': 'last 24 hours',
  '7d': 'last 7 days',
  '30d': 'last 30 days'
};

const SEVERITY_ICONS: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🟢'
};

const Dashboard = () => {
  const [filterLevel, setFilterLevel] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [refreshKey, setRefreshKey] = useState<number>(0);
  const [threatLimit, setThreatLimit] = useState<number>(THREAT_PAGE);

  const refresh = useCallback(() => setRefreshKey((key) => key + 1), []);

  // Poll the API until the WebSocket feed exists
  useEffect(() => {
    const timer = setInterval(refresh, REFRESH_SECONDS * 1000);
    return () => clearInterval(timer);
  }, [refresh]);

  const range = { time_range: timeRange };
  const stats = useApi<StatsResponse>(buildUrl('/api/stats', range), refreshKey);
  const threats = useApi<ThreatsResponse>(
    buildUrl('/api/threats', {
      ...range,
      limit: threatLimit,
      severity: filterLevel === 'all' ? undefined : filterLevel
    }),
    refreshKey
  );
  const timeline = useApi<TimelineResponse>(buildUrl('/api/timeline', { ...range, limit: 6 }), refreshKey);
  const eventTypes = useApi<EventTypesResponse>(buildUrl('/api/event-types', { ...range, limit: 6 }), refreshKey);
  const sourceIps = useApi<SourceIpsResponse>(buildUrl('/api/source-ips', { ...range, limit: 6 }), refreshKey);

  const investigate = async (id: string) => {
    try {
      await request(`/api/threats/${id}/investigate`, 'POST');
    } finally {
      refresh();
    }
  };

  const counts = stats.data?.severity_counts;
  const level = stats.data?.threat_level ?? 'low';
  const threatList = threats.data?.threats ?? [];
  const threatTotal = threats.data?.total ?? 0;

  return (
    <div className="dashboard">
      {/* Header */}
      <header className="dashboard-header">
        <div className="header-content">
          <div className="header-title">
            <h1>SOC Dashboard</h1>
            <p className="subtitle">Security Operations Center - Real-time Threat Detection</p>
          </div>
          <div className="header-controls">
            <select
              className="filter-select"
              value={timeRange}
              onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setTimeRange(e.target.value as TimeRange)}
            >
              <option value="1h">Last 1 Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
            <button className="btn-refresh" onClick={refresh}>🔄 Refresh</button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="dashboard-main">
        {stats.error && (
          <div className="data-message error">
            Cannot reach the API ({stats.error}). Start the backend with: python backend/main.py
          </div>
        )}
        {stats.data && !stats.data.database_connected && (
          <div className="data-message error">
            The API is running but MongoDB is not reachable, so no data can be shown.
          </div>
        )}

        {/* Stats Section */}
        <section className="stats-section">
          <Stats stats={stats.data} rangeLabel={RANGE_LABELS[timeRange]} />
        </section>

        {/* Middle Section - Events & Alerts */}
        <div className="middle-section">
          {/* Left Column - Threats & Events */}
          <div className="column left-column">
            <div className="card">
              <div className="card-header">
                <h2>🎯 Active Threats</h2>
                <div className="threat-filter">
                  <button
                    className={`threat-btn ${filterLevel === 'all' ? 'active' : ''}`}
                    onClick={() => setFilterLevel('all')}
                  >
                    All
                  </button>
                  <button
                    className={`threat-btn ${filterLevel === 'critical' ? 'active' : ''}`}
                    onClick={() => setFilterLevel('critical')}
                  >
                    🔴 Critical
                  </button>
                  <button
                    className={`threat-btn ${filterLevel === 'high' ? 'active' : ''}`}
                    onClick={() => setFilterLevel('high')}
                  >
                    🟠 High
                  </button>
                </div>
              </div>
              <div className="card-content">
                {/* Unresolved alerts raised by the IDS sensor */}
                <div className="threat-list">
                  {threatList.map((threat) => (
                    <div key={threat.id} className={`threat-item ${threat.severity}`}>
                      <div className="threat-icon">{SEVERITY_ICONS[threat.severity]}</div>
                      <div className="threat-details">
                        <h4>{threat.title}</h4>
                        <p>Source: {threat.source} | Target: {threat.target}</p>
                        <span className="timestamp">
                          {timeAgo(threat.timestamp)}
                          {threat.description ? ` · ${threat.description}` : ''}
                        </span>
                      </div>
                      <button
                        className="btn-action"
                        disabled={threat.status === 'investigating'}
                        onClick={() => investigate(threat.id)}
                      >
                        {threat.status === 'investigating' ? 'Investigating' : 'Investigate'}
                      </button>
                    </div>
                  ))}
                  {threatList.length === 0 && (
                    <div className="data-message">
                      {threats.loading ? 'Loading threats...' : `No active threats in the ${RANGE_LABELS[timeRange]}.`}
                    </div>
                  )}
                </div>
                {threatTotal > THREAT_PAGE && (
                  <div className="view-more">
                    {threatList.length < threatTotal ? (
                      <button onClick={() => setThreatLimit(threatLimit + 20)}>
                        View More Threats ({threatList.length} of {formatNumber(threatTotal)}) →
                      </button>
                    ) : (
                      <button onClick={() => setThreatLimit(THREAT_PAGE)}>Show Fewer</button>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Right Column - Stats & Timeline */}
          <div className="column right-column">
            {/* Threat Level Gauge */}
            <div className="card">
              <div className="card-header">
                <h2>⚡ Threat Level</h2>
              </div>
              <div className="card-content threat-gauge">
                <div className="gauge-container">
                  <div className="gauge-circle">
                    <div className={`gauge-value ${level}`}>
                      {stats.data ? stats.data.threat_score : '—'}
                    </div>
                    <div className="gauge-label">{stats.data ? level.toUpperCase() : ''}</div>
                  </div>
                  <div className="gauge-stats">
                    <div className="stat-item">
                      <span className="label">Critical Events</span>
                      <span className="value">{counts ? formatNumber(counts.critical) : '—'}</span>
                    </div>
                    <div className="stat-item">
                      <span className="label">High Events</span>
                      <span className="value">{counts ? formatNumber(counts.high) : '—'}</span>
                    </div>
                    <div className="stat-item">
                      <span className="label">Medium Events</span>
                      <span className="value">{counts ? formatNumber(counts.medium) : '—'}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Event Timeline */}
            <div className="card">
              <div className="card-header">
                <h2>📊 Event Timeline</h2>
              </div>
              <div className="card-content timeline">
                {/* TODO: Replace polling with the WebSocket alert feed */}
                {(timeline.data?.timeline ?? []).map((event) => (
                  <div key={event.id} className="timeline-item">
                    <div className={`timeline-dot ${event.severity}`}></div>
                    <div className="timeline-content">
                      <h4>{event.title}</h4>
                      <p>{event.description}</p>
                      <span>{formatTime(event.timestamp)}</span>
                    </div>
                  </div>
                ))}
                {timeline.data?.timeline.length === 0 && (
                  <div className="data-message">No high or critical events in the {RANGE_LABELS[timeRange]}.</div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Section - Alerts Table */}
        <section className="alerts-section">
          <Alerts timeRange={timeRange} refreshKey={refreshKey} onChange={refresh} />
        </section>

        {/* Bottom Section - Additional Analytics */}
        <div className="bottom-section">
          {/* Top Events */}
          <div className="card">
            <div className="card-header">
              <h2>📈 Top Event Types</h2>
            </div>
            <div className="card-content">
              <div className="event-types-list">
                {(eventTypes.data?.event_types ?? []).map((eventType) => (
                  <div key={eventType.name} className="event-type">
                    <div className="event-name">{titleCase(eventType.name)}</div>
                    <div className="event-bar">
                      <div className="bar-fill" style={{width: `${eventType.percentage}%`}}></div>
                    </div>
                    <div className="event-count">{formatNumber(eventType.count)} events</div>
                  </div>
                ))}
                {eventTypes.data?.event_types.length === 0 && (
                  <div className="data-message">No events in the {RANGE_LABELS[timeRange]}.</div>
                )}
              </div>
            </div>
          </div>

          {/* Top Sources */}
          <div className="card">
            <div className="card-header">
              <h2>🌍 Top Source IPs</h2>
            </div>
            <div className="card-content">
              {/* TODO: Add geolocation mapping for source IPs */}
              <div className="source-list">
                {(sourceIps.data?.source_ips ?? []).map((source) => (
                  <div key={source.ip} className="source-item">
                    <div className="source-info">
                      <div className="ip">{source.ip}</div>
                      <div className="location">{source.location}</div>
                    </div>
                    <div className="event-count">{formatNumber(source.event_count)} events</div>
                  </div>
                ))}
                {sourceIps.data?.source_ips.length === 0 && (
                  <div className="data-message">No source IPs in the {RANGE_LABELS[timeRange]}.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
