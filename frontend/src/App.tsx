import React, { useCallback, useEffect, useState } from 'react';
import Icon from './components/Icons';
import EntityDrawer from './components/EntityDrawer';
import Dashboard from './pages/Dashboard';
import AlertsPage from './pages/AlertsPage';
import Hunting from './pages/Hunting';
import Entities from './pages/Entities';
import { EntityRef, ModelsResponse, StatsResponse, TimeRange, buildUrl, formatNumber, useApi } from './api';
import './styles/index.css';

type Page = 'overview' | 'alerts' | 'hunting' | 'entities';

const REFRESH_SECONDS = 10;

const PAGES: { id: Page; label: string; icon: string; title: string; subtitle: string }[] = [
  { id: 'overview', label: 'Overview', icon: 'overview', title: 'Security overview', subtitle: 'What is happening across all log sources' },
  { id: 'alerts', label: 'Alerts', icon: 'alerts', title: 'Alerts', subtitle: 'Triage rule-based and ML-detected alerts' },
  { id: 'hunting', label: 'Threat hunting', icon: 'search', title: 'Threat hunting', subtitle: 'Search every normalized log' },
  { id: 'entities', label: 'Entities & ML', icon: 'entities', title: 'Entities and ML', subtitle: 'Risk per IP and user, and the model behind it' }
];

const RANGES: TimeRange[] = ['1h', '24h', '7d', '30d'];

function App() {
  // The page lives in the URL hash (#alerts, #hunting, ...) so views can be linked and reloaded
  const [page, setPageState] = useState<Page>(() => {
    const fromHash = window.location.hash.slice(1) as Page;
    return PAGES.some((item) => item.id === fromHash) ? fromHash : 'overview';
  });
  const setPage = (next: Page) => {
    window.location.hash = next;
    setPageState(next);
  };
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [refreshKey, setRefreshKey] = useState<number>(0);
  const [entity, setEntity] = useState<EntityRef | null>(null);

  const refresh = useCallback(() => setRefreshKey((key) => key + 1), []);
  const closeEntity = useCallback(() => setEntity(null), []);

  // Poll the API until the WebSocket feed exists
  useEffect(() => {
    const timer = setInterval(refresh, REFRESH_SECONDS * 1000);
    return () => clearInterval(timer);
  }, [refresh]);

  const stats = useApi<StatsResponse>(buildUrl('/api/stats', { time_range: timeRange }), refreshKey);
  const models = useApi<ModelsResponse>('/api/ml/models', refreshKey);
  const current = PAGES.find((item) => item.id === page) as (typeof PAGES)[number];
  const pageProps = { timeRange, refreshKey, refresh, openEntity: setEntity };
  const apiUp = !stats.error;
  const dbUp = apiUp && (stats.data?.database_connected ?? false);
  const alertCount = (stats.data?.active_alerts ?? 0) + (stats.data?.ml_alerts ?? 0);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Icon name="shield" size={19} /></div>
          <div>
            <div className="brand-name">ARGUS</div>
            <div className="brand-sub">Security operations</div>
          </div>
        </div>
        <nav className="nav">
          {PAGES.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${page === item.id ? 'active' : ''}`}
              onClick={() => setPage(item.id)}
            >
              <Icon name={item.icon} />
              {item.label}
              {item.id === 'alerts' && alertCount > 0 && <span className="nav-count">{formatNumber(alertCount)}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="status-line">
            <span><span className={`dot ${apiUp ? 'ok' : 'bad'}`} />API</span>
            <span>{apiUp ? 'online' : 'offline'}</span>
          </div>
          <div className="status-line">
            <span><span className={`dot ${dbUp ? 'ok' : 'bad'}`} />MongoDB</span>
            <span>{dbUp ? 'connected' : 'unreachable'}</span>
          </div>
          <div className="status-line">
            <span><span className={`dot ${models.data?.active ? 'ok' : ''}`} />ML model</span>
            <span>{models.data?.active ?? 'none'}</span>
          </div>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div>
            <h1>{current.title}</h1>
            <p>{current.subtitle}</p>
          </div>
          <div className="topbar-controls">
            <span className="live"><span className={`dot ${apiUp ? 'ok' : 'bad'}`} />{apiUp ? `Live · every ${REFRESH_SECONDS}s` : 'Disconnected'}</span>
            {page !== 'hunting' && page !== 'entities' && (
              <div className="segmented" role="group" aria-label="Time range">
                {RANGES.map((range) => (
                  <button key={range} className={timeRange === range ? 'active' : ''} onClick={() => setTimeRange(range)}>
                    {range}
                  </button>
                ))}
              </div>
            )}
            <button className="btn" onClick={refresh}><Icon name="refresh" size={15} /> Refresh</button>
          </div>
        </header>

        <main className="content">
          {stats.error && (
            <div className="banner">
              Cannot reach the API ({stats.error}). Start the backend with: python backend/main.py
            </div>
          )}
          {stats.data && !stats.data.database_connected && (
            <div className="banner">The API is running but MongoDB is not reachable, so no data can be shown.</div>
          )}

          {page === 'overview' && <Dashboard {...pageProps} stats={stats.data} />}
          {page === 'alerts' && <AlertsPage {...pageProps} stats={stats.data} />}
          {page === 'hunting' && <Hunting {...pageProps} />}
          {page === 'entities' && <Entities {...pageProps} />}
        </main>
      </div>

      {entity && <EntityDrawer entity={entity} refreshKey={refreshKey} onClose={closeEntity} />}
    </div>
  );
}

export default App;
