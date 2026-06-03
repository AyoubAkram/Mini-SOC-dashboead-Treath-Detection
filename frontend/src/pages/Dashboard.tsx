import React, { useState } from 'react';
import Stats from '../components/Stats';
import Alerts from '../components/Alerts';
import '../styles/dashboard.css';

const Dashboard = () => {
  // TODO: Add state management for real-time data
  const [filterLevel, setFilterLevel] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('1h');

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
              onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setTimeRange(e.target.value)}
            >
              <option value="1h">Last 1 Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
            <button className="btn-refresh">🔄 Refresh</button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="dashboard-main">
        {/* Stats Section */}
        <section className="stats-section">
          <Stats />
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
                {/* TODO: Add real threat data from backend API */}
                <div className="threat-list">
                  <div className="threat-item critical">
                    <div className="threat-icon">🔴</div>
                    <div className="threat-details">
                      <h4>SQL Injection Attempt</h4>
                      <p>Source: 192.168.1.105 | Target: /api/users</p>
                      <span className="timestamp">2 minutes ago</span>
                    </div>
                    <button className="btn-action">Investigate</button>
                  </div>
                  <div className="threat-item high">
                    <div className="threat-icon">🟠</div>
                    <div className="threat-details">
                      <h4>Suspicious Port Scan</h4>
                      <p>Source: 203.45.67.89 | Ports scanned: 1-1000</p>
                      <span className="timestamp">15 minutes ago</span>
                    </div>
                    <button className="btn-action">Investigate</button>
                  </div>
                  <div className="threat-item medium">
                    <div className="threat-icon">🟡</div>
                    <div className="threat-details">
                      <h4>Failed Login Attempts</h4>
                      <p>User: admin@company.com | Attempts: 5</p>
                      <span className="timestamp">28 minutes ago</span>
                    </div>
                    <button className="btn-action">Investigate</button>
                  </div>
                </div>
                {/* TODO: Connect to backend for pagination and real-time updates */}
                <div className="view-more">
                  <button>View All Threats →</button>
                </div>
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
                {/* TODO: Add animated gauge component based on real threat score */}
                <div className="gauge-container">
                  <div className="gauge-circle">
                    <div className="gauge-value critical">7.8</div>
                    <div className="gauge-label">HIGH</div>
                  </div>
                  <div className="gauge-stats">
                    <div className="stat-item">
                      <span className="label">Critical Events</span>
                      <span className="value">3</span>
                    </div>
                    <div className="stat-item">
                      <span className="label">High Events</span>
                      <span className="value">12</span>
                    </div>
                    <div className="stat-item">
                      <span className="label">Medium Events</span>
                      <span className="value">24</span>
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
                {/* TODO: Add real-time event timeline with WebSocket connection */}
                <div className="timeline-item">
                  <div className="timeline-dot critical"></div>
                  <div className="timeline-content">
                    <h4>Critical Alert</h4>
                    <p>Malware detection - C2 communication</p>
                    <span>14:32:05</span>
                  </div>
                </div>
                <div className="timeline-item">
                  <div className="timeline-dot high"></div>
                  <div className="timeline-content">
                    <h4>Unauthorized Access</h4>
                    <p>Multiple failed authentication attempts</p>
                    <span>14:28:15</span>
                  </div>
                </div>
                <div className="timeline-item">
                  <div className="timeline-dot medium"></div>
                  <div className="timeline-content">
                    <h4>Anomalous Behavior</h4>
                    <p>Large data exfiltration detected</p>
                    <span>14:15:42</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Section - Alerts Table */}
        <section className="alerts-section">
          <Alerts />
        </section>

        {/* Bottom Section - Additional Analytics */}
        <div className="bottom-section">
          {/* Top Events */}
          <div className="card">
            <div className="card-header">
              <h2>📈 Top Event Types</h2>
            </div>
            <div className="card-content">
              {/* TODO: Add bar chart visualization component */}
              <div className="event-types-list">
                <div className="event-type">
                  <div className="event-name">Network Traffic Anomalies</div>
                  <div className="event-bar">
                    <div className="bar-fill" style={{width: '85%'}}></div>
                  </div>
                  <div className="event-count">1,245 events</div>
                </div>
                <div className="event-type">
                  <div className="event-name">Failed Authentication</div>
                  <div className="event-bar">
                    <div className="bar-fill" style={{width: '62%'}}></div>
                  </div>
                  <div className="event-count">892 events</div>
                </div>
                <div className="event-type">
                  <div className="event-name">Malware Detection</div>
                  <div className="event-bar">
                    <div className="bar-fill" style={{width: '45%'}}></div>
                  </div>
                  <div className="event-count">648 events</div>
                </div>
                <div className="event-type">
                  <div className="event-name">Data Exfiltration</div>
                  <div className="event-bar">
                    <div className="bar-fill" style={{width: '38%'}}></div>
                  </div>
                  <div className="event-count">547 events</div>
                </div>
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
                <div className="source-item">
                  <div className="source-info">
                    <div className="ip">192.168.1.105</div>
                    <div className="location">Internal Network</div>
                  </div>
                  <div className="event-count">234 events</div>
                </div>
                <div className="source-item">
                  <div className="source-info">
                    <div className="ip">203.45.67.89</div>
                    <div className="location">Unknown Location</div>
                  </div>
                  <div className="event-count">156 events</div>
                </div>
                <div className="source-item">
                  <div className="source-info">
                    <div className="ip">10.0.0.50</div>
                    <div className="location">Internal Network</div>
                  </div>
                  <div className="event-count">98 events</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
