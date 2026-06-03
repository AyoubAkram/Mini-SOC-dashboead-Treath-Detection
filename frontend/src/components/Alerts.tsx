import React, { useState } from 'react';
import '../styles/alerts.css';

const Alerts = () => {
  // TODO: Connect to backend API for real alert data
  // TODO: Add sorting, filtering, and pagination
  const [selectedAlerts, setSelectedAlerts] = useState<number[]>([]);

  const alerts = [
    {
      id: 1,
      timestamp: '2024-01-15 14:35:22',
      severity: 'critical',
      type: 'SQL Injection',
      source: '192.168.1.105',
      destination: '10.0.1.50:3306',
      description: 'Detected SQL injection pattern in HTTP request',
      status: 'open'
    },
    {
      id: 2,
      timestamp: '2024-01-15 14:28:15',
      severity: 'high',
      type: 'Port Scan',
      source: '203.45.67.89',
      destination: '10.0.0.0/24',
      description: 'Systematic port scanning detected',
      status: 'open'
    },
    {
      id: 3,
      timestamp: '2024-01-15 14:15:42',
      severity: 'high',
      type: 'Brute Force',
      source: '198.51.100.42',
      destination: '10.0.2.15:22',
      description: 'Multiple failed SSH login attempts',
      status: 'investigating'
    },
    {
      id: 4,
      timestamp: '2024-01-15 13:55:08',
      severity: 'medium',
      type: 'Anomalous Traffic',
      source: '10.0.3.200',
      destination: '8.8.8.8:53',
      description: 'Unusual DNS query pattern detected',
      status: 'investigating'
    },
    {
      id: 5,
      timestamp: '2024-01-15 13:42:31',
      severity: 'low',
      type: 'Policy Violation',
      source: '10.0.1.120',
      destination: '*.torrent.site',
      description: 'Access to restricted website detected',
      status: 'resolved'
    }
  ];

  // TODO: Implement actual toggle functionality
  const toggleAlert = (id: number) => {
    setSelectedAlerts(prev =>
      prev.includes(id) ? prev.filter(a => a !== id) : [...prev, id]
    );
  };

  // TODO: Implement bulk actions (acknowledge, resolve, assign)
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
          {/* TODO: Add search functionality */}
          <input 
            type="text" 
            placeholder="Search alerts..." 
            className="search-input"
            disabled
          />
          {/* TODO: Add more filter options */}
          <select className="filter-select" disabled>
            <option>All Alerts</option>
            <option>Critical Only</option>
            <option>Unresolved</option>
          </select>
          {/* TODO: Add export functionality */}
          <button className="btn-secondary" disabled>
            Export
          </button>
        </div>
      </div>

      <div className="alerts-table-wrapper">
        <table className="alerts-table">
          <thead>
            <tr>
              <th style={{width: '40px'}}>
                {/* TODO: Add select-all functionality */}
                <input type="checkbox" disabled />
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
                <td className="timestamp">{alert.timestamp}</td>
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
                  {/* TODO: Add action handlers for investigate, acknowledge, resolve */}
                  <button className="btn-action-sm" title="Investigate">
                    🔍
                  </button>
                  <button className="btn-action-sm" title="Acknowledge">
                    ✓
                  </button>
                  <button className="btn-action-sm" title="More options">
                    ⋮
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* TODO: Add pagination component */}
      <div className="alerts-pagination">
        <span>Showing 1-5 of 247 alerts</span>
        <div className="pagination-controls">
          <button disabled>← Previous</button>
          <button>Next →</button>
        </div>
      </div>
    </div>
  );
};

export default Alerts;
