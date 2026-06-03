import React from 'react';
import '../styles/stats.css';

const Stats = () => {
  // TODO: Connect to backend API to fetch real-time stats
  const stats = [
    {
      id: 1,
      label: 'Total Events',
      value: '12,847',
      trend: '+5.2%',
      icon: '📊',
      color: 'blue',
      description: 'Events processed in last 24h'
    },
    {
      id: 2,
      label: 'Active Alerts',
      value: '24',
      trend: '+12%',
      icon: '🚨',
      color: 'red',
      description: 'Critical and High priority'
    },
    {
      id: 3,
      label: 'Response Time',
      value: '4.2m',
      trend: '-8.1%',
      icon: '⏱️',
      color: 'green',
      description: 'Average response time (Lower is better)'
    },
    {
      id: 4,
      label: 'Threat Score',
      value: '7.8/10',
      trend: '+2.3%',
      icon: '⚠️',
      color: 'orange',
      description: 'Overall security risk level'
    }
  ];

  return (
    <div className="stats-container">
      {stats.map((stat) => (
        <div key={stat.id} className={`stat-card stat-${stat.color}`}>
          <div className="stat-header">
            <div className="stat-icon">{stat.icon}</div>
            <div className="stat-trend" style={{
              color: stat.trend.includes('+') && stat.color !== 'green' ? '#ff6b6b' : '#51cf66'
            }}>
              {stat.trend}
            </div>
          </div>
          <div className="stat-body">
            <div className="stat-label">{stat.label}</div>
            <div className="stat-value">{stat.value}</div>
            <div className="stat-description">{stat.description}</div>
          </div>
          {/* TODO: Add click handler to navigate to detailed view */}
          <div className="stat-action">
            <button className="stat-btn">View Details →</button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default Stats;
