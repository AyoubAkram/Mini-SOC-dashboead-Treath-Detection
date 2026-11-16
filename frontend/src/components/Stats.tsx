import React from 'react';
import { StatsResponse, formatNumber } from '../api';
import '../styles/stats.css';

interface StatsProps {
  stats: StatsResponse | null;
  rangeLabel: string;
}

const formatTrend = (trend: number | null | undefined): string => {
  if (trend === null || trend === undefined) {
    return '—';
  }
  return `${trend > 0 ? '+' : ''}${trend}%`;
};

const Stats = ({ stats, rangeLabel }: StatsProps) => {
  const value = (number: number | undefined): string =>
    number === undefined ? '—' : formatNumber(number);

  const cards = [
    {
      id: 1,
      label: 'Total Events',
      value: value(stats?.total_events),
      trend: stats?.total_events_trend,
      icon: '📊',
      color: 'blue',
      description: `Events ingested, ${rangeLabel}`
    },
    {
      id: 2,
      label: 'Active Alerts',
      value: value(stats?.active_alerts),
      trend: stats?.active_alerts_trend,
      icon: '🚨',
      color: 'red',
      description: 'Unresolved security events'
    },
    {
      id: 3,
      label: 'Failed Logins',
      value: value(stats?.failed_logins),
      trend: stats?.failed_logins_trend,
      icon: '🔐',
      color: 'green',
      description: `${value(stats?.unique_source_ips)} distinct source IPs seen overall`
    },
    {
      id: 4,
      label: 'Threat Score',
      value: stats ? `${stats.threat_score}/10` : '—',
      trend: undefined,
      icon: '⚠️',
      color: 'orange',
      description: 'Severity-weighted share of alerts'
    }
  ];

  return (
    <div className="stats-container">
      {cards.map((card) => (
        <div key={card.id} className={`stat-card stat-${card.color}`}>
          <div className="stat-header">
            <div className="stat-icon">{card.icon}</div>
            {card.trend !== undefined && (
              <div
                className="stat-trend"
                title="Change against the previous period"
                style={{
                  // More events, alerts or failed logins is never good news
                  color: card.trend === null ? '#a0aab8' : card.trend > 0 ? '#ff6b6b' : '#51cf66'
                }}
              >
                {formatTrend(card.trend)}
              </div>
            )}
          </div>
          <div className="stat-body">
            <div className="stat-label">{card.label}</div>
            <div className="stat-value">{card.value}</div>
            <div className="stat-description">{card.description}</div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default Stats;
