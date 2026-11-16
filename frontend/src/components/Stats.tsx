import React from 'react';
import { StatsResponse, formatNumber } from '../api';
import '../styles/stats.css';

interface StatsProps {
  stats: StatsResponse | null;
  rangeLabel: string;
}

const Trend = ({ value }: { value: number | null | undefined }) => {
  if (value === undefined) {
    return null;
  }
  if (value === null) {
    return <span className="trend" title="No data in the previous period">new</span>;
  }
  // More events, alerts or failed logins is never good news
  const direction = value > 0 ? 'up' : value < 0 ? 'down' : '';
  return (
    <span className={`trend ${direction}`} title="Change against the previous period">
      {value > 0 ? '+' : ''}{value}%
    </span>
  );
};

const Stats = ({ stats, rangeLabel }: StatsProps) => {
  const value = (number: number | undefined): string =>
    number === undefined ? '—' : formatNumber(number);

  const cards = [
    {
      label: 'Total events',
      value: value(stats?.total_events),
      trend: stats?.total_events_trend,
      color: 'var(--accent)',
      note: `Ingested in the ${rangeLabel}`
    },
    {
      label: 'Active alerts',
      value: value(stats?.active_alerts),
      trend: stats?.active_alerts_trend,
      color: 'var(--critical)',
      note: 'Unresolved security events'
    },
    {
      label: 'ML anomalies',
      value: value(stats?.ml_alerts),
      trend: undefined,
      color: 'var(--ml)',
      note: 'Behaviour the model found unusual'
    },
    {
      label: 'Failed logins',
      value: value(stats?.failed_logins),
      trend: stats?.failed_logins_trend,
      color: 'var(--high)',
      note: `${value(stats?.unique_source_ips)} distinct source IPs overall`
    }
  ];

  return (
    <div className="kpis">
      {cards.map((card) => (
        <div key={card.label} className="card kpi" style={{ '--kpi-color': card.color } as React.CSSProperties}>
          <div className="kpi-top">
            <span className="kpi-label">{card.label}</span>
            <Trend value={card.trend} />
          </div>
          <div className="kpi-value">{card.value}</div>
          <div className="kpi-note">{card.note}</div>
        </div>
      ))}
    </div>
  );
};

export default Stats;
