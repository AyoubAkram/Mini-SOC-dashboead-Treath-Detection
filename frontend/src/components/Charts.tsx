import React from 'react';
import {
  Area, CartesianGrid, Cell, ComposedChart, Line, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis
} from 'recharts';
import { SEVERITY_COLORS, Severity, StatsResponse, VolumeBucket, formatNumber, titleCase } from '../api';

const SERIES: { key: keyof VolumeBucket; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: SEVERITY_COLORS.critical },
  { key: 'high', label: 'High', color: SEVERITY_COLORS.high },
  { key: 'medium', label: 'Medium', color: SEVERITY_COLORS.medium },
  { key: 'low', label: 'Low', color: SEVERITY_COLORS.low }
];

const TYPE_COLORS = ['#6c8cff', '#a889ff', '#f2526b', '#f79a3e', '#e8c547', '#3fbf8f', '#4cc3e0', '#8892a8'];

const bucketLabel = (iso: string, bucketMinutes: number): string => {
  const date = new Date(iso);
  if (bucketMinutes >= 24 * 60) {
    return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
  }
  if (bucketMinutes >= 6 * 60) {
    return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) + ' ' +
      date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  }
  return date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
};

interface TooltipProps {
  active?: boolean;
  label?: string;
  payload?: { name: string; value: number; color: string }[];
}

const ChartTooltip = ({ active, label, payload }: TooltipProps) => {
  if (!active || !payload || payload.length === 0) {
    return null;
  }
  return (
    <div className="chart-tooltip">
      <div className="title">{label}</div>
      {[...payload].reverse().map((item) => (
        <div key={item.name} className="row">
          <span><span className="swatch" style={{ background: item.color }} />{item.name}</span>
          <b>{formatNumber(item.value)}</b>
        </div>
      ))}
    </div>
  );
};

/** Stacked alert volume per severity, with ML anomalies as a line on top. */
export const AlertVolumeChart = ({ buckets, bucketMinutes }: { buckets: VolumeBucket[]; bucketMinutes: number }) => {
  const data = buckets.map((bucket) => ({ ...bucket, label: bucketLabel(bucket.time, bucketMinutes) }));
  return (
    <div className="chart">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <defs>
            {SERIES.map((series) => (
              <linearGradient key={series.key} id={`fill-${series.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={series.color} stopOpacity={0.55} />
                <stop offset="100%" stopColor={series.color} stopOpacity={0.08} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke="#232a3b" vertical={false} />
          <XAxis dataKey="label" tick={{ fill: '#6b7489', fontSize: 11 }} tickLine={false} axisLine={false} minTickGap={28} />
          <YAxis tick={{ fill: '#6b7489', fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ stroke: '#46516d' }} />
          {[...SERIES].reverse().map((series) => (
            <Area
              key={series.key}
              type="monotone"
              dataKey={series.key}
              name={series.label}
              stackId="severity"
              stroke={series.color}
              strokeWidth={1.6}
              fill={`url(#fill-${series.key})`}
              isAnimationActive={false}
            />
          ))}
          <Line
            type="monotone"
            dataKey="ml"
            name="ML anomalies"
            stroke={SEVERITY_COLORS.ml}
            strokeWidth={2}
            strokeDasharray="4 3"
            dot={false}
            isAnimationActive={false}
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
};

export const VolumeLegend = ({ buckets }: { buckets: VolumeBucket[] }) => {
  const total = (key: keyof VolumeBucket) => buckets.reduce((sum, bucket) => sum + (bucket[key] as number), 0);
  return (
    <div className="legend">
      {SERIES.map((series) => (
        <span key={series.key}>
          <span className="swatch" style={{ background: series.color }} />{series.label}<b>{formatNumber(total(series.key))}</b>
        </span>
      ))}
      <span><span className="swatch" style={{ background: SEVERITY_COLORS.ml }} />ML anomalies<b>{formatNumber(total('ml'))}</b></span>
    </div>
  );
};

/** Donut of alerts by type, with its legend. */
export const AttackTypesChart = ({ types }: { types: { name: string; count: number }[] }) => {
  const total = types.reduce((sum, item) => sum + item.count, 0);
  return (
    <div className="gauge">
      <div style={{ width: 150, height: 150, flexShrink: 0, position: 'relative' }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={types} dataKey="count" nameKey="name" innerRadius={48} outerRadius={72} paddingAngle={2} stroke="none" isAnimationActive={false}>
              {types.map((item, index) => (
                <Cell key={item.name} fill={TYPE_COLORS[index % TYPE_COLORS.length]} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="gauge-center">
          <strong style={{ fontSize: 22 }}>{formatNumber(total)}</strong>
          <span className="muted">ALERTS</span>
        </div>
      </div>
      <div className="severity-bars" style={{ gap: 7 }}>
        {types.slice(0, 6).map((item, index) => (
          <div key={item.name} className="severity-row" style={{ gridTemplateColumns: 'minmax(0, 1fr) 44px' }}>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              <span className="swatch" style={{ background: TYPE_COLORS[index % TYPE_COLORS.length] }} />
              {titleCase(item.name)}
            </span>
            <b>{formatNumber(item.count)}</b>
          </div>
        ))}
      </div>
    </div>
  );
};

/** Ring gauge for the 0-10 threat score with the severity breakdown beside it. */
export const ThreatGauge = ({ stats }: { stats: StatsResponse | null }) => {
  const score = stats?.threat_score ?? 0;
  const level: Severity = stats?.threat_level ?? 'low';
  const counts = stats?.severity_counts;
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const highest = Math.max(1, counts?.critical ?? 0, counts?.high ?? 0, counts?.medium ?? 0, counts?.low ?? 0);
  return (
    <div className="gauge">
      <div className="gauge-ring">
        <svg width="132" height="132" viewBox="0 0 132 132">
          <circle className="track" cx="66" cy="66" r={radius} fill="none" strokeWidth="10" />
          <circle
            className="value"
            cx="66"
            cy="66"
            r={radius}
            fill="none"
            strokeWidth="10"
            strokeLinecap="round"
            stroke={SEVERITY_COLORS[level]}
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - score / 10)}
          />
        </svg>
        <div className="gauge-center">
          <strong>{stats ? score.toFixed(1) : '—'}</strong>
          <span style={{ color: SEVERITY_COLORS[level] }}>{stats ? level.toUpperCase() : ''}</span>
        </div>
      </div>
      <div className="severity-bars">
        {(['critical', 'high', 'medium', 'low'] as Severity[]).map((severity) => (
          <div key={severity} className="severity-row">
            <span>{titleCase(severity)}</span>
            <div className="bar">
              <span style={{ width: `${100 * (counts?.[severity] ?? 0) / highest}%`, background: SEVERITY_COLORS[severity] }} />
            </div>
            <b>{counts ? formatNumber(counts[severity]) : '—'}</b>
          </div>
        ))}
      </div>
    </div>
  );
};

/** Rule-based vs ML-detected alerts. */
export const DetectionSplit = ({ rule, ml }: { rule: number; ml: number }) => {
  const total = rule + ml;
  const share = (value: number) => (total ? `${(100 * value / total).toFixed(0)}%` : '0%');
  return (
    <div>
      <div className="split">
        <span style={{ width: share(rule), background: SEVERITY_COLORS.accent }} />
        <span style={{ width: share(ml), background: SEVERITY_COLORS.ml }} />
      </div>
      <div className="split-legend">
        <div>
          <strong>{formatNumber(rule)}</strong>
          <span className="swatch" style={{ background: SEVERITY_COLORS.accent }} />Rule-based · {share(rule)}
        </div>
        <div style={{ textAlign: 'right' }}>
          <strong>{formatNumber(ml)}</strong>
          <span className="swatch" style={{ background: SEVERITY_COLORS.ml }} />ML-detected · {share(ml)}
        </div>
      </div>
    </div>
  );
};
