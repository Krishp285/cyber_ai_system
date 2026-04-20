// src/pages/AnalyticsPage.js
import React, { useState, useEffect, useCallback } from 'react';
import { analyticsAPI } from '../utils/api';
import toast from 'react-hot-toast';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, Radar, Legend
} from 'recharts';
import { BarChart3, Globe, TrendingUp, Calendar, Clock, Cpu, RefreshCw } from 'lucide-react';

const COLORS = ['#ff2d55','#ff6b35','#ffd60a','#30d158','#00d4ff','#bf5af2','#64d2ff','#ff9f0a','#5e5ce6'];
const RISK_COLORS = { LOW: '#30d158', MEDIUM: '#ffd60a', HIGH: '#ff6b35', CRITICAL: '#ff2d55' };

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#111827', border: '1px solid #1e2a3a', borderRadius: 8, padding: '10px 14px' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#8b9ab3', marginBottom: 4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: p.color || '#00d4ff' }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

export default function AnalyticsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchAnalytics = useCallback(async () => {
    setLoading(true);
    try {
      const { data: res } = await analyticsAPI.overview();
      setData(res);
    } catch {
      toast.error('Failed to load analytics');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAnalytics(); }, [fetchAnalytics]);

  if (loading) {
    return (
      <>
        <div className="page-header">
          <BarChart3 size={18} color="var(--accent-cyan)" />
          <div><div className="page-title">Analytics</div></div>
        </div>
        <div className="full-loader" style={{ minHeight: 'calc(100vh - 60px)' }}>
          <div className="pulse-ring" />
          <span>Analyzing threat data...</span>
        </div>
      </>
    );
  }

  if (!data) return null;

  const attacksPerDay = data.attacks_per_day || [];
  const typeDistrib = data.attack_type_distribution || [];
  const topIPs = data.top_attacker_ips?.slice(0, 8) || [];
  const riskDist = data.risk_level_distribution || [];
  const protoDist = data.protocol_distribution || [];
  const geoDist = data.geo_distribution?.slice(0, 8) || [];
  const hourly = data.hourly_pattern || [];
  const forecast = data.threat_forecast || [];

  // Radar data from attack types
  const radarData = typeDistrib.filter(d => d.type !== 'Normal').slice(0, 7).map(d => ({
    subject: d.type,
    count: d.count,
    fullMark: Math.max(...typeDistrib.map(x => x.count)),
  }));

  return (
    <>
      <div className="page-header">
        <BarChart3 size={18} color="var(--accent-cyan)" />
        <div>
          <div className="page-title">Analytics &amp; Insights</div>
          <div className="page-subtitle">Data science analysis of attack patterns &amp; threat forecasting</div>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <button className="btn btn-ghost btn-sm" onClick={fetchAnalytics}><RefreshCw size={13} /> Refresh</button>
        </div>
      </div>

      <div className="page-body">

        {/* ── Row 1: Timeline + Protocol ────────────────── */}
        <div className="section">
          <div className="section-title"><Calendar size={13} /> Attack Timeline</div>
          <div className="card">
            <div className="card-title"><TrendingUp size={13} /> Attacks Per Day — Last 30 Days</div>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={attacksPerDay}>
                <defs>
                  <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff2d55" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff2d55" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="date" tick={{ fill: '#8b9ab3', fontSize: 9, fontFamily: 'JetBrains Mono' }} />
                <YAxis tick={{ fill: '#8b9ab3', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="count" name="Attacks" stroke="#ff2d55" strokeWidth={2.5} fill="url(#attackGrad)" dot={{ fill: '#ff2d55', r: 3 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── Row 2: Type distribution + Risk Pie ───────── */}
        <div className="grid-2 section">
          <div className="card">
            <div className="card-title"><Cpu size={13} /> Attack Type Distribution</div>
            <ResponsiveContainer width="100%" height={230}>
              <BarChart data={typeDistrib} layout="vertical" barSize={16}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#8b9ab3', fontSize: 10 }} />
                <YAxis type="category" dataKey="type" tick={{ fill: '#8b9ab3', fontSize: 10, fontFamily: 'JetBrains Mono' }} width={80} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Count" radius={[0, 4, 4, 0]}>
                  {typeDistrib.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="card">
            <div className="card-title">Risk Level Distribution</div>
            <ResponsiveContainer width="100%" height={230}>
              <PieChart>
                <Pie
                  data={riskDist}
                  dataKey="count"
                  nameKey="level"
                  cx="50%" cy="50%"
                  outerRadius={90}
                  innerRadius={50}
                  paddingAngle={4}
                  label={({ level, percent }) => `${level} ${(percent * 100).toFixed(0)}%`}
                  labelLine={{ stroke: '#2d3f57', strokeWidth: 1 }}
                >
                  {riskDist.map(entry => (
                    <Cell key={entry.level} fill={RISK_COLORS[entry.level] || '#8e8e93'} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── Row 3: Top IPs + Protocol ─────────────────── */}
        <div className="grid-2 section">
          <div className="card">
            <div className="card-title">Top Attacker IPs</div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>IP Address</th>
                    <th>Attacks</th>
                    <th>Max Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {topIPs.map((ip, i) => (
                    <tr key={ip.ip}>
                      <td style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                      <td className="ip-addr">{ip.ip}</td>
                      <td style={{ color: 'var(--accent-red)' }}>{ip.count}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div className="risk-bar-wrap" style={{ width: 60 }}>
                            <div className="risk-bar" style={{
                              width: `${ip.max_risk}%`,
                              background: ip.max_risk >= 85 ? 'var(--risk-critical)' : ip.max_risk >= 65 ? 'var(--risk-high)' : ip.max_risk >= 40 ? 'var(--risk-medium)' : 'var(--risk-low)'
                            }} />
                          </div>
                          <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{ip.max_risk?.toFixed(0)}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <div className="card-title"><Globe size={13} /> Attack Origins by Country</div>
            <ResponsiveContainer width="100%" height={230}>
              <BarChart data={geoDist} barSize={20}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="country" tick={{ fill: '#8b9ab3', fontSize: 9, fontFamily: 'JetBrains Mono' }} />
                <YAxis tick={{ fill: '#8b9ab3', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Attacks" radius={[4, 4, 0, 0]}>
                  {geoDist.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── Row 4: Hourly Pattern + Radar ────────────── */}
        <div className="grid-2 section">
          <div className="card">
            <div className="card-title"><Clock size={13} /> Hourly Attack Pattern</div>
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={hourly}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="hour" tick={{ fill: '#8b9ab3', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  tickFormatter={h => `${h}:00`} />
                <YAxis tick={{ fill: '#8b9ab3', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Line type="monotone" dataKey="count" name="Attacks" stroke="#00d4ff" strokeWidth={2}
                  dot={{ fill: '#00d4ff', r: 3 }} activeDot={{ r: 5, fill: '#00d4ff' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="card">
            <div className="card-title">Attack Radar — Type Intensity</div>
            <ResponsiveContainer width="100%" height={220}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="var(--border)" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: '#8b9ab3', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                <Radar name="Attacks" dataKey="count" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.15} strokeWidth={2} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── Row 5: Threat Forecast ────────────────────── */}
        <div className="section">
          <div className="section-title"><TrendingUp size={13} /> 7-Day Threat Forecast</div>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 20 }}>Predicted Attack Count — Next 7 Days</div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={forecast} barSize={32}>
                <defs>
                  <linearGradient id="forecastGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#bf5af2" stopOpacity={0.9} />
                    <stop offset="95%" stopColor="#bf5af2" stopOpacity={0.4} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="date" tick={{ fill: '#8b9ab3', fontSize: 10, fontFamily: 'JetBrains Mono' }} />
                <YAxis tick={{ fill: '#8b9ab3', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="predicted_count" name="Predicted Attacks" fill="url(#forecastGrad)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <div className="table-wrap" style={{ marginTop: 16 }}>
              <table>
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Predicted Count</th>
                    <th>Attack Type</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {forecast.map(f => (
                    <tr key={f.date}>
                      <td className="ts">{f.date}</td>
                      <td style={{ color: 'var(--accent-purple)' }}>{f.predicted_count}</td>
                      <td><span className="badge badge-info">{f.predicted_type}</span></td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div className="risk-bar-wrap" style={{ width: 60 }}>
                            <div style={{ height: '100%', borderRadius: 4, background: '#bf5af2', width: `${f.confidence * 100}%` }} />
                          </div>
                          <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                            {(f.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* ── Protocol Distribution ─────────────────────── */}
        <div className="section">
          <div className="card">
            <div className="card-title">Protocol Distribution</div>
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              {protoDist.map((p, i) => {
                const total = protoDist.reduce((s, x) => s + x.count, 0);
                const pct = total > 0 ? ((p.count / total) * 100).toFixed(1) : '0';
                return (
                  <div key={p.protocol} style={{
                    flex: 1, minWidth: 140,
                    background: 'var(--bg-secondary)', borderRadius: 'var(--radius)',
                    padding: '16px 20px', border: '1px solid var(--border)',
                    textAlign: 'center'
                  }}>
                    <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, fontWeight: 700, color: COLORS[i] }}>{pct}%</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{p.protocol}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>{p.count.toLocaleString()} packets</div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
