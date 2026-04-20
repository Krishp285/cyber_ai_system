// src/pages/DashboardPage.js
import React, { useState, useEffect, useCallback } from 'react';
import { logsAPI, alertsAPI, predictionAPI } from '../utils/api';
import toast from 'react-hot-toast';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, Legend
} from 'recharts';
import {
  Shield, Zap, AlertTriangle, Eye, RefreshCw, Play,
  Ban, TrendingUp, Globe, Lock
} from 'lucide-react';

const RISK_COLORS = { LOW: '#30d158', MEDIUM: '#ffd60a', HIGH: '#ff6b35', CRITICAL: '#ff2d55' };

function RiskBadge({ level }) {
  const cls = `badge badge-${(level || 'low').toLowerCase()}`;
  return <span className={cls}>{level || 'LOW'}</span>;
}

function StatCard({ label, value, sub, color, icon: Icon }) {
  return (
    <div className={`stat-card ${color}`}>
      {Icon && <Icon className="stat-icon" />}
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${color}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

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

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [recentLogs, setRecentLogs] = useState([]);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [simulating, setSimulating] = useState(false);
  const [loadingStats, setLoadingStats] = useState(true);

  const fetchAll = useCallback(async () => {
    try {
      const [statsRes, alertsRes, logsRes, blockedRes] = await Promise.all([
        logsAPI.getStats(),
        alertsAPI.getRecent(),
        logsAPI.getRecent(),
        predictionAPI.getBlockedIPs(),
      ]);
      setStats(statsRes.data);
      setRecentAlerts(alertsRes.data.alerts || []);
      setRecentLogs(logsRes.data.logs || []);
      setBlockedIPs(blockedRes.data.blocked_ips || []);
    } catch (err) {
      toast.error('Failed to load dashboard data');
    } finally {
      setLoadingStats(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 15000); // refresh every 15s
    return () => clearInterval(interval);
  }, [fetchAll]);

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      const { data } = await predictionAPI.simulate();
      const p = data.prediction;
      const toastMsg = `${p.attack_type} | ${p.risk_level} | ${(p.confidence * 100).toFixed(1)}%`;
      if (p.risk_level === 'CRITICAL') toast.error(`🔴 CRITICAL: ${toastMsg}`);
      else if (p.risk_level === 'HIGH') toast(`⚠️ HIGH: ${toastMsg}`, { icon: '🟠' });
      else toast.success(`✅ ${toastMsg}`);
      fetchAll();
    } catch {
      toast.error('Simulation failed');
    } finally {
      setSimulating(false);
    }
  };

  const handleUnblock = async (id, ip) => {
    try {
      await predictionAPI.unblockIP(id);
      toast.success(`Unblocked ${ip}`);
      fetchAll();
    } catch {
      toast.error('Failed to unblock IP');
    }
  };

  // Prepare chart data from stats
  const attackTypeData = (stats?.attack_type_breakdown || [])
    .filter(d => d.type !== 'Normal')
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const riskData = stats?.risk_level_breakdown || [];

  const timelineData = recentLogs.slice(0, 20).map((log, i) => ({
    t: i,
    bytes: log.bytes_sent,
    packets: log.packets_sent,
  }));

  if (loadingStats) {
    return (
      <div className="full-loader" style={{ minHeight: 'calc(100vh - 60px)' }}>
        <div className="pulse-ring" />
        <span>Loading dashboard...</span>
      </div>
    );
  }

  return (
    <>
      {/* ── Header ─────────────────────────────────── */}
      <div className="page-header">
        <Shield size={18} color="var(--accent-cyan)" />
        <div>
          <div className="page-title">Security Dashboard</div>
          <div className="page-subtitle">Real-time threat overview · Auto-refresh every 15s</div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10 }}>
          <button className="btn btn-ghost btn-sm" onClick={fetchAll}>
            <RefreshCw size={13} /> Refresh
          </button>
          <button className="btn btn-primary btn-sm" onClick={handleSimulate} disabled={simulating}>
            {simulating ? <><span className="spinner" style={{ borderColor: 'rgba(0,0,0,0.2)', borderTopColor: '#000' }} /> Simulating...</> : <><Play size={13} /> Simulate Attack</>}
          </button>
        </div>
      </div>

      <div className="page-body">
        {/* ── Stat Cards ──────────────────────────────────── */}
        <div className="grid-4 section">
          <StatCard label="Total Attacks" value={stats?.total_attacks || 0} sub="All time" color="red" icon={Zap} />
          <StatCard label="Active Alerts" value={stats?.active_alerts || 0} sub="Unresolved" color="orange" icon={AlertTriangle} />
          <StatCard label="Blocked IPs" value={stats?.blocked_ips || 0} sub="Firewall active" color="purple" icon={Ban} />
          <StatCard label="Critical Events" value={stats?.critical_count || 0} sub="Risk ≥ 85%" color="cyan" icon={Eye} />
        </div>

        <div className="grid-2 section">
          <StatCard label="Network Logs" value={stats?.total_logs || 0} sub="Total recorded" color="green" icon={Globe} />
          <StatCard label="Attacks (24h)" value={stats?.recent_attacks_24h || 0} sub="Last 24 hours" color="yellow" icon={TrendingUp} />
        </div>

        {/* ── Charts Row ──────────────────────────────────── */}
        <div className="grid-2-1 section">
          {/* Attack types bar */}
          <div className="card">
            <div className="card-title"><Zap size={13} /> Attack Type Distribution</div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={attackTypeData} barSize={28}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="type" tick={{ fill: '#8b9ab3', fontSize: 11, fontFamily: 'JetBrains Mono' }} />
                <YAxis tick={{ fill: '#8b9ab3', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Count" radius={[4, 4, 0, 0]}>
                  {attackTypeData.map((_, i) => (
                    <Cell key={i} fill={['#ff2d55','#ff6b35','#ffd60a','#00d4ff','#bf5af2','#30d158'][i % 6]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Risk level pie */}
          <div className="card">
            <div className="card-title"><Shield size={13} /> Risk Levels</div>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={riskData}
                  dataKey="count"
                  nameKey="level"
                  cx="50%" cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={3}
                >
                  {riskData.map((entry) => (
                    <Cell key={entry.level} fill={RISK_COLORS[entry.level] || '#8e8e93'} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  formatter={(val) => <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#8b9ab3' }}>{val}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── Traffic Timeline ─────────────────────────────── */}
        <div className="card section">
          <div className="card-title"><TrendingUp size={13} /> Network Traffic · Recent Logs</div>
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff2d55" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#ff2d55" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="t" hide />
              <YAxis tick={{ fill: '#8b9ab3', fontSize: 10 }} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="bytes" name="Bytes Sent" stroke="#00d4ff" strokeWidth={2} fill="url(#cyanGrad)" />
              <Area type="monotone" dataKey="packets" name="Packets" stroke="#ff6b35" strokeWidth={2} fill="url(#redGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* ── Bottom Row ─────────────────────────────────── */}
        <div className="grid-2 section">
          {/* Live Alerts */}
          <div className="card">
            <div className="card-title" style={{ justifyContent: 'space-between' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><AlertTriangle size={13} /> Live Alerts</span>
              <div className="live-dot" />
            </div>
            {recentAlerts.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)', textAlign: 'center', padding: '20px 0' }}>No active alerts</div>
            ) : (
              recentAlerts.slice(0, 6).map(alert => (
                <div key={alert.id} className={`alert-item ${alert.severity}`}>
                  <div className="live-dot" style={{
                    background: alert.severity === 'CRITICAL' ? 'var(--accent-red)' : alert.severity === 'HIGH' ? 'var(--accent-orange)' : 'var(--accent-yellow)',
                    boxShadow: `0 0 8px ${alert.severity === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-orange)'}`,
                  }} />
                  <div>
                    <div className="alert-msg">{alert.message}</div>
                    <div className="alert-time">{new Date(alert.timestamp).toLocaleString()}</div>
                  </div>
                  <RiskBadge level={alert.severity} />
                </div>
              ))
            )}
          </div>

          {/* Blocked IPs */}
          <div className="card">
            <div className="card-title"><Lock size={13} /> Firewall · Blocked IPs</div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Hits</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {blockedIPs.length === 0 ? (
                    <tr><td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No blocked IPs</td></tr>
                  ) : (
                    blockedIPs.slice(0, 6).map(ip => (
                      <tr key={ip.id}>
                        <td className="ip-addr">{ip.ip_address}</td>
                        <td style={{ color: 'var(--accent-red)' }}>{ip.attack_count}</td>
                        <td>
                          <button className="btn btn-ghost btn-sm" onClick={() => handleUnblock(ip.id, ip.ip_address)}>
                            Unblock
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* ── Recent Logs Table ─────────────────────────── */}
        <div className="card section">
          <div className="card-title"><Eye size={13} /> Recent Network Logs</div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Dest Port</th>
                  <th>Protocol</th>
                  <th>Service</th>
                  <th>Bytes Sent</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.slice(0, 10).map(log => (
                  <tr key={log.id}>
                    <td className="ts">{new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td className="ip-addr">{log.source_ip}</td>
                    <td style={{ color: 'var(--text-secondary)' }}>{log.destination_port}</td>
                    <td><span className="badge badge-info">{log.protocol}</span></td>
                    <td style={{ color: 'var(--text-secondary)' }}>{log.service}</td>
                    <td style={{ color: 'var(--text-secondary)' }}>{log.bytes_sent?.toLocaleString()}</td>
                    <td>
                      <span className={`badge badge-${log.action === 'ALLOW' ? 'low' : 'critical'}`}>{log.action}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
