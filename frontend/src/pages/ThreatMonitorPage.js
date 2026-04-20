// src/pages/ThreatMonitorPage.js
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { predictionAPI, alertsAPI } from '../utils/api';
import toast from 'react-hot-toast';
import {
  Shield, Play, Pause, AlertTriangle, CheckCircle,
  RefreshCw, Cpu, Zap, Eye, Ban
} from 'lucide-react';

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, WARNING: 2, INFO: 3 };

function RiskBar({ score, level }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div className="risk-bar-wrap" style={{ flex: 1 }}>
        <div className={`risk-bar ${level}`} style={{ width: `${score}%` }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', width: 32, textAlign: 'right' }}>{score?.toFixed(0)}</span>
    </div>
  );
}

function PredictionCard({ pred }) {
  const borderColor = { CRITICAL: 'var(--risk-critical)', HIGH: 'var(--risk-high)', MEDIUM: 'var(--risk-medium)', LOW: 'var(--risk-low)' }[pred.risk_level] || 'var(--border)';
  const badgeCls = `badge badge-${pred.risk_level?.toLowerCase()}`;
  return (
    <div style={{
      background: 'var(--bg-card)', border: `1px solid var(--border)`,
      borderLeft: `3px solid ${borderColor}`,
      borderRadius: 'var(--radius)', padding: '14px 16px', marginBottom: 8,
      transition: 'background 0.15s'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{pred.attack_type}</span>
          {pred.is_anomaly && (
            <span style={{ marginLeft: 8, fontSize: 10, color: 'var(--accent-orange)', fontFamily: 'var(--font-mono)', border: '1px solid rgba(255,107,53,0.4)', padding: '2px 6px', borderRadius: 4 }}>ANOMALY</span>
          )}
        </div>
        <span className={badgeCls}>{pred.risk_level}</span>
      </div>
      <div style={{ display: 'flex', gap: 20, marginBottom: 10, flexWrap: 'wrap' }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          <span>IP: </span><span className="ip-addr">{pred.source_ip}</span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Confidence: <span style={{ color: 'var(--text-primary)' }}>{(pred.confidence * 100).toFixed(1)}%</span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Model: <span style={{ color: 'var(--text-secondary)' }}>{pred.model_used}</span>
        </div>
        <div className="ts">{new Date(pred.timestamp).toLocaleString()}</div>
      </div>
      <RiskBar score={pred.risk_score} level={pred.risk_level} />
    </div>
  );
}

export default function ThreatMonitorPage() {
  const [predictions, setPredictions] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [filter, setFilter] = useState({ risk_level: '', attack_type: '' });
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [liveMode, setLiveMode] = useState(false);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const liveRef = useRef(null);

  const fetchData = useCallback(async () => {
    try {
      const params = { page, limit: 15, ...filter };
      Object.keys(params).forEach(k => !params[k] && delete params[k]);
      const [predRes, alertRes] = await Promise.all([
        predictionAPI.getPredictions(params),
        alertsAPI.getAll({ limit: 8, resolved: 'false' }),
      ]);
      setPredictions(predRes.data.predictions || []);
      setTotalPages(predRes.data.pages || 1);
      setAlerts(alertRes.data.alerts || []);
    } catch {
      toast.error('Failed to load threat data');
    } finally {
      setLoading(false);
    }
  }, [page, filter]);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Live simulation mode
  useEffect(() => {
    if (liveMode) {
      liveRef.current = setInterval(async () => {
        try {
          await predictionAPI.simulate();
          fetchData();
        } catch {}
      }, 3000);
    } else {
      clearInterval(liveRef.current);
    }
    return () => clearInterval(liveRef.current);
  }, [liveMode, fetchData]);

  const handleResolve = async (id) => {
    try {
      await alertsAPI.resolve(id);
      toast.success('Alert resolved');
      fetchData();
    } catch {
      toast.error('Failed to resolve');
    }
  };

  const handleBulkSim = async () => {
    setSimulating(true);
    try {
      const { data } = await predictionAPI.bulkSimulate(10);
      toast.success(`Generated ${data.generated} logs | ${JSON.stringify(data.summary)}`);
      fetchData();
    } catch {
      toast.error('Bulk simulation failed');
    } finally {
      setSimulating(false);
    }
  };

  const ATTACK_TYPES = ['DoS', 'DDoS', 'Probe', 'PortScan', 'BruteForce', 'R2L', 'U2R', 'Normal', 'SQLInjection'];
  const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

  return (
    <>
      <div className="page-header">
        <Shield size={18} color="var(--accent-cyan)" />
        <div>
          <div className="page-title">Threat Monitor</div>
          <div className="page-subtitle">ML-powered attack detection &amp; predictions</div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, alignItems: 'center' }}>
          {liveMode && (
            <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <div className="live-dot" /> LIVE
            </span>
          )}
          <button className={`btn btn-sm ${liveMode ? 'btn-danger' : 'btn-ghost'}`} onClick={() => setLiveMode(v => !v)}>
            {liveMode ? <><Pause size={13} /> Stop Live</> : <><Play size={13} /> Live Mode</>}
          </button>
          <button className="btn btn-primary btn-sm" onClick={handleBulkSim} disabled={simulating}>
            {simulating ? 'Simulating...' : <><Zap size={13} /> Bulk Simulate (10)</>}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={fetchData}><RefreshCw size={13} /></button>
        </div>
      </div>

      <div className="page-body">
        {/* ── Filters ───────────────────────────────────── */}
        <div className="card section" style={{ padding: '16px 20px' }}>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div style={{ flex: 1, minWidth: 160 }}>
              <label>Risk Level</label>
              <select value={filter.risk_level} onChange={e => setFilter(f => ({ ...f, risk_level: e.target.value }))}>
                <option value="">All Levels</option>
                {RISK_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
              </select>
            </div>
            <div style={{ flex: 1, minWidth: 160 }}>
              <label>Attack Type</label>
              <select value={filter.attack_type} onChange={e => setFilter(f => ({ ...f, attack_type: e.target.value }))}>
                <option value="">All Types</option>
                {ATTACK_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => { setFilter({ risk_level: '', attack_type: '' }); setPage(1); }}>
              Clear
            </button>
          </div>
        </div>

        <div className="grid-2-1 section">
          {/* ── Predictions Feed ──────────────────────── */}
          <div>
            <div className="section-title"><Cpu size={13} /> ML Predictions Feed</div>
            {loading ? (
              <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                <div className="pulse-ring" style={{ margin: '0 auto 12px' }} />
                Loading predictions...
              </div>
            ) : predictions.length === 0 ? (
              <div className="card" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                <Shield size={32} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>No predictions yet — run a simulation</div>
              </div>
            ) : (
              <>
                {predictions.map(pred => <PredictionCard key={pred.id} pred={pred} />)}
                {/* Pagination */}
                <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 16 }}>
                  <button className="btn btn-ghost btn-sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)', alignSelf: 'center' }}>
                    {page} / {totalPages}
                  </span>
                  <button className="btn btn-ghost btn-sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
                </div>
              </>
            )}
          </div>

          {/* ── Alert Panel ───────────────────────────── */}
          <div>
            <div className="section-title"><AlertTriangle size={13} /> Active Alerts</div>
            {alerts.length === 0 ? (
              <div className="card" style={{ textAlign: 'center', padding: 24, color: 'var(--accent-green)' }}>
                <CheckCircle size={28} style={{ margin: '0 auto 8px' }} />
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>All clear</div>
              </div>
            ) : (
              alerts.sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4)).map(alert => (
                <div key={alert.id} className={`alert-item ${alert.severity}`} style={{ justifyContent: 'space-between' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', gap: 8, marginBottom: 4 }}>
                      <span className={`badge badge-${alert.severity?.toLowerCase()}`}>{alert.severity}</span>
                      <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{alert.alert_type}</span>
                    </div>
                    <div className="alert-msg">{alert.message}</div>
                    <div className="alert-time">{new Date(alert.timestamp).toLocaleString()}</div>
                  </div>
                  <button className="btn btn-ghost btn-sm" style={{ marginLeft: 8, flexShrink: 0 }} onClick={() => handleResolve(alert.id)}>
                    <CheckCircle size={12} /> Resolve
                  </button>
                </div>
              ))
            )}

            {alerts.length > 0 && (
              <button className="btn btn-ghost" style={{ width: '100%', marginTop: 8, justifyContent: 'center' }}
                onClick={async () => { await alertsAPI.resolveAll(); toast.success('All alerts resolved'); fetchData(); }}>
                Resolve All
              </button>
            )}

            {/* ── ML Info Panel ─────────────────────── */}
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-title"><Cpu size={13} /> ML Model Info</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[
                  { label: 'Primary Model', value: 'Random Forest', color: 'var(--accent-cyan)' },
                  { label: 'Anomaly Detection', value: 'Isolation Forest', color: 'var(--accent-green)' },
                  { label: 'Attack Classes', value: '9 categories', color: 'var(--text-secondary)' },
                  { label: 'Features Used', value: '17 dimensions', color: 'var(--text-secondary)' },
                  { label: 'Risk Scoring', value: 'Multi-factor (0-100)', color: 'var(--accent-yellow)' },
                ].map(({ label, value, color }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                    <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>{label}</span>
                    <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color }}>{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
