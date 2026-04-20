// src/pages/LoginPage.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Lock, User, Eye, EyeOff, ShieldAlert } from 'lucide-react';
import toast from 'react-hot-toast';

export default function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: '', password: '' });
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [attempts, setAttempts] = useState(0);

  useEffect(() => {
    if (isAuthenticated) navigate('/dashboard', { replace: true });
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.username || !form.password) {
      setError('All fields are required');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await login(form.username, form.password);
      toast.success(`Welcome back, ${form.username}!`);
      navigate('/dashboard');
    } catch (err) {
      const msg = err.response?.data?.error || 'Authentication failed';
      const remaining = err.response?.data?.remaining_attempts;
      setError(msg);
      setAttempts(prev => prev + 1);
      if (remaining !== undefined) {
        toast.error(`${remaining} attempts remaining before lockout`);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-bg-grid" />
      <div className="login-bg-glow" />

      {/* Animated corner accents */}
      <svg style={{ position: 'absolute', top: 40, left: 40, opacity: 0.3 }} width="60" height="60" viewBox="0 0 60 60">
        <path d="M0 60 L0 0 L60 0" stroke="#00d4ff" strokeWidth="1" fill="none" />
      </svg>
      <svg style={{ position: 'absolute', bottom: 40, right: 40, opacity: 0.3 }} width="60" height="60" viewBox="0 0 60 60">
        <path d="M60 0 L60 60 L0 60" stroke="#00d4ff" strokeWidth="1" fill="none" />
      </svg>

      <div className="login-card">
        {/* Glow border top */}
        <div style={{ position: 'absolute', top: 0, left: '20%', right: '20%', height: '1px', background: 'linear-gradient(90deg, transparent, var(--accent-cyan), transparent)' }} />

        <div className="login-header">
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 14 }}>
            <div style={{
              width: 60, height: 60,
              background: 'rgba(0,212,255,0.08)',
              border: '1px solid rgba(0,212,255,0.25)',
              borderRadius: '50%',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <ShieldAlert size={28} color="var(--accent-cyan)" />
            </div>
          </div>
          <div className="login-logo">CYBER·AI</div>
          <div className="login-tagline">Threat Intelligence &amp; Attack Prediction System</div>
        </div>

        {error && (
          <div className="login-error">
            ⚠ {error}
            {attempts >= 3 && <div style={{ marginTop: 4, opacity: 0.7 }}>Multiple failed attempts detected from your IP</div>}
          </div>
        )}

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username</label>
            <div style={{ position: 'relative' }}>
              <User size={15} style={{ position: 'absolute', left: 13, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                placeholder="admin"
                style={{ paddingLeft: 38 }}
                autoComplete="username"
                autoFocus
              />
            </div>
          </div>
          <div className="form-group">
            <label>Password</label>
            <div style={{ position: 'relative' }}>
              <Lock size={15} style={{ position: 'absolute', left: 13, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type={showPwd ? 'text' : 'password'}
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                placeholder="••••••••"
                style={{ paddingLeft: 38, paddingRight: 42 }}
                autoComplete="current-password"
              />
              <button type="button" onClick={() => setShowPwd(v => !v)}
                style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2 }}>
                {showPwd ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          <button type="submit" className="login-submit" disabled={loading}>
            {loading ? (
              <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
                <span className="spinner" />
                AUTHENTICATING...
              </span>
            ) : 'SECURE LOGIN'}
          </button>
        </form>

        <div className="login-hint">
          Default: <span style={{ color: 'var(--accent-cyan)' }}>admin</span> / <span style={{ color: 'var(--accent-cyan)' }}>Admin@123</span>
        </div>

        <div style={{ marginTop: 24, padding: '12px 14px', background: 'rgba(0,212,255,0.04)', borderRadius: 8, border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: 1 }}>
            🔒 SECURITY NOTICE: All login attempts are monitored. Unauthorized access attempts will be logged and may result in IP blocking.
          </div>
        </div>
      </div>
    </div>
  );
}
