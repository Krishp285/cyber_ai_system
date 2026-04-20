// src/components/Layout.js
import React, { useState } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import toast from 'react-hot-toast';
import {
  LayoutDashboard, Shield, BarChart3, LogOut,
  Activity, Bell, Settings, Wifi
} from 'lucide-react';

const NAV_ITEMS = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/threats',   icon: Shield,          label: 'Threat Monitor' },
  { to: '/analytics', icon: BarChart3,        label: 'Analytics' },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [isLoggingOut, setLoggingOut] = useState(false);

  const handleLogout = async () => {
    setLoggingOut(true);
    await logout();
    toast.success('Logged out');
    navigate('/login');
  };

  return (
    <div className="app-shell">
      {/* ── Sidebar ──────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-brand scan-header">
          <div className="brand-logo">⬡ CYBER·AI</div>
          <div className="brand-sub">Threat Intelligence System</div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-label">Navigation</div>
          {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <Icon className="nav-icon" />
              {label}
            </NavLink>
          ))}

          <div className="nav-label" style={{ marginTop: 24 }}>System</div>
          <div className="nav-item" style={{ cursor: 'default' }}>
            <Wifi className="nav-icon" style={{ color: 'var(--accent-green)' }} />
            <span style={{ fontSize: 12 }}>
              Monitor <span style={{ color: 'var(--accent-green)', marginLeft: 4 }}>● LIVE</span>
            </span>
          </div>
          <div className="nav-item" style={{ cursor: 'default' }}>
            <Bell className="nav-icon" />
            Alerts
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user">
            <div className="user-avatar">
              {user?.username?.[0]?.toUpperCase() || 'A'}
            </div>
            <div className="user-info">
              <div className="user-name">{user?.username || 'admin'}</div>
              <div className="user-role">{user?.role || 'ADMIN'}</div>
            </div>
            <button
              onClick={handleLogout}
              disabled={isLoggingOut}
              title="Logout"
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4, borderRadius: 4, transition: 'color 0.15s' }}
              onMouseEnter={e => e.currentTarget.style.color = 'var(--accent-red)'}
              onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main Content ─────────────────────────────── */}
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
