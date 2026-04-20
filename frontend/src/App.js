// src/App.js
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { AuthProvider, useAuth } from './hooks/useAuth';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import ThreatMonitorPage from './pages/ThreatMonitorPage';
import AnalyticsPage from './pages/AnalyticsPage';
import Layout from './components/Layout';
import './styles/global.css';

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return <div className="full-loader"><div className="pulse-ring"/><span>Initializing...</span></div>;
  return isAuthenticated ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster
          position="top-right"
          toastOptions={{
            style: { background: '#1c1c1e', color: '#fff', border: '1px solid #2d2d2f', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px' },
            success: { iconTheme: { primary: '#30d158', secondary: '#0d1117' } },
            error: { iconTheme: { primary: '#ff2d55', secondary: '#0d1117' } },
          }}
        />
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="threats" element={<ThreatMonitorPage />} />
            <Route path="analytics" element={<AnalyticsPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
