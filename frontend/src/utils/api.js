// src/utils/api.js
// Centralized Axios API client with JWT interceptors

import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

// ── Request interceptor: attach JWT ──────────────────────────
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) config.headers.Authorization = `Bearer ${token}`;
    return config;
  },
  (error) => Promise.reject(error)
);

// ── Response interceptor: handle 401 ─────────────────────────
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;

    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        try {
          const { data } = await axios.post(`${API_BASE}/refresh`, {}, {
            headers: { Authorization: `Bearer ${refreshToken}` }
          });
          localStorage.setItem('access_token', data.access_token);
          original.headers.Authorization = `Bearer ${data.access_token}`;
          return api(original);
        } catch {
          // Refresh failed — force logout
          localStorage.clear();
          window.location.href = '/login';
        }
      } else {
        localStorage.clear();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// ── Auth ──────────────────────────────────────────────────────
export const authAPI = {
  login: (credentials) => api.post('/login', credentials),
  logout: () => api.post('/logout'),
  me: () => api.get('/me'),
};

// ── Logs ──────────────────────────────────────────────────────
export const logsAPI = {
  getAll: (params) => api.get('/logs', { params }),
  getRecent: () => api.get('/logs/recent'),
  getStats: () => api.get('/logs/stats'),
};

// ── Predictions / Simulation ──────────────────────────────────
export const predictionAPI = {
  predict: (data) => api.post('/predict', data),
  simulate: () => api.post('/simulate'),
  bulkSimulate: (count) => api.post('/bulk-simulate', { count }),
  getPredictions: (params) => api.get('/predictions', { params }),
  getBlockedIPs: (params) => api.get('/blocked-ips', { params }),
  unblockIP: (id) => api.post(`/blocked-ips/${id}/unblock`),
};

// ── Alerts ───────────────────────────────────────────────────
export const alertsAPI = {
  getAll: (params) => api.get('/alerts', { params }),
  getRecent: () => api.get('/alerts/recent'),
  getSummary: () => api.get('/alerts/summary'),
  resolve: (id) => api.post(`/alerts/${id}/resolve`),
  resolveAll: () => api.post('/alerts/resolve-all'),
};

// ── Analytics ────────────────────────────────────────────────
export const analyticsAPI = {
  overview: () => api.get('/analytics/overview'),
  chart: (type) => `${API_BASE}/analytics/chart/${type}`,
};

export default api;
