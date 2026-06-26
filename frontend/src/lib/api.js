const BASE = '/api';

async function fetchJSON(path, opts = {}) {
  const url = `${BASE}${path}`;
  const token = localStorage.getItem('nv-token');
  const headers = { ...opts.headers };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (!opts.raw) headers['Accept'] = 'application/json';

  const res = await fetch(url, { ...opts, headers });
  if (opts.raw) return res;

  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || `Request failed: ${res.status}`);
  return data;
}

export const api = {
  // ── Health ──
  health: {
    live: () => fetchJSON('/health/live'),
    ready: () => fetchJSON('/health/ready'),
    scan: () => fetchJSON('/health/scan'),
  },

  // ── Scans ──
  scan: {
    start: (target, profile = 'quick', opts = {}) =>
      fetchJSON('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target,
          profile,
          duration: opts.duration || 30,
          trace_hops: opts.trace_hops || false,
          custom_args: opts.custom_args || '',
        }),
      }),
    stop: () => fetchJSON('/scan/stop', { method: 'POST' }),
    history: (limit = 20) => fetchJSON(`/scan/history?limit=${limit}`),
    queue: () => fetchJSON('/scan/queue'),
    schedule: {
      list: () => fetchJSON('/scan/schedule'),
      create: (data) => fetchJSON('/scan/schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      }),
      toggle: (id) => fetchJSON(`/scan/schedule/${id}/toggle`, { method: 'POST' }),
      delete: (id) => fetchJSON(`/scan/schedule/${id}`, { method: 'DELETE' }),
    },
  },

  // ── Devices ──
  devices: {
    list: () => fetchJSON('/devices'),
    healthHistory: (deviceIp, hours = 24) =>
      fetchJSON(`/health/history?${deviceIp ? `device_ip=${deviceIp}&` : ''}hours=${hours}`),
  },

  // ── Vulnerabilities ──
  vulnerabilities: {
    list: () => fetchJSON('/vulnerabilities'),
    correlate: (ip) => fetchJSON('/vulnerabilities/correlate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }),
  },

  // ── Capture ──
  capture: {
    summary: () => fetchJSON('/capture/analysis-summary'),
    topTalkers: () => fetchJSON('/capture/top-talkers'),
    anomalies: (minScore) =>
      fetchJSON(`/capture/anomalies${minScore ? `?min_score=${minScore}` : ''}`),
    startStreaming: (duration, bpf) =>
      fetchJSON('/capture/start-streaming', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ duration: duration || 60, bpf_filter: bpf || '' }),
      }),
    stopStreaming: () => fetchJSON('/capture/stop-streaming', { method: 'POST' }),
    status: () => fetchJSON('/capture/streaming-status'),
    rogueEvents: () => fetchJSON('/capture/rogue-events'),
    rogueScan: () => fetchJSON('/capture/rogue-scan', { method: 'POST' }),
    httpLogs: (limit = 50) => fetchJSON(`/capture/http-logs?limit=${limit}`),
    dnsLogs: (limit = 50) => fetchJSON(`/capture/dns-logs?limit=${limit}`),
    suspiciousDns: () => fetchJSON('/capture/suspicious-dns'),
  },

  // ── Auth ──
  auth: {
    login: (username, password) =>
      fetchJSON('/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      }),
    whoami: () => fetchJSON('/auth/whoami'),
    refresh: (token) =>
      fetchJSON('/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: token }),
      }),
  },

  // ── Settings / config ──
  settings: {
    config: () => fetchJSON('/config'),
  },
};
