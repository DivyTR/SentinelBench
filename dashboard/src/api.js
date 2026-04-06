// src/api.js
// Thin wrapper around fetch() for the SentinelBench API.

const BASE = ''  // proxied by Vite to http://127.0.0.1:8000

async function get(path) {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`)
  return res.json()
}

export const api = {
  runs:        ()        => get('/api/runs'),
  runDetail:   (runId)   => get(`/api/runs/${runId}`),
  kql:         (runId)   => get(`/api/runs/${runId}/kql`),
  techniques:  ()        => get('/api/techniques'),
  health:      ()        => get('/health'),
}
