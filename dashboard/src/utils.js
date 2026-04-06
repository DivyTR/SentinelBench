// src/utils.js

export const BAND_COLORS = {
  green:  '#16a34a',
  amber:  '#d97706',
  red:    '#dc2626',
  missed: '#7f1d1d',
  grey:   '#374151',  // not covered in v1 scope
}

export const BAND_LABELS = {
  green:  '< 3 min',
  amber:  '3–10 min',
  red:    '> 10 min',
  missed: 'Missed',
  grey:   'Not tested',
}

export const SEVERITY_COLORS = {
  High:          '#dc2626',
  Medium:        '#d97706',
  Low:           '#2563eb',
  Informational: '#6b7280',
}

// ATT&CK tactics in the order we show them on the heatmap (top → bottom)
export const TACTICS = [
  'Execution',
  'Persistence',
  'Credential Access',
  'Defense Evasion',
]

export function fmtLatency(seconds) {
  if (seconds == null) return '—'
  if (seconds < 60) return `${Math.round(seconds)}s`
  return `${Math.round(seconds / 60)}m ${Math.round(seconds % 60)}s`
}

export function fmtDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

export function severityDeltaLabel(delta) {
  if (delta == null) return ''
  if (delta > 0)  return `↓ under-rated by ${delta}`
  if (delta < 0)  return `↑ over-rated by ${Math.abs(delta)}`
  return '✓ accurate'
}

export function shortId(id) {
  return id ? id.slice(0, 8) + '…' : ''
}
