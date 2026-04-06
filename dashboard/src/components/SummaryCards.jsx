import { fmtLatency, fmtDate, shortId } from '../utils'

export default function SummaryCards({ summary, run }) {
  const cards = [
    {
      label: 'Coverage',
      value: summary.coverage_pct != null ? `${summary.coverage_pct}%` : '—',
      sub:   `${summary.caught} / ${summary.total} techniques caught`,
      color: coverageColor(summary.coverage_pct),
    },
    {
      label: 'Avg detection latency',
      value: fmtLatency(summary.avg_latency_seconds),
      sub:   'Across all caught techniques',
      color: latencyColor(summary.avg_latency_seconds),
    },
    {
      label: 'Missed detections',
      value: summary.missed,
      sub:   'KQL suggestions generated',
      color: summary.missed > 0 ? 'text-red-400' : 'text-green-400',
    },
    {
      label: 'Severity miscalibrations',
      value: summary.severity_miscalibrations,
      sub:   'Alerts under-rated by Sentinel',
      color: summary.severity_miscalibrations > 0 ? 'text-amber-400' : 'text-green-400',
    },
    {
      label: 'Run',
      value: shortId(run.run_id),
      sub:   fmtDate(run.started_at),
      color: 'text-gray-400',
    },
    {
      label: 'Host',
      value: run.host || '—',
      sub:   run.suite,
      color: 'text-gray-400',
    },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map(c => (
        <div
          key={c.label}
          className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3"
        >
          <p className="text-xs text-gray-500 mb-1">{c.label}</p>
          <p className={`text-xl font-medium font-mono ${c.color}`}>{c.value}</p>
          <p className="text-xs text-gray-600 mt-1 truncate">{c.sub}</p>
        </div>
      ))}
    </div>
  )
}

function coverageColor(pct) {
  if (pct == null) return 'text-gray-400'
  if (pct >= 80) return 'text-green-400'
  if (pct >= 50) return 'text-amber-400'
  return 'text-red-400'
}

function latencyColor(seconds) {
  if (seconds == null) return 'text-gray-400'
  if (seconds < 180) return 'text-green-400'
  if (seconds < 600) return 'text-amber-400'
  return 'text-red-400'
}
