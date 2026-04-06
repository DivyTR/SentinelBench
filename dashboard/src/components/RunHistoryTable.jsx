import { fmtDate, fmtLatency, shortId, BAND_COLORS } from '../utils'

export default function RunHistoryTable({ runs, selectedId, onSelect }) {
  if (runs.length === 0) {
    return (
      <div className="text-center py-16 text-gray-500">
        No runs recorded yet.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-left text-xs text-gray-500 uppercase tracking-wider">
            <th className="px-4 py-3">Run ID</th>
            <th className="px-4 py-3">Suite</th>
            <th className="px-4 py-3">Started</th>
            <th className="px-4 py-3">Finished</th>
            <th className="px-4 py-3 text-center">Total</th>
            <th className="px-4 py-3 text-center">Caught</th>
            <th className="px-4 py-3 text-center">Missed</th>
            <th className="px-4 py-3 text-center">Coverage</th>
            <th className="px-4 py-3 text-center">Avg latency</th>
            <th className="px-4 py-3 text-center">Sev issues</th>
            <th className="px-4 py-3">Host</th>
          </tr>
        </thead>
        <tbody>
          {runs.map(r => {
            const isSelected = r.run_id === selectedId
            return (
              <tr
                key={r.run_id}
                onClick={() => onSelect(r.run_id)}
                className={[
                  'border-b border-gray-800/50 cursor-pointer transition-colors',
                  isSelected
                    ? 'bg-blue-950/40 border-l-2 border-l-blue-500'
                    : 'hover:bg-gray-900',
                ].join(' ')}
              >
                <td className="px-4 py-3 font-mono text-xs text-gray-400">
                  {shortId(r.run_id)}
                </td>
                <td className="px-4 py-3 font-mono text-xs text-blue-300">
                  {r.suite}
                </td>
                <td className="px-4 py-3 text-gray-300 text-xs">
                  {fmtDate(r.started_at)}
                </td>
                <td className="px-4 py-3 text-gray-400 text-xs">
                  {r.finished_at ? fmtDate(r.finished_at) : (
                    <span className="text-amber-400">In progress</span>
                  )}
                </td>
                <td className="px-4 py-3 text-center text-gray-300">
                  {r.total ?? '—'}
                </td>
                <td className="px-4 py-3 text-center text-green-400 font-medium">
                  {r.caught ?? '—'}
                </td>
                <td className="px-4 py-3 text-center text-red-400 font-medium">
                  {r.missed ?? '—'}
                </td>
                <td className="px-4 py-3 text-center">
                  <CoveragePill pct={r.coverage_pct} />
                </td>
                <td className="px-4 py-3 text-center font-mono text-xs">
                  <LatencyBadge seconds={r.avg_latency_seconds} />
                </td>
                <td className="px-4 py-3 text-center">
                  {r.severity_miscalibrations > 0 ? (
                    <span className="text-amber-400 font-medium">
                      {r.severity_miscalibrations}
                    </span>
                  ) : (
                    <span className="text-green-400">0</span>
                  )}
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs font-mono">
                  {r.host || '—'}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function CoveragePill({ pct }) {
  if (pct == null) return <span className="text-gray-500">—</span>
  const color =
    pct >= 80 ? 'bg-green-900/50 text-green-400 border-green-800' :
    pct >= 50 ? 'bg-amber-900/50 text-amber-400 border-amber-800' :
                'bg-red-900/50 text-red-400 border-red-800'
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs border font-medium ${color}`}>
      {pct}%
    </span>
  )
}

function LatencyBadge({ seconds }) {
  if (seconds == null) return <span className="text-gray-500">—</span>
  const color =
    seconds < 180 ? 'text-green-400' :
    seconds < 600 ? 'text-amber-400' :
                    'text-red-400'
  return <span className={color}>{fmtLatency(seconds)}</span>
}
