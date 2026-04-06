import { fmtDate, shortId } from '../utils'

export default function RunSelector({ runs, selectedId, onChange }) {
  if (runs.length === 0) {
    return (
      <span className="text-xs text-gray-500 font-mono">No runs found</span>
    )
  }

  return (
    <div className="flex items-center gap-2">
      <label className="text-xs text-gray-500">Run</label>
      <select
        value={selectedId || ''}
        onChange={e => onChange(e.target.value)}
        className="bg-gray-800 border border-gray-700 rounded-md text-sm
                   text-gray-200 px-3 py-1.5 focus:outline-none
                   focus:ring-1 focus:ring-blue-500"
      >
        {runs.map(r => (
          <option key={r.run_id} value={r.run_id}>
            {shortId(r.run_id)} · {r.suite} · {fmtDate(r.started_at)}
            {r.coverage_pct != null ? ` · ${r.coverage_pct}% caught` : ''}
          </option>
        ))}
      </select>
    </div>
  )
}
