import { useState } from 'react'
import { TACTICS, BAND_COLORS, BAND_LABELS, fmtLatency } from '../utils'

// All 15 v1 techniques grouped by tactic
const TECHNIQUE_GRID = {
  'Execution': [
    { id: 'T1059.001', name: 'PowerShell' },
    { id: 'T1059.003', name: 'Cmd Shell' },
    { id: 'T1569.002', name: 'Service Exec' },
  ],
  'Persistence': [
    { id: 'T1547.001', name: 'Run Keys' },
    { id: 'T1053.005', name: 'Sched Task' },
    { id: 'T1136.001', name: 'Create Account' },
  ],
  'Credential Access': [
    { id: 'T1003.001', name: 'LSASS Memory' },
    { id: 'T1110.001', name: 'Brute Force' },
    { id: 'T1552.001', name: 'Creds in Files' },
    { id: 'T1555.003', name: 'Browser Creds' },
    { id: 'T1040',     name: 'Net Sniffing' },
  ],
  'Defense Evasion': [
    { id: 'T1070.001', name: 'Clear Logs' },
    { id: 'T1562.001', name: 'Disable AV' },
    { id: 'T1027',     name: 'Obfuscation' },
    { id: 'T1112',     name: 'Modify Reg' },
  ],
}

export default function AttackHeatmap({ results }) {
  const [tooltip, setTooltip] = useState(null)

  // Build a lookup map: technique_id → result row
  const resultMap = {}
  for (const r of results) {
    resultMap[r.technique_id] = r
  }

  return (
    <div className="space-y-6">
      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-xs text-gray-400">
        {Object.entries(BAND_COLORS).map(([band, color]) => (
          <span key={band} className="flex items-center gap-1.5">
            <span
              className="inline-block w-3 h-3 rounded-sm"
              style={{ background: color }}
            />
            {BAND_LABELS[band]}
          </span>
        ))}
      </div>

      {/* Grid */}
      <div className="space-y-4">
        {TACTICS.map(tactic => {
          const techniques = TECHNIQUE_GRID[tactic] || []
          return (
            <div key={tactic}>
              <div className="flex items-center gap-3 mb-2">
                <span className="text-xs font-medium text-gray-400 uppercase tracking-wider w-36 shrink-0">
                  {tactic}
                </span>
                <div className="flex flex-wrap gap-2">
                  {techniques.map(tech => {
                    const result = resultMap[tech.id]
                    const band   = result
                      ? (result.caught ? (result.latency_band || 'green') : 'missed')
                      : 'grey'
                    const color  = BAND_COLORS[band] || BAND_COLORS.grey

                    return (
                      <div
                        key={tech.id}
                        className="heatmap-cell relative cursor-pointer"
                        onMouseEnter={e =>
                          setTooltip({ tech, result, band, x: e.clientX, y: e.clientY })
                        }
                        onMouseLeave={() => setTooltip(null)}
                      >
                        <div
                          className="rounded-md px-3 py-2 text-center"
                          style={{ background: color + '33', border: `1px solid ${color}` }}
                        >
                          <div
                            className="text-xs font-mono font-medium"
                            style={{ color }}
                          >
                            {tech.id}
                          </div>
                          <div className="text-xs text-gray-300 mt-0.5 whitespace-nowrap">
                            {tech.name}
                          </div>
                          {result && result.caught && result.latency_seconds != null && (
                            <div className="text-xs mt-1" style={{ color }}>
                              {fmtLatency(result.latency_seconds)}
                            </div>
                          )}
                          {result && !result.caught && (
                            <div className="text-xs mt-1 text-red-300">MISSED</div>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Tooltip */}
      {tooltip && (
        <HeatmapTooltip
          tech={tooltip.tech}
          result={tooltip.result}
          band={tooltip.band}
          x={tooltip.x}
          y={tooltip.y}
        />
      )}
    </div>
  )
}

function HeatmapTooltip({ tech, result, band, x, y }) {
  const color = BAND_COLORS[band]

  return (
    <div
      className="fixed z-50 pointer-events-none bg-gray-900 border border-gray-700
                 rounded-lg shadow-xl p-3 text-xs w-64"
      style={{ left: x + 14, top: y - 10 }}
    >
      <div className="font-mono font-medium text-white mb-1">
        {tech.id} — {tech.name}
      </div>
      {result ? (
        <div className="space-y-1 text-gray-300">
          <div className="flex justify-between">
            <span className="text-gray-500">Status</span>
            <span style={{ color }}>
              {result.caught ? 'Caught' : 'Missed'}
            </span>
          </div>
          {result.caught && (
            <>
              <div className="flex justify-between">
                <span className="text-gray-500">Latency</span>
                <span style={{ color }}>{fmtLatency(result.latency_seconds)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Severity assigned</span>
                <span>{result.severity_assigned || '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Severity expected</span>
                <span>{result.severity_expected}</span>
              </div>
              {result.severity_delta > 0 && (
                <div className="text-amber-400 mt-1">
                  ⚠ Under-rated by {result.severity_delta} level(s)
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-gray-500">Detected at</span>
                <span>{result.poll_checkpoint || '—'}</span>
              </div>
            </>
          )}
          {!result.caught && (
            <div className="text-red-300 mt-1">
              KQL suggestion generated. See Remediation tab.
            </div>
          )}
        </div>
      ) : (
        <div className="text-gray-500">Not run in this benchmark.</div>
      )}
    </div>
  )
}
