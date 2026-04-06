import { useState } from 'react'
import { SEVERITY_COLORS } from '../utils'

const CONFIDENCE_STYLES = {
  high:             'bg-green-900/40 text-green-400 border-green-800',
  medium:           'bg-amber-900/40 text-amber-400 border-amber-800',
  requires_tuning:  'bg-red-900/40 text-red-400 border-red-800',
}

const CONFIDENCE_LABELS = {
  high:             'High confidence',
  medium:           'Medium confidence',
  requires_tuning:  'Requires tuning',
}

export default function RemediationPanel({ kql, results }) {
  const [expanded, setExpanded] = useState(null)
  const [copied, setCopied]     = useState(null)

  const missedResults = results.filter(r => !r.caught)

  if (kql.length === 0) {
    return (
      <div className="text-center py-16 text-gray-500">
        {missedResults.length === 0
          ? '🎉 All techniques were detected — no remediation needed.'
          : 'No KQL suggestions generated yet for this run.'}
      </div>
    )
  }

  // Build a lookup: technique_id → missed result
  const missedMap = {}
  for (const r of missedResults) missedMap[r.technique_id] = r

  async function copy(text, id) {
    await navigator.clipboard.writeText(text)
    setCopied(id)
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="space-y-4">
      {/* Summary banner */}
      <div className="flex items-center gap-3 bg-red-950/30 border border-red-900/50
                      rounded-lg px-4 py-3 text-sm text-red-300">
        <span className="text-red-400 text-base">⚠</span>
        <span>
          <strong>{kql.length}</strong> missed detection{kql.length !== 1 ? 's' : ''}.
          KQL rules below would have caught them. Review and tune before deploying.
        </span>
      </div>

      {kql.map(s => {
        const missed  = missedMap[s.technique_id]
        const isOpen  = expanded === s.suggestion_id
        const confStyle = CONFIDENCE_STYLES[s.confidence] || CONFIDENCE_STYLES.requires_tuning

        return (
          <div
            key={s.suggestion_id}
            className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
          >
            {/* Header row */}
            <div
              className="flex items-start justify-between px-5 py-4 cursor-pointer
                         hover:bg-gray-800/50 transition-colors"
              onClick={() => setExpanded(isOpen ? null : s.suggestion_id)}
            >
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-red-400 font-medium">
                  {s.technique_id}
                </span>
                {missed && (
                  <span className="text-sm text-gray-300">{missed.technique_name}</span>
                )}
                {missed && (
                  <span className="text-xs text-gray-500">{missed.tactic}</span>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0 ml-4">
                <span className={`text-xs px-2 py-0.5 rounded-full border ${confStyle}`}>
                  {CONFIDENCE_LABELS[s.confidence]}
                </span>
                <span className="text-xs text-gray-500">{s.data_source}</span>
                <svg
                  className={`w-4 h-4 text-gray-500 transition-transform ${isOpen ? 'rotate-180' : ''}`}
                  fill="none" viewBox="0 0 24 24" stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </div>

            {/* Expanded content */}
            {isOpen && (
              <div className="border-t border-gray-800 px-5 py-4 space-y-4">

                {/* Severity context if available */}
                {missed && missed.severity_expected && (
                  <div className="flex flex-wrap gap-4 text-xs">
                    <span className="text-gray-500">
                      Expected severity:
                      <span className="ml-1 font-medium"
                        style={{ color: SEVERITY_COLORS[missed.severity_expected] }}>
                        {missed.severity_expected}
                      </span>
                    </span>
                    <span className="text-gray-500">
                      Tactic: <span className="text-gray-300">{missed.tactic}</span>
                    </span>
                  </div>
                )}

                {/* False positive note */}
                {s.false_positive_note && (
                  <div className="flex gap-2 bg-amber-950/30 border border-amber-900/40
                                  rounded-lg px-3 py-2 text-xs text-amber-300">
                    <span className="shrink-0">⚠</span>
                    <span>{s.false_positive_note}</span>
                  </div>
                )}

                {/* KQL block */}
                <div className="relative">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-gray-500 uppercase tracking-wider">
                      Generated KQL rule
                    </span>
                    <button
                      onClick={() => copy(s.kql_query, s.suggestion_id)}
                      className={[
                        'flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md',
                        'border transition-colors',
                        copied === s.suggestion_id
                          ? 'bg-green-900/50 border-green-700 text-green-400'
                          : 'bg-gray-800 border-gray-700 text-gray-300 hover:bg-gray-700',
                      ].join(' ')}
                    >
                      {copied === s.suggestion_id ? (
                        <>
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                          Copied
                        </>
                      ) : (
                        <>
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                          Copy KQL
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="kql-block">{s.kql_query}</pre>
                </div>

              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
