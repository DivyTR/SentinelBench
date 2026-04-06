import { useState, useEffect } from 'react'
import { api } from './api'
import RunSelector from './components/RunSelector'
import SummaryCards from './components/SummaryCards'
import AttackHeatmap from './components/AttackHeatmap'
import RunHistoryTable from './components/RunHistoryTable'
import RemediationPanel from './components/RemediationPanel'

export default function App() {
  const [runs, setRuns]           = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [detail, setDetail]       = useState(null)   // { run, summary, results }
  const [kql, setKql]             = useState([])
  const [activeTab, setActiveTab] = useState('heatmap')
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState(null)

  // Load run list on mount
  useEffect(() => {
    api.runs()
      .then(data => {
        setRuns(data)
        if (data.length > 0) setSelectedId(data[0].run_id)
      })
      .catch(() => setError('Cannot reach API. Is the backend running?\n\npython dashboard/api.py'))
  }, [])

  // Load detail when selection changes
  useEffect(() => {
    if (!selectedId) return
    setLoading(true)
    setDetail(null)
    setKql([])
    Promise.all([
      api.runDetail(selectedId),
      api.kql(selectedId),
    ])
      .then(([d, k]) => { setDetail(d); setKql(k) })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [selectedId])

  const tabs = [
    { id: 'heatmap',     label: 'ATT&CK Heatmap' },
    { id: 'history',     label: 'Run History' },
    { id: 'remediation', label: `Remediation (${kql.length})` },
  ]

  if (error) return <ErrorScreen message={error} />

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* ── Top bar ─────────────────────────────────────────────── */}
      <header className="border-b border-gray-800 px-6 py-4 flex items-center gap-4">
        <div className="flex items-center gap-3">
          <span className="text-blue-400 font-mono font-medium text-lg">
            SentinelBench
          </span>
          <span className="text-gray-600 text-sm">
            Detection quality benchmarking for Microsoft Sentinel
          </span>
        </div>
        <div className="ml-auto">
          <RunSelector
            runs={runs}
            selectedId={selectedId}
            onChange={setSelectedId}
          />
        </div>
      </header>

      {/* ── Summary cards ────────────────────────────────────────── */}
      {detail && (
        <div className="px-6 pt-5">
          <SummaryCards summary={detail.summary} run={detail.run} />
        </div>
      )}

      {/* ── Tab bar ─────────────────────────────────────────────── */}
      <div className="px-6 pt-5 border-b border-gray-800">
        <nav className="flex gap-1">
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id)}
              className={[
                'px-4 py-2 text-sm rounded-t-md font-medium transition-colors',
                activeTab === t.id
                  ? 'bg-gray-800 text-white border border-b-0 border-gray-700'
                  : 'text-gray-400 hover:text-gray-200',
              ].join(' ')}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>

      {/* ── Main content ─────────────────────────────────────────── */}
      <main className="px-6 py-6">
        {loading && <Spinner />}

        {!loading && detail && activeTab === 'heatmap' && (
          <AttackHeatmap results={detail.results} />
        )}
        {!loading && activeTab === 'history' && (
          <RunHistoryTable
            runs={runs}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        )}
        {!loading && detail && activeTab === 'remediation' && (
          <RemediationPanel kql={kql} results={detail.results} />
        )}

        {!loading && !detail && runs.length === 0 && (
          <EmptyState />
        )}
      </main>
    </div>
  )
}

function Spinner() {
  return (
    <div className="flex items-center justify-center py-20 text-gray-500 gap-3">
      <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24" fill="none">
        <circle className="opacity-25" cx="12" cy="12" r="10"
          stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor"
          d="M4 12a8 8 0 018-8v8H4z" />
      </svg>
      Loading run data…
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-gray-500 gap-4">
      <div className="text-5xl">🛡</div>
      <p className="text-lg font-medium text-gray-400">No runs yet</p>
      <p className="text-sm text-center max-w-sm">
        Run a benchmark to see results here.
      </p>
      <code className="text-xs bg-gray-900 px-4 py-2 rounded text-green-400 mt-2">
        python sentinelbench.py --suite v1 --dry-run
      </code>
    </div>
  )
}

function ErrorScreen({ message }) {
  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-8">
      <div className="max-w-md bg-gray-900 border border-red-900 rounded-xl p-6">
        <h2 className="text-red-400 font-medium text-lg mb-3">Connection error</h2>
        <pre className="text-sm text-gray-300 whitespace-pre-wrap font-mono">
          {message}
        </pre>
      </div>
    </div>
  )
}
