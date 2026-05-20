import { useSummary, useThreatModel } from '../api/client';
import RiskScoreCard from './RiskScoreCard';
import FindingsChart from './FindingsChart';
import AttackPathVisualization from './AttackPathVisualization';
import FindingsTable from './FindingsTable';
import TopFixes from './TopFixes';
import LoadingSpinner from './LoadingSpinner';

export default function Dashboard() {
  const { data: summary, error: summaryError, isLoading: summaryLoading } = useSummary();
  const { data: model,   error: modelError,   isLoading: modelLoading }   = useThreatModel();

  if (summaryLoading || modelLoading) return <LoadingSpinner />;

  if (summaryError || modelError) {
    return (
      <div className="min-h-screen flex items-center justify-center p-8">
        <div className="card max-w-md w-full text-center">
          <div className="text-4xl mb-4">🔌</div>
          <h2 className="text-xl font-bold text-red-400 mb-3">
            Could not reach the API
          </h2>
          <p className="text-gray-400 text-sm mb-2">
            {summaryError?.message ?? modelError?.message}
          </p>
          <p className="text-gray-500 text-xs mb-6">
            Make sure <code className="bg-dark-700 px-1 rounded">bluehound serve</code> is
            running on port 8080.
          </p>
          <button onClick={() => window.location.reload()} className="btn-primary">
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!summary || !model) return null;

  const severityData: Record<string, number> = {
    critical: summary.critical_findings,
    high:     summary.high_findings,
    medium:   summary.medium_findings,
    low:      summary.low_findings,
  };

  const analysisDate = summary.analysis_timestamp
    ? new Date(summary.analysis_timestamp).toLocaleString()
    : 'Unknown';

  return (
    <div className="min-h-screen bg-dark-900 text-white">

      {/* ── Header ─────────────────────────────────────────────────── */}
      <header className="bg-dark-800 border-b border-dark-700 sticky top-0 z-10 backdrop-blur">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-2xl">🔵</span>
              <div>
                <h1 className="text-xl font-bold text-primary-400 leading-none">
                  BlueHound
                </h1>
                <p className="text-xs text-gray-500 mt-0.5">
                  Active Directory Threat Modeling
                </p>
              </div>
            </div>

            <div className="flex items-center gap-6">
              <div className="hidden sm:block text-right">
                <p className="text-xs text-gray-500">Domain</p>
                <p className="text-sm font-semibold text-white">{summary.domain}</p>
              </div>
              <div className="hidden md:block text-right">
                <p className="text-xs text-gray-500">Last Analysis</p>
                <p className="text-xs text-gray-300">{analysisDate}</p>
              </div>
              {/* Live indicator */}
              <div className="flex items-center gap-1.5 text-xs text-green-400">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse-slow" />
                Live
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* ── Main ──────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

        {/* Tier-0 alert banner */}
        {summary.tier0_reachable && (
          <div className="bg-red-500/10 border border-red-500/40 rounded-xl px-5 py-3 flex items-center gap-3 animate-fade-in">
            <span className="text-2xl flex-shrink-0">🚨</span>
            <div>
              <p className="text-red-400 font-semibold text-sm">
                Tier-0 Reachable — Domain Admin compromise possible
              </p>
              {model.time_to_domain_admin && (
                <p className="text-red-300/70 text-xs mt-0.5">
                  Estimated time to DA: {model.time_to_domain_admin}
                </p>
              )}
            </div>
          </div>
        )}

        {/* ── Summary cards row ───────────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

          <RiskScoreCard summary={summary} />

          {/* Exposure */}
          <div className="card">
            <h3 className="text-gray-400 text-sm font-medium mb-3">Exposure Level</h3>
            <p className="text-2xl font-bold mb-2 capitalize">
              {summary.exposure_level.replace(/-/g, ' ')}
            </p>
            <span
              className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                summary.tier0_reachable
                  ? 'bg-red-500/20 text-red-400'
                  : 'bg-green-500/20 text-green-400'
              }`}
            >
              {summary.tier0_reachable ? '⚠ Tier-0 Reachable' : '✓ Tier-0 Isolated'}
            </span>
            {model.blast_radius != null && (
              <p className="text-xs text-gray-500 mt-2">
                Blast radius: {(model.blast_radius * 100).toFixed(0)}%
              </p>
            )}
          </div>

          {/* Findings count */}
          <div className="card">
            <h3 className="text-gray-400 text-sm font-medium mb-3">Total Findings</h3>
            <p className="text-4xl font-bold tabular-nums mb-3">
              {summary.total_findings}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {summary.critical_findings > 0 && (
                <span className="badge bg-red-500/20 text-red-400">
                  {summary.critical_findings} Critical
                </span>
              )}
              {summary.high_findings > 0 && (
                <span className="badge bg-orange-500/20 text-orange-400">
                  {summary.high_findings} High
                </span>
              )}
              {summary.medium_findings > 0 && (
                <span className="badge bg-yellow-500/20 text-yellow-400">
                  {summary.medium_findings} Medium
                </span>
              )}
              {summary.low_findings > 0 && (
                <span className="badge bg-green-500/20 text-green-400">
                  {summary.low_findings} Low
                </span>
              )}
            </div>
          </div>

          {/* Detection info */}
          <div className="card">
            <h3 className="text-gray-400 text-sm font-medium mb-3">Detection Info</h3>
            {model.time_to_domain_admin && (
              <div className="mb-2">
                <p className="text-xs text-gray-500">Time to Domain Admin</p>
                <p className="text-sm font-medium text-white">{model.time_to_domain_admin}</p>
              </div>
            )}
            {model.detection_surface && (
              <div className="mb-2">
                <p className="text-xs text-gray-500">Detection Surface</p>
                <p className="text-sm font-medium text-white">{model.detection_surface}</p>
              </div>
            )}
            <div>
              <p className="text-xs text-gray-500">Collector</p>
              <p className="text-sm font-medium text-white capitalize">
                {model.metadata.collector}
              </p>
            </div>
          </div>
        </div>

        {/* ── Charts ──────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <FindingsChart data={model.category_breakdown} type="category" />
          <FindingsChart data={severityData} type="severity" />
        </div>

        {/* ── Attack path ─────────────────────────────────────────── */}
        {summary.tier0_reachable && model.primary_kill_path && (
          <AttackPathVisualization killPath={model.primary_kill_path} />
        )}

        {/* ── Bottom row: top fixes + findings table ───────────────── */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="xl:col-span-1">
            <TopFixes fixes={model.top_fixes} />
          </div>
          <div className="xl:col-span-2">
            <FindingsTable />
          </div>
        </div>

      </main>

      {/* ── Footer ─────────────────────────────────────────────────── */}
      <footer className="border-t border-dark-700 mt-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col sm:flex-row items-center justify-between gap-2">
          <p className="text-gray-600 text-xs">
            BlueHound v{model.metadata.version} · Active Directory Threat Modeling Engine
          </p>
          <p className="text-gray-600 text-xs">
            Domain: {model.metadata.domain_fqdn}
          </p>
        </div>
      </footer>
    </div>
  );
}
