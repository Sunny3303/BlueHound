import { useState } from 'react';
import { useFindings } from '../api/client';
import { SEVERITY_BADGE, SEVERITY_LEFT_BORDER, formatCategory, type SeverityLevel } from '../types';
import LoadingSpinner from './LoadingSpinner';

export default function FindingsTable() {
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, error, isLoading } = useFindings(category, severity);

  if (isLoading) return <div className="card"><LoadingSpinner /></div>;

  if (error) {
    return (
      <div className="card">
        <p className="text-red-400 text-sm">Error loading findings: {error.message}</p>
      </div>
    );
  }

  const findings = data?.findings ?? [];

  return (
    <div className="card">
      {/* Header + filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h3 className="text-base font-semibold text-gray-200">Findings Details</h3>
          <p className="text-xs text-gray-500 mt-0.5">
            {data?.total ?? 0} finding{(data?.total ?? 0) !== 1 ? 's' : ''}
            {(category || severity) ? ' (filtered)' : ''}
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <select
            value={category}
            onChange={e => setCategory(e.target.value)}
            className="select-dark"
          >
            <option value="">All Categories</option>
            <option value="privilege_exposure">Privilege Exposure</option>
            <option value="kerberos_abuse">Kerberos Abuse</option>
            <option value="delegation_abuse">Delegation Abuse</option>
            <option value="adcs_abuse">ADCS Abuse</option>
            <option value="tier0_exposure">Tier-0 Exposure</option>
          </select>

          <select
            value={severity}
            onChange={e => setSeverity(e.target.value)}
            className="select-dark"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {(category || severity) && (
            <button
              onClick={() => { setCategory(''); setSeverity(''); }}
              className="btn-ghost text-sm"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Findings list */}
      {findings.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <div className="text-4xl mb-3">🔍</div>
          <p className="text-sm">No findings match the selected filters</p>
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map(finding => {
            const isOpen = expanded === finding.id;
            const sev = finding.severity as SeverityLevel;

            return (
              <div
                key={finding.id}
                className={`border-l-4 ${SEVERITY_LEFT_BORDER[sev]} bg-dark-900/50 rounded-r-lg overflow-hidden`}
              >
                {/* Summary row — always visible */}
                <button
                  className="w-full text-left px-4 py-3 flex items-start justify-between gap-3 hover:bg-dark-700/40 transition-colors"
                  onClick={() => setExpanded(isOpen ? null : finding.id)}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className={`badge ${SEVERITY_BADGE[sev]}`}>
                        {finding.severity}
                      </span>
                      <span className="text-xs text-gray-500">
                        {formatCategory(finding.category)}
                      </span>
                      <span className="text-xs text-gray-600 font-mono">
                        {finding.id}
                      </span>
                    </div>
                    <p className="text-sm font-medium text-white truncate">
                      {finding.title}
                    </p>
                  </div>
                  <span className="text-gray-500 text-xs mt-1 flex-shrink-0">
                    {isOpen ? '▲' : '▼'}
                  </span>
                </button>

                {/* Expanded detail */}
                {isOpen && (
                  <div className="px-4 pb-4 border-t border-dark-700/50 pt-3 space-y-4 animate-fade-in">
                    <p className="text-sm text-gray-300 leading-relaxed">
                      {finding.description}
                    </p>

                    {finding.remediation && (
                      <div className="bg-primary-900/20 border border-primary-700/30 rounded-lg p-3">
                        <p className="text-xs text-primary-400 font-semibold uppercase tracking-wider mb-1">
                          Remediation
                        </p>
                        <p className="text-sm text-gray-300">{finding.remediation}</p>
                      </div>
                    )}

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                      {finding.mitre_techniques.length > 0 && (
                        <div>
                          <p className="text-gray-500 uppercase tracking-wider mb-1.5">
                            MITRE ATT&amp;CK
                          </p>
                          <div className="flex flex-wrap gap-1.5">
                            {finding.mitre_techniques.map(t => (
                              <span
                                key={t}
                                className="px-2 py-0.5 bg-dark-700 border border-dark-600 rounded text-gray-300 font-mono"
                              >
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {finding.affected_principals.length > 0 && (
                        <div>
                          <p className="text-gray-500 uppercase tracking-wider mb-1.5">
                            Affected Principals ({finding.affected_principals.length})
                          </p>
                          <div className="space-y-1 max-h-24 overflow-y-auto">
                            {finding.affected_principals.map(p => (
                              <p
                                key={p}
                                className="font-mono text-gray-400 truncate"
                                title={p}
                              >
                                {p}
                              </p>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {finding.evidence.reasoning && (
                      <div>
                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-1.5">
                          Reasoning
                        </p>
                        <p className="text-xs text-gray-400 italic leading-relaxed">
                          {finding.evidence.reasoning}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
