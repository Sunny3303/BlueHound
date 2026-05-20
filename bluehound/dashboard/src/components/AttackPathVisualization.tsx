import type { KillPath } from '../types';

interface Props {
  killPath: KillPath;
}

export default function AttackPathVisualization({ killPath }: Props) {
  return (
    <div className="card border-2 border-red-500/60 bg-red-500/5 animate-fade-in">
      <div className="flex items-center gap-2 mb-5">
        <span className="text-xl">⚠️</span>
        <h3 className="text-lg font-semibold text-red-400">
          Primary Kill Path to Tier-0
        </h3>
      </div>

      {/* Path nodes */}
      <div className="flex flex-wrap items-center gap-2 mb-5 p-4 bg-dark-900/60 rounded-lg border border-red-500/20">
        {killPath.nodes.map((node, idx) => (
          <span key={idx} className="flex items-center gap-2">
            <span className="px-3 py-1.5 bg-dark-700 border border-dark-600 rounded-lg text-sm font-mono text-white">
              {node}
            </span>
            {idx < killPath.nodes.length - 1 && (
              <span className="text-red-500 font-bold text-lg select-none">→</span>
            )}
          </span>
        ))}
      </div>

      {/* Meta */}
      <div className="flex flex-wrap gap-4 mb-5 text-sm text-gray-400">
        {killPath.estimated_time && (
          <span className="flex items-center gap-1.5">
            <span>⏱</span>
            <span>Estimated time: <span className="text-white">{killPath.estimated_time}</span></span>
          </span>
        )}
        {killPath.stealth_level && (
          <span className="flex items-center gap-1.5">
            <span>🕵️</span>
            <span>Stealth: <span className="text-white">{killPath.stealth_level}</span></span>
          </span>
        )}
      </div>

      {/* Techniques */}
      {killPath.techniques.length > 0 && (
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            Techniques Used
          </p>
          <div className="flex flex-wrap gap-2">
            {killPath.techniques.map((t, idx) => (
              <span
                key={idx}
                className="px-3 py-1 bg-red-500/15 border border-red-500/30 text-red-300 rounded-full text-sm"
              >
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
