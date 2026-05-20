import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts';
import type { ThreatModelSummary } from '../types';

interface Props {
  summary: ThreatModelSummary;
}

function getRiskColor(score: number): string {
  if (score >= 9.0) return '#ef4444';
  if (score >= 7.5) return '#f97316';
  if (score >= 5.0) return '#eab308';
  return '#22c55e';
}

function getRiskBorder(score: number): string {
  if (score >= 9.0) return 'border-red-500';
  if (score >= 7.5) return 'border-orange-500';
  if (score >= 5.0) return 'border-yellow-500';
  return 'border-green-500';
}

export default function RiskScoreCard({ summary }: Props) {
  const color = getRiskColor(summary.risk_score);
  const chartData = [
    { value: summary.risk_score * 10, fill: color },
  ];

  return (
    <div className={`card border-2 ${getRiskBorder(summary.risk_score)} relative overflow-hidden`}>
      {/* Subtle glow */}
      <div
        className="absolute inset-0 opacity-5 rounded-xl"
        style={{ background: color }}
      />

      <h3 className="text-gray-400 text-sm font-medium mb-1 relative z-10">
        Risk Score
      </h3>

      <div className="flex items-center gap-4 relative z-10">
        {/* Gauge */}
        <div className="w-24 h-24 flex-shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              cx="50%" cy="50%"
              innerRadius="60%" outerRadius="100%"
              barSize={8}
              data={chartData}
              startAngle={210} endAngle={-30}
            >
              <RadialBar dataKey="value" cornerRadius={4} />
            </RadialBarChart>
          </ResponsiveContainer>
        </div>

        <div>
          <div className="text-4xl font-bold tabular-nums" style={{ color }}>
            {summary.risk_score.toFixed(1)}
            <span className="text-lg text-gray-500 font-normal">/10</span>
          </div>
          <div className="text-sm font-semibold mt-1 uppercase tracking-wider" style={{ color }}>
            {summary.risk_classification}
          </div>
        </div>
      </div>
    </div>
  );
}
