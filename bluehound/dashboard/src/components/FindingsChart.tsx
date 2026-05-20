import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';
import { CATEGORY_COLORS, SEVERITY_COLORS, formatCategory } from '../types';

interface Props {
  data: Record<string, number>;
  type: 'category' | 'severity';
}

const TOOLTIP_STYLE = {
  backgroundColor: '#1e293b',
  border: '1px solid #334155',
  borderRadius: '0.5rem',
  color: '#f1f5f9',
};

export default function FindingsChart({ data, type }: Props) {
  const chartData = Object.entries(data)
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({
      name:  formatCategory(key),
      rawKey: key,
      value,
    }));

  if (chartData.length === 0) {
    return (
      <div className="card flex items-center justify-center h-64">
        <p className="text-gray-500 text-sm">No data to display</p>
      </div>
    );
  }

  if (type === 'severity') {
    return (
      <div className="card">
        <h3 className="text-base font-semibold mb-4 text-gray-200">
          Findings by Severity
        </h3>
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie
              data={chartData}
              cx="50%" cy="50%"
              outerRadius={90}
              innerRadius={48}
              dataKey="value"
              paddingAngle={3}
              label={({ name, percent }) =>
                percent > 0.05 ? `${name} ${(percent * 100).toFixed(0)}%` : ''
              }
              labelLine={false}
            >
              {chartData.map((entry) => (
                <Cell
                  key={entry.rawKey}
                  fill={SEVERITY_COLORS[entry.rawKey as keyof typeof SEVERITY_COLORS] ?? '#64748b'}
                />
              ))}
            </Pie>
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Legend
              iconType="circle"
              iconSize={8}
              formatter={(value) => (
                <span className="text-gray-300 text-sm">{value}</span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    );
  }

  // ── Category bar chart ──────────────────────────────────────────────────
  return (
    <div className="card">
      <h3 className="text-base font-semibold mb-4 text-gray-200">
        Findings by Category
      </h3>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={chartData} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={{ stroke: '#334155' }}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {chartData.map((entry) => (
              <Cell
                key={entry.rawKey}
                fill={CATEGORY_COLORS[entry.rawKey] ?? '#3b82f6'}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
