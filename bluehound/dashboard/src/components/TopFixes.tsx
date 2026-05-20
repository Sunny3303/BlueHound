interface Props {
  fixes: string[];
}

export default function TopFixes({ fixes }: Props) {
  if (!fixes || fixes.length === 0) return null;

  return (
    <div className="card">
      <h3 className="text-base font-semibold mb-4 text-gray-200">
        Top Remediation Priorities
      </h3>
      <ol className="space-y-3">
        {fixes.slice(0, 10).map((fix, idx) => (
          <li
            key={idx}
            className="flex items-start gap-3 pb-3 border-b border-dark-700 last:border-b-0 last:pb-0 animate-slide-up"
            style={{ animationDelay: `${idx * 40}ms` }}
          >
            <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary-600 text-white flex items-center justify-center text-xs font-bold mt-0.5">
              {idx + 1}
            </span>
            <span className="text-gray-300 text-sm leading-relaxed">{fix}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}
