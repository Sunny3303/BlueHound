import useSWR from 'swr';
import type {
  ThreatModelSummary,
  FindingsResponse,
  AttackPath,
  Statistics,
  ThreatModel,
  SnapshotsResponse,
} from '../types';

// SWR expects a plain fetcher — the generic type T is inferred at the hook
// call site via useSWR<T>, not inside the fetcher itself.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fetcher = async (url: string): Promise<any> => {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
};

const REFRESH = { refreshInterval: 30_000 }; // poll every 30 s

export function useSummary(snapshot?: string) {
  const url = snapshot ? `/api/summary?snapshot=${snapshot}` : '/api/summary';
  return useSWR<ThreatModelSummary>(url, fetcher, REFRESH);
}

export function useFindings(category?: string, severity?: string) {
  const params = new URLSearchParams();
  if (category) params.append('category', category);
  if (severity) params.append('severity', severity);
  const qs = params.toString();
  return useSWR<FindingsResponse>(
    qs ? `/api/findings?${qs}` : '/api/findings',
    fetcher,
  );
}

export function useAttackPath(snapshot?: string) {
  const url = snapshot
    ? `/api/attack-paths?snapshot=${snapshot}`
    : '/api/attack-paths';
  return useSWR<AttackPath>(url, fetcher);
}

export function useStatistics(snapshot?: string) {
  const url = snapshot
    ? `/api/statistics?snapshot=${snapshot}`
    : '/api/statistics';
  return useSWR<Statistics>(url, fetcher);
}

export function useThreatModel(snapshot?: string) {
  const url = snapshot
    ? `/api/threat-model?snapshot=${snapshot}`
    : '/api/threat-model';
  return useSWR<ThreatModel>(url, fetcher, REFRESH);
}

export function useSnapshots() {
  return useSWR<SnapshotsResponse>('/api/snapshots', fetcher);
}
