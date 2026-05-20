// ─── API response shapes ───────────────────────────────────────────────────

export interface ThreatModelSummary {
  risk_score: number;
  risk_classification: string;
  exposure_level: string;
  tier0_reachable: boolean;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  domain: string;
  analysis_timestamp: string;
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export interface Evidence {
  type: string;
  raw_data: Record<string, unknown>;
  reasoning: string;
}

export interface Finding {
  id: string;
  category: string;
  severity: SeverityLevel;
  confidence: string;
  title: string;
  description: string;
  evidence: Evidence;
  affected_principals: string[];
  mitre_techniques: string[];
  remediation: string;
}

export interface FindingsResponse {
  total: number;
  filters: {
    category?: string | null;
    severity?: string | null;
    limit?: number | null;
  };
  findings: Finding[];
}

export interface KillPath {
  nodes: string[];
  techniques: string[];
  estimated_time: string;
  stealth_level: string;
}

export interface AttackPath {
  tier0_reachable: boolean;
  primary_kill_path: KillPath | null;
  time_to_domain_admin?: string;
}

export interface Statistics {
  total_findings: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  blast_radius: number | null;
  tier0_reachable: boolean;
  time_to_domain_admin?: string | null;
  detection_surface?: string | null;
  category_breakdown: Record<string, number>;
}

export interface SnapshotMetadata {
  version: string;
  collected_at: string;
  domain_fqdn: string;
  collector: string;
  signature: string;
}

export interface ThreatModel {
  metadata: SnapshotMetadata;
  risk_score: number;
  risk_classification: string;
  exposure_level: string;
  tier0_reachable: boolean;
  blast_radius: number | null;
  time_to_domain_admin?: string | null;
  detection_surface?: string | null;
  category_breakdown: Record<string, number>;
  findings: Finding[];
  top_fixes: string[];
  primary_kill_path: KillPath | null;
}

export interface Snapshot {
  timestamp: string;
  domain: string;
  risk_score: number;
  risk_classification: string;
  findings_count: number;
  file_path: string;
}

export interface SnapshotsResponse {
  snapshots: Snapshot[];
}

// ─── UI helpers ────────────────────────────────────────────────────────────

export type SeverityColorKey = SeverityLevel;

export const SEVERITY_COLORS: Record<SeverityColorKey, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
};

export const SEVERITY_BADGE: Record<SeverityColorKey, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
  high:     'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium:   'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  low:      'bg-green-500/20 text-green-400 border border-green-500/30',
};

export const SEVERITY_LEFT_BORDER: Record<SeverityColorKey, string> = {
  critical: 'border-l-red-500',
  high:     'border-l-orange-500',
  medium:   'border-l-yellow-500',
  low:      'border-l-green-500',
};

export const CATEGORY_COLORS: Record<string, string> = {
  'privilege_exposure': '#3b82f6',
  'kerberos_abuse':     '#8b5cf6',
  'delegation_abuse':   '#ec4899',
  'adcs_abuse':         '#f59e0b',
  'tier0_exposure':     '#ef4444',
};

export function formatCategory(raw: string): string {
  return raw
    .split('_')
    .map(w => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}
