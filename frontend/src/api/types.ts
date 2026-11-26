export interface TenantResponse {
  id: string
  name: string
  slug: string
  created_at: string
  updated_at: string
}

export type SecurityEventSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'

export type SecurityEventOrigin = 'manual' | 'simulated' | 'integration'

export interface SecurityEventResponse {
  id: string
  tenant_id: string
  event_type: string
  severity: SecurityEventSeverity
  source: string
  description: string
  payload: Record<string, unknown>
  metadata: Record<string, unknown>
  timestamp: string
  origin: SecurityEventOrigin
  created_at: string
}

export interface SecurityEventCreateRequest {
  event_type: string
  severity: SecurityEventSeverity
  source: string
  description: string
  timestamp?: string
  metadata?: Record<string, unknown>
  origin: SecurityEventOrigin
}

export interface SecurityEventTimeBucket {
  date: string
  count: number
}

export interface SecurityMonitoringSummary {
  total_events: number
  critical_events: number
  high_severity_events: number
  events_by_source: Record<string, number>
  new_alerts: number
  acknowledged_alerts: number
  resolved_alerts: number
  events_over_time: SecurityEventTimeBucket[]
}

export type AlertStatus = 'New' | 'Acknowledged' | 'Resolved'
export type AlertSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'

export interface AlertResponse {
  id: string
  tenant_id: string
  event_id: string
  rule_id: string
  severity: AlertSeverity
  description: string
  status: AlertStatus
  created_at: string
  updated_at: string
}

export type VulnerabilitySeverity =
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low'
  | 'Informational'

export type VulnerabilityStatus =
  | 'Open'
  | 'In Progress'
  | 'Resolved'
  | 'Accepted Risk'

export interface VulnerabilitySummary {
  total_vulnerabilities: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  open_findings: number
  resolved_findings: number
  overdue_findings: number
}

export interface VulnerabilityResponse {
  id: string
  tenant_id: string
  asset_id: string
  title: string
  description: string
  cve_id: string | null
  cvss_score: number
  severity: VulnerabilitySeverity
  status: VulnerabilityStatus
  detection_source: string
  remediation_recommendation: string
  first_detected_at: string
  last_updated_at: string
  remediation_due_date: string | null
}
