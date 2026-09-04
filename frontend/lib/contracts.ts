export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_type:
    | "session_bound"
    | "replay_attempted"
    | "proof_absent"
    | "signature_invalid"
    | "request_blocked"
    | "request_allowed"
    | "oauth_grant_blocked"
    | "oauth_grant_allowed"
    | "device_code_blocked";
  session_id: string | null;
  user_id: string | null;
  application_id: string | null;
  reason: string;
  detail: Record<string, string>;
  severity: "info" | "warning" | "blocked";
}

export interface RadarFinding {
  finding_id: string;
  check: string;
  severity: "low" | "medium" | "high";
  affected_count: number;
  description: string;
  remediation: string;
}

export interface RadarReport {
  organization_id: string;
  exposure_score: number;
  exposure_label: "Low" | "Medium" | "High";
  generated_at: string;
  findings: RadarFinding[];
}

export interface IncidentExplanation {
  incident_id: string;
  related_event_ids: string[];
  summary: string;
  affected_user: string | null;
  affected_application: string | null;
  suggested_remediation: string[];
  generated_at: string;
}
