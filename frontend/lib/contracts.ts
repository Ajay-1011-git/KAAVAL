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
