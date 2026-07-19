export type Profile = "app" | "api" | "brochure";
export type Expectation =
  | "observe"
  | "recommended"
  | "required"
  | "not_applicable";

export interface Bootstrap {
  tool_version: string;
  workspace_schema_version: string;
  mapping_set_version: string;
  allow_private_targets: boolean;
  workspaces: WorkspaceListItem[];
}

export interface WorkspaceListItem {
  workspace_id: string;
  revision: number;
  schema_version: string;
  name: string;
  updated_at: string;
}

export interface PolicyTarget {
  id: string;
  url: string;
  profile: Profile;
  minimum_score: number;
  maximum_score_drop: number;
  required_controls: string[];
  reporting_readiness: Expectation;
  cross_origin_isolation: Expectation;
  allow_cross_origin_redirects?: boolean;
  include_query?: boolean;
  timeout?: number;
}

export interface WorkspaceDocument {
  schema_version: string;
  workspace_id: string;
  name: string;
  policy: {
    schema_version: string;
    methodology_version: string;
    name: string;
    defaults: {
      fail_on_severity: string[];
      allow_auto_profile: boolean;
    };
    targets: PolicyTarget[];
  };
  approved_baseline: BaselineCandidate | null;
  latest_summaries: Record<string, TargetSummary>;
  created_at: string;
  updated_at: string;
}

export interface WorkspaceRecord {
  revision: number;
  document: WorkspaceDocument;
}

export interface TargetSummary {
  target_id: string;
  completed_at: string;
  target: string;
  selected_profile: Profile;
  score: number;
  outcome: "passed" | "failed" | "operational_error";
  exit_code: 0 | 1 | 2;
  findings: Record<string, SummaryFinding>;
}

export interface SummaryFinding {
  status: string;
  severity: string;
  category: string;
  applicability: string;
  points: number;
  max_points: number;
}

export interface EvidenceMapping {
  control_key: string;
  framework_id: string;
  framework: string;
  framework_version: string;
  requirement: string;
  relationship: string;
  rationale: string;
  limitations: string;
  citation_key: string;
  evidence_family: string;
  confidence: string;
}

export interface DetailedFinding extends SummaryFinding {
  key: string;
  name: string;
  value: string | null;
  note: string;
  recommendation: string;
  scoring_rationale: string;
  citation_keys: string[];
  standards: string[];
  evidence_mappings: EvidenceMapping[];
}

export interface AssessmentResult {
  target: string;
  final_url: string | null;
  status_code: number | null;
  requested_profile: string;
  selected_profile: Profile | null;
  profile_label: string | null;
  profile_confidence: string | null;
  profile_evidence: string[];
  score: number;
  summary: string;
  findings: DetailedFinding[];
  error: string | null;
}

export interface AssurancePayload {
  methodology_version: string;
  mapping_set_version: string;
  policy_name: string;
  policy_schema_version: string;
  baseline_schema_version: string | null;
  outcome: "passed" | "failed" | "operational_error";
  exit_code: 0 | 1 | 2;
  assessments: {
    target_id: string;
    policy: PolicyTarget;
    result: AssessmentResult;
  }[];
  policy_violations: Diagnostic[];
  regressions: Diagnostic[];
  operational_errors: string[];
}

export interface Diagnostic {
  target_id: string;
  code: string;
  severity: string;
  control_key: string | null;
  message: string;
  previous?: string | number | null;
  current?: string | number | null;
}

export interface RunResponse {
  record: WorkspaceRecord;
  run: AssurancePayload;
}

export interface BaselineCandidate {
  schema_version: string;
  methodology_version: string;
  mapping_set_version: string;
  policy_name: string;
  targets: Record<string, {
    target: string;
    selected_profile: Profile;
    score: number;
    findings: Record<string, SummaryFinding>;
  }>;
}

export interface BaselineDiff {
  previous_present: boolean;
  change_count: number;
  targets: {
    target_id: string;
    change: "added" | "changed" | "removed";
    previous_score: number | null;
    candidate_score: number | null;
    changed_controls: string[];
  }[];
}

export interface BaselineCandidateResponse extends RunResponse {
  candidate: BaselineCandidate;
  diff: BaselineDiff;
}

export interface BaselineApprovalResponse {
  record: WorkspaceRecord;
  approved: BaselineCandidate;
}

export type ReportFormat = "html" | "markdown" | "json" | "sarif" | "junit";

export interface ReportExport {
  format: ReportFormat;
  media_type: string;
  filename: string;
  content: string;
}

export type ViewName =
  | "targets"
  | "assessment"
  | "assurance"
  | "evidence"
  | "workspace";
