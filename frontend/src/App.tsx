import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  ClipboardCheck,
  Database,
  Download,
  FileJson,
  History,
  Info,
  Library,
  LoaderCircle,
  Play,
  Plus,
  RotateCcw,
  ShieldCheck,
  Target,
  Trash2,
  Upload,
  X,
  XCircle,
} from "lucide-react";
import {
  type ChangeEvent,
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { ApiError, WorkspaceApi } from "./api";
import type {
  AssurancePayload,
  AuditHistoryEntry,
  BaselineCandidateResponse,
  Bootstrap,
  DetailedFinding,
  PolicyTarget,
  Profile,
  ReportFormat,
  RunResponse,
  TargetSummary,
  ViewName,
  WorkspaceDocument,
  WorkspaceImportPreview,
  WorkspaceRecord,
} from "./types";

interface AppProps {
  sessionToken: string | null;
}

interface TargetDraft {
  label: string;
  url: string;
  profile: Profile;
  minimumScore: number;
  reporting: PolicyTarget["reporting_readiness"];
  isolation: PolicyTarget["cross_origin_isolation"];
}

const EMPTY_TARGET: TargetDraft = {
  label: "",
  url: "https://",
  profile: "app",
  minimumScore: 75,
  reporting: "observe",
  isolation: "not_applicable",
};

const MAX_WORKSPACE_IMPORT_BYTES = 2 * 1024 * 1024;

const NAVIGATION: {
  id: ViewName;
  label: string;
  icon: typeof Target;
}[] = [
  { id: "targets", label: "Targets", icon: Target },
  { id: "assessment", label: "Assessment", icon: ClipboardCheck },
  { id: "assurance", label: "Assurance", icon: CircleGauge },
  { id: "history", label: "History", icon: History },
  { id: "evidence", label: "Evidence", icon: Library },
  { id: "workspace", label: "Workspace", icon: Database },
];

export function App({ sessionToken }: AppProps) {
  const api = useMemo(
    () => (sessionToken ? new WorkspaceApi(sessionToken) : null),
    [sessionToken],
  );
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [record, setRecord] = useState<WorkspaceRecord | null>(null);
  const [run, setRun] = useState<AssurancePayload | null>(null);
  const [baselineCandidate, setBaselineCandidate] =
    useState<BaselineCandidateResponse | null>(null);
  const [view, setView] = useState<ViewName>("targets");
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningTarget, setRunningTarget] = useState<string | "all" | null>(null);
  const [baselineBusy, setBaselineBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showTargetForm, setShowTargetForm] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [targetToEdit, setTargetToEdit] = useState<PolicyTarget | null>(null);
  const [importPreview, setImportPreview] = useState<WorkspaceImportPreview | null>(
    null,
  );
  const importInput = useRef<HTMLInputElement>(null);

  const loadWorkspace = useCallback(
    async (workspaceId: string) => {
      if (!api) return;
      const next = await api.getWorkspace(workspaceId);
      setRecord(next);
      setSelectedTargetId(
        (current) =>
          current ??
          next.document.policy.targets[0]?.id ??
          null,
      );
    },
    [api],
  );

  const refresh = useCallback(async () => {
    if (!api) return;
    setLoading(true);
    setError(null);
    try {
      const nextBootstrap = await api.bootstrap();
      setBootstrap(nextBootstrap);
      if (nextBootstrap.workspaces.length) {
        await loadWorkspace(nextBootstrap.workspaces[0].workspace_id);
      } else {
        setShowCreateForm(true);
      }
    } catch (caught) {
      setError(messageFor(caught));
    } finally {
      setLoading(false);
    }
  }, [api, loadWorkspace]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const selectedTarget =
    record?.document.policy.targets.find(
      (target) => target.id === selectedTargetId,
    ) ?? null;
  const selectedSummary = selectedTargetId
    ? record?.document.latest_summaries[selectedTargetId] ?? null
    : null;
  const selectedAssessment =
    run?.assessments.find(
      (assessment) => assessment.target_id === selectedTargetId,
    ) ?? null;

  async function createWorkspace(draft: TargetDraft, workspaceName: string) {
    if (!api || !bootstrap) return;
    setError(null);
    try {
      const document = newWorkspaceDocument(
        workspaceName,
        draft,
        bootstrap,
      );
      const created = await api.createWorkspace(document);
      setRecord(created);
      setSelectedTargetId(created.document.policy.targets[0].id);
      setShowCreateForm(false);
      setView("targets");
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  async function saveTarget(draft: TargetDraft) {
    if (!api || !record) return;
    const nextTarget = targetFromDraft(
      draft,
      record.document.policy.targets,
      targetToEdit?.id,
    );
    const nextDocument = structuredClone(record.document);
    const existingIndex = nextDocument.policy.targets.findIndex(
      (target) => target.id === targetToEdit?.id,
    );
    if (existingIndex >= 0) {
      nextDocument.policy.targets[existingIndex] = nextTarget;
      if (targetToEdit?.id !== nextTarget.id) {
        delete nextDocument.latest_summaries[targetToEdit!.id];
        nextDocument.disabled_target_ids = nextDocument.disabled_target_ids.map(
          (id) => (id === targetToEdit!.id ? nextTarget.id : id),
        );
      }
    } else {
      nextDocument.policy.targets.push(nextTarget);
    }
    nextDocument.updated_at = now();
    try {
      const saved = await api.saveWorkspace({
        revision: record.revision,
        document: nextDocument,
      });
      setRecord(saved);
      setSelectedTargetId(nextTarget.id);
      setRun(null);
      setShowTargetForm(false);
      setTargetToEdit(null);
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  async function removeTarget(targetId: string) {
    if (!api || !record || record.document.policy.targets.length === 1) return;
    const nextDocument = structuredClone(record.document);
    nextDocument.policy.targets = nextDocument.policy.targets.filter(
      (target) => target.id !== targetId,
    );
    nextDocument.disabled_target_ids = nextDocument.disabled_target_ids.filter(
      (id) => id !== targetId,
    );
    delete nextDocument.latest_summaries[targetId];
    nextDocument.updated_at = now();
    try {
      const saved = await api.saveWorkspace({
        revision: record.revision,
        document: nextDocument,
      });
      setRecord(saved);
      setSelectedTargetId(saved.document.policy.targets[0]?.id ?? null);
      setRun(null);
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  async function toggleTargetDisabled(targetId: string) {
    if (!api || !record) return;
    const nextDocument = structuredClone(record.document);
    const disabled = new Set(nextDocument.disabled_target_ids);
    if (disabled.has(targetId)) {
      disabled.delete(targetId);
    } else {
      disabled.add(targetId);
      delete nextDocument.latest_summaries[targetId];
    }
    nextDocument.disabled_target_ids = [...disabled].sort();
    nextDocument.updated_at = now();
    try {
      const saved = await api.saveWorkspace({
        revision: record.revision,
        document: nextDocument,
      });
      setRecord(saved);
      setRun(null);
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  async function executeAudit(targetId?: string) {
    if (!api || !record) return;
    setError(null);
    setRunningTarget(targetId ?? "all");
    try {
      const response: RunResponse = await api.runTarget(record, targetId);
      setRecord(response.record);
      setRun(response.run);
      if (targetId) setSelectedTargetId(targetId);
      setView(targetId ? "assessment" : "assurance");
    } catch (caught) {
      setError(messageFor(caught));
    } finally {
      setRunningTarget(null);
    }
  }

  async function createBaselineCandidate() {
    if (!api || !record) return;
    setError(null);
    setBaselineBusy(true);
    try {
      const response = await api.createBaselineCandidate(record);
      setRecord(response.record);
      setRun(response.run);
      setBaselineCandidate(response);
      setView("assurance");
    } catch (caught) {
      setError(messageFor(caught));
    } finally {
      setBaselineBusy(false);
    }
  }

  async function approveBaseline() {
    if (!api || !baselineCandidate) return;
    setError(null);
    setBaselineBusy(true);
    try {
      const response = await api.approveBaseline(
        baselineCandidate.record,
        baselineCandidate.candidate,
      );
      setRecord(response.record);
      setBaselineCandidate(null);
    } catch (caught) {
      setError(messageFor(caught));
    } finally {
      setBaselineBusy(false);
    }
  }

  async function exportCurrentReport(reportFormat: ReportFormat) {
    if (!api || !record) return;
    setError(null);
    try {
      const report = await api.exportCurrentReport(
        record.document.workspace_id,
        reportFormat,
      );
      const objectUrl = URL.createObjectURL(
        new Blob([report.content], { type: report.media_type }),
      );
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = report.filename;
      anchor.click();
      URL.revokeObjectURL(objectUrl);
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  function exportWorkspace() {
    if (!record) return;
    const text = `${JSON.stringify(record.document, null, 2)}\n`;
    const objectUrl = URL.createObjectURL(
      new Blob([text], { type: "application/json" }),
    );
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = `${slug(record.document.name)}-workspace-v${record.document.schema_version}.json`;
    anchor.click();
    URL.revokeObjectURL(objectUrl);
  }

  async function importWorkspace(event: ChangeEvent<HTMLInputElement>) {
    if (!api || !event.target.files?.[0]) return;
    const file = event.target.files[0];
    setError(null);
    try {
      if (file.size > MAX_WORKSPACE_IMPORT_BYTES) {
        throw new Error(
          `Workspace imports must not exceed ${MAX_WORKSPACE_IMPORT_BYTES / 1024 / 1024} MiB.`,
        );
      }
      const imported = JSON.parse(await file.text()) as WorkspaceDocument;
      const preview = await api.previewWorkspaceImport(imported);
      setImportPreview(preview);
    } catch (caught) {
      setError(messageFor(caught));
    } finally {
      event.target.value = "";
    }
  }

  async function commitWorkspaceImport() {
    if (!api || !importPreview) return;
    setError(null);
    try {
      const saved = await api.commitWorkspaceImport(importPreview);
      setRecord(saved);
      setSelectedTargetId(saved.document.policy.targets[0]?.id ?? null);
      setRun(null);
      setShowCreateForm(false);
      setImportPreview(null);
      setBootstrap(await api.bootstrap());
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  async function deleteWorkspace() {
    if (!api || !record) return;
    if (!window.confirm(`Delete "${record.document.name}" from this device?`)) {
      return;
    }
    try {
      await api.deleteWorkspace(record);
      setRecord(null);
      setRun(null);
      setSelectedTargetId(null);
      await refresh();
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  if (!sessionToken) {
    return (
      <FatalState
        title="Workspace session unavailable"
        message="Stop the local workspace process and start a new session."
      />
    );
  }

  if (loading) {
    return (
      <div className="loading-screen" role="status">
        <LoaderCircle aria-hidden="true" className="spin" />
        <span>Opening local workspace</span>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to workspace
      </a>
      <TopBar
        record={record}
        bootstrap={bootstrap}
        onImport={() => importInput.current?.click()}
        onExport={exportWorkspace}
      />
      <input
        ref={importInput}
        className="visually-hidden"
        type="file"
        accept="application/json,.json"
        onChange={(event) => void importWorkspace(event)}
      />
      <SideNavigation view={view} onChange={setView} />
      <main id="main-content" className="workspace-main">
        {error && (
          <div className="error-banner" role="alert">
            <AlertTriangle aria-hidden="true" />
            <span>{error}</span>
            <button
              type="button"
              className="icon-button"
              aria-label="Dismiss error"
              title="Dismiss"
              onClick={() => setError(null)}
            >
              <X aria-hidden="true" />
            </button>
          </div>
        )}
        {record && view === "targets" && (
          <TargetsView
            record={record}
            selectedTargetId={selectedTargetId}
            runningTarget={runningTarget}
            onSelect={setSelectedTargetId}
            onAdd={() => {
              setTargetToEdit(null);
              setShowTargetForm(true);
            }}
            onEdit={(target) => {
              setTargetToEdit(target);
              setShowTargetForm(true);
            }}
            onRemove={(targetId) => void removeTarget(targetId)}
            onToggleDisabled={(targetId) => void toggleTargetDisabled(targetId)}
            onRun={(targetId) => void executeAudit(targetId)}
            onRunAll={() => void executeAudit()}
          />
        )}
        {record && view === "assessment" && (
          <AssessmentView
            target={selectedTarget}
            summary={selectedSummary}
            assessment={selectedAssessment}
            running={runningTarget === selectedTargetId}
            disabled={Boolean(
              selectedTargetId && record.document.disabled_target_ids.includes(selectedTargetId),
            )}
            onRun={() =>
              selectedTargetId && void executeAudit(selectedTargetId)
            }
          />
        )}
        {record && view === "assurance" && (
          <AssuranceView
            record={record}
            run={run}
            running={runningTarget === "all"}
            onRun={() => void executeAudit()}
            baselineBusy={baselineBusy}
            onCreateBaseline={() => void createBaselineCandidate()}
            onExport={(reportFormat) =>
              void exportCurrentReport(reportFormat)
            }
          />
        )}
        {record && view === "history" && (
          <AuditHistoryView history={record.document.audit_history} />
        )}
        {record && view === "evidence" && (
          <EvidenceView run={run} />
        )}
        {record && view === "workspace" && bootstrap && (
          <WorkspaceView
            record={record}
            bootstrap={bootstrap}
            onExport={exportWorkspace}
            onImport={() => importInput.current?.click()}
            onDelete={() => void deleteWorkspace()}
          />
        )}
      </main>
      {showCreateForm && bootstrap && (
        <TargetDialog
          title="Create workspace"
          requireWorkspaceName
          initial={EMPTY_TARGET}
          onCancel={bootstrap.workspaces.length ? () => setShowCreateForm(false) : undefined}
          onSubmit={(draft, workspaceName) =>
            void createWorkspace(draft, workspaceName)
          }
        />
      )}
      {showTargetForm && (
        <TargetDialog
          title={targetToEdit ? "Edit target" : "Add target"}
          initial={
            targetToEdit ? draftFromTarget(targetToEdit) : EMPTY_TARGET
          }
          onCancel={() => {
            setShowTargetForm(false);
            setTargetToEdit(null);
          }}
          onSubmit={(draft) => void saveTarget(draft)}
        />
      )}
      {baselineCandidate && (
        <BaselineReviewDialog
          response={baselineCandidate}
          approving={baselineBusy}
          onCancel={() => setBaselineCandidate(null)}
          onApprove={() => void approveBaseline()}
        />
      )}
      {importPreview && (
        <ImportPreviewDialog
          preview={importPreview}
          onCancel={() => setImportPreview(null)}
          onCommit={() => void commitWorkspaceImport()}
        />
      )}
    </div>
  );
}

function TopBar({
  record,
  bootstrap,
  onImport,
  onExport,
}: {
  record: WorkspaceRecord | null;
  bootstrap: Bootstrap | null;
  onImport: () => void;
  onExport: () => void;
}) {
  return (
    <header className="top-bar">
      <div className="brand">
        <ShieldCheck aria-hidden="true" />
        <strong>Security Headers Auditor</strong>
      </div>
      <div className="workspace-name">
        {record?.document.name ?? "Local workspace"}
      </div>
      <span className="local-status">
        <span aria-hidden="true" />
        Local only
      </span>
      <div className="top-actions">
        <button type="button" onClick={onImport}>
          <Upload aria-hidden="true" />
          <span>Import</span>
        </button>
        <button type="button" onClick={onExport} disabled={!record}>
          <Download aria-hidden="true" />
          <span>Export</span>
        </button>
        <span className="version-label">
          v{bootstrap?.tool_version ?? "-"}
        </span>
      </div>
    </header>
  );
}

function SideNavigation({
  view,
  onChange,
}: {
  view: ViewName;
  onChange: (view: ViewName) => void;
}) {
  return (
    <nav className="side-navigation" aria-label="Workspace sections">
      {NAVIGATION.map((item) => {
        const Icon = item.icon;
        return (
          <button
            type="button"
            key={item.id}
            className={view === item.id ? "active" : ""}
            aria-current={view === item.id ? "page" : undefined}
            onClick={() => onChange(item.id)}
          >
            <Icon aria-hidden="true" />
            <span>{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

function TargetsView({
  record,
  selectedTargetId,
  runningTarget,
  onSelect,
  onAdd,
  onEdit,
  onRemove,
  onToggleDisabled,
  onRun,
  onRunAll,
}: {
  record: WorkspaceRecord;
  selectedTargetId: string | null;
  runningTarget: string | "all" | null;
  onSelect: (id: string) => void;
  onAdd: () => void;
  onEdit: (target: PolicyTarget) => void;
  onRemove: (id: string) => void;
  onToggleDisabled: (id: string) => void;
  onRun: (id: string) => void;
  onRunAll: () => void;
}) {
  const disabledTargetIds = new Set(record.document.disabled_target_ids);
  const enabledTargetCount = record.document.policy.targets.filter(
    (target) => !disabledTargetIds.has(target.id),
  ).length;
  const selected =
    record.document.policy.targets.find(
      (target) => target.id === selectedTargetId,
    ) ?? record.document.policy.targets[0];
  const summary = selected
    ? record.document.latest_summaries[selected.id]
    : undefined;
  const counts = Object.values(record.document.latest_summaries).reduce(
    (current, item) => {
      current[item.outcome] += 1;
      return current;
    },
    { passed: 0, failed: 0, operational_error: 0 },
  );
  return (
    <div className="targets-layout">
      <section className="targets-pane" aria-labelledby="targets-heading">
        <div className="page-heading">
          <div>
            <h1 id="targets-heading">Targets</h1>
            <p>
              {record.document.policy.targets.length} targets
              <span className="summary-separator">·</span>
              <span className="text-pass">{counts.passed} passed</span>
              <span className="summary-separator">·</span>
              <span className="text-review">
                {counts.failed + counts.operational_error} require review
              </span>
            </p>
          </div>
          <div className="heading-actions">
            <button
              type="button"
              className="secondary-button"
              onClick={onRunAll}
              disabled={runningTarget !== null || enabledTargetCount === 0}
            >
              {runningTarget === "all" ? (
                <LoaderCircle className="spin" aria-hidden="true" />
              ) : (
                <Play aria-hidden="true" />
              )}
              Run assurance
            </button>
            <button type="button" className="primary-button" onClick={onAdd}>
              <Plus aria-hidden="true" />
              Add target
            </button>
          </div>
        </div>
        <div className="target-table-wrap">
          <table className="target-table">
            <thead>
              <tr>
                <th scope="col">Target</th>
                <th scope="col">Profile</th>
                <th scope="col">Score</th>
                <th scope="col">Policy</th>
                <th scope="col">Last checked</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {record.document.policy.targets.map((target) => {
                const targetSummary =
                  record.document.latest_summaries[target.id];
                const isSelected = target.id === selected?.id;
                const isDisabled = disabledTargetIds.has(target.id);
                return (
                  <tr
                    key={target.id}
                    className={isSelected ? "selected" : ""}
                    onClick={() => onSelect(target.id)}
                  >
                    <th scope="row">
                      <button
                        type="button"
                        className="target-cell"
                        onClick={() => onSelect(target.id)}
                      >
                        <strong>{humanize(target.id)}</strong>
                        <span>{target.url}</span>
                      </button>
                    </th>
                    <td>
                      <span className="profile-tag">{target.profile}</span>
                    </td>
                    <td>
                      <ScoreCell summary={isDisabled ? undefined : targetSummary} />
                    </td>
                    <td>≥ {target.minimum_score}</td>
                    <td>{isDisabled ? "Disabled" : relativeTime(targetSummary?.completed_at)}</td>
                    <td>
                      {isDisabled ? (
                        <span className="status-badge status-none">Disabled</span>
                      ) : (
                        <StatusBadge outcome={targetSummary?.outcome} />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
      <TargetInspector
        target={selected}
        summary={summary}
        running={runningTarget === selected?.id}
        disabled={Boolean(selected && disabledTargetIds.has(selected.id))}
        onlyTarget={record.document.policy.targets.length === 1}
        onEdit={() => selected && onEdit(selected)}
        onRemove={() => selected && onRemove(selected.id)}
        onToggleDisabled={() => selected && onToggleDisabled(selected.id)}
        onRun={() => selected && onRun(selected.id)}
      />
    </div>
  );
}

function TargetInspector({
  target,
  summary,
  running,
  disabled,
  onlyTarget,
  onEdit,
  onRemove,
  onToggleDisabled,
  onRun,
}: {
  target?: PolicyTarget;
  summary?: TargetSummary;
  running: boolean;
  disabled: boolean;
  onlyTarget: boolean;
  onEdit: () => void;
  onRemove: () => void;
  onToggleDisabled: () => void;
  onRun: () => void;
}) {
  if (!target) return null;
  const topFindings = summary
    ? Object.entries(summary.findings)
        .sort(([, left], [, right]) => severityRank(right.severity) - severityRank(left.severity))
        .slice(0, 3)
    : [];
  return (
    <aside className="target-inspector" aria-label="Selected target">
      <div className="inspector-heading">
        <div>
          <h2>{humanize(target.id)}</h2>
          <p>{target.url}</p>
        </div>
        <button
          type="button"
          className="primary-button"
          onClick={onRun}
          disabled={running || disabled}
        >
          {running ? (
            <LoaderCircle className="spin" aria-hidden="true" />
          ) : (
            <Play aria-hidden="true" />
          )}
          {disabled ? "Target disabled" : "Run audit"}
        </button>
      </div>
      <dl className="target-facts">
        <div>
          <dt>Profile</dt>
          <dd>{profileLabel(target.profile)}</dd>
        </div>
        <div>
          <dt>Minimum score</dt>
          <dd>{target.minimum_score}</dd>
        </div>
      </dl>
      <div className="score-summary">
        <div>
          <span>Score</span>
          <strong>
            {summary?.score ?? "-"}
            <small> / 100</small>
          </strong>
        </div>
        <div
          className="score-track"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={summary?.score}
          aria-label={
            summary ? `Score ${summary.score} out of 100` : "Not yet assessed"
          }
        >
          <span style={{ width: `${summary?.score ?? 0}%` }} />
        </div>
        <p>Last checked: {relativeTime(summary?.completed_at)}</p>
      </div>
      <section className="inspector-section">
        <h3>Profile decision</h3>
        <div className="decision-row">
          {summary ? (
            <CheckCircle2 aria-hidden="true" className="tone-pass" />
          ) : (
            <Info aria-hidden="true" className="tone-info" />
          )}
          <div>
            <strong>{profileLabel(target.profile)}</strong>
            <span>Explicit policy profile</span>
          </div>
        </div>
      </section>
      <section className="inspector-section">
        <h3>Top findings</h3>
        {topFindings.length ? (
          <div className="compact-findings">
            {topFindings.map(([key, finding]) => (
              <div key={key}>
                <FindingIcon status={finding.status} />
                <strong>{headerLabel(key)}</strong>
                <span className={`status-text tone-${toneFor(finding.status)}`}>
                  {statusLabel(finding.status)}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="empty-copy">No current assessment.</p>
        )}
      </section>
      <section className="inspector-section target-actions">
        <button type="button" onClick={onEdit}>
          Edit target
        </button>
        <button type="button" onClick={onToggleDisabled}>
          {disabled ? "Enable target" : "Disable target"}
        </button>
        <button
          type="button"
          className="danger-link"
          onClick={onRemove}
          disabled={onlyTarget}
          title={onlyTarget ? "A workspace requires at least one target" : undefined}
        >
          <Trash2 aria-hidden="true" />
          Remove
        </button>
      </section>
    </aside>
  );
}

function AssessmentView({
  target,
  summary,
  assessment,
  running,
  disabled,
  onRun,
}: {
  target: PolicyTarget | null;
  summary: TargetSummary | null;
  assessment: AssurancePayload["assessments"][number] | null;
  running: boolean;
  disabled: boolean;
  onRun: () => void;
}) {
  if (!target) return <EmptyView title="No target selected" />;
  const result = assessment?.result;
  return (
    <section className="single-view" aria-labelledby="assessment-heading">
      <div className="page-heading">
        <div>
          <p className="eyebrow">{humanize(target.id)}</p>
          <h1 id="assessment-heading">Assessment</h1>
          <p>{target.url}</p>
        </div>
        <button
          type="button"
          className="primary-button"
          disabled={running || disabled}
          onClick={onRun}
        >
          {running ? (
            <LoaderCircle className="spin" aria-hidden="true" />
          ) : (
            <RotateCcw aria-hidden="true" />
          )}
          {disabled ? "Target disabled" : "Run audit"}
        </button>
      </div>
      <div className="assessment-overview">
        <div>
          <span>Score</span>
          <strong>{result?.score ?? summary?.score ?? "-"}</strong>
        </div>
        <div>
          <span>Profile</span>
          <strong>{profileLabel(target.profile)}</strong>
        </div>
        <div>
          <span>Policy</span>
          <strong>≥ {target.minimum_score}</strong>
        </div>
        <div>
          <span>Status</span>
          <StatusBadge outcome={summary?.outcome} />
        </div>
      </div>
      {result?.error ? (
        <div className="empty-panel" role="alert">
          <XCircle aria-hidden="true" />
          <h2>Audit could not complete</h2>
          <p>{result.error}</p>
        </div>
      ) : result ? (
        <>
          <section className="profile-evidence-section">
            <h2>Profile decision</h2>
            <ul>
              {result.profile_evidence.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
          <div className="finding-stack">
            {result.findings.map((finding) => (
              <FindingDisclosure key={finding.key} finding={finding} />
            ))}
          </div>
        </>
      ) : (
        <EmptyView title="Run this target to inspect current response evidence" />
      )}
    </section>
  );
}

function FindingDisclosure({ finding }: { finding: DetailedFinding }) {
  return (
    <details className={`finding-row finding-${toneFor(finding.status)}`}>
      <summary>
        <FindingIcon status={finding.status} />
        <span>
          <strong>{finding.name}</strong>
          <small>{finding.applicability.replaceAll("_", " ")}</small>
        </span>
        <span className="finding-points">
          {finding.max_points
            ? `${finding.points}/${finding.max_points}`
            : "Not scored"}
        </span>
        <span className={`status-text tone-${toneFor(finding.status)}`}>
          {statusLabel(finding.status)}
        </span>
        <ChevronRight className="disclosure-chevron" aria-hidden="true" />
      </summary>
      <div className="finding-detail">
        <section>
          <h3>Evidence</h3>
          <pre>{finding.value ?? "Header not observed."}</pre>
          <p>{finding.note}</p>
        </section>
        <section>
          <h3>Recommendation</h3>
          <p>{finding.recommendation}</p>
          <h3>Scoring rationale</h3>
          <p>{finding.scoring_rationale}</p>
        </section>
        <section>
          <h3>Framework evidence</h3>
          {finding.evidence_mappings.length ? (
            <ul className="mapping-list">
              {finding.evidence_mappings.map((mapping) => (
                <li key={`${mapping.framework_id}-${mapping.requirement}`}>
                  <strong>
                    {mapping.framework} {mapping.framework_version}
                  </strong>
                  <span>
                    {mapping.requirement} · {mapping.evidence_family} ·{" "}
                    {mapping.relationship}
                  </span>
                  <small>Confidence: {mapping.confidence}</small>
                  <small>{mapping.limitations}</small>
                </li>
              ))}
            </ul>
          ) : (
            <p>No direct framework relationship claimed.</p>
          )}
        </section>
      </div>
    </details>
  );
}

function AssuranceView({
  record,
  run,
  running,
  onRun,
  baselineBusy,
  onCreateBaseline,
  onExport,
}: {
  record: WorkspaceRecord;
  run: AssurancePayload | null;
  running: boolean;
  onRun: () => void;
  baselineBusy: boolean;
  onCreateBaseline: () => void;
  onExport: (reportFormat: ReportFormat) => void;
}) {
  const latest = Object.values(record.document.latest_summaries);
  const passed = latest.filter((item) => item.outcome === "passed").length;
  return (
    <section className="single-view" aria-labelledby="assurance-heading">
      <div className="page-heading">
        <div>
          <h1 id="assurance-heading">Assurance</h1>
          <p>{record.document.policy.name}</p>
        </div>
        <div className="heading-actions">
          <ReportExportControl disabled={!run || running || baselineBusy} onExport={onExport} />
          <button
            type="button"
            className="secondary-button"
            onClick={onCreateBaseline}
            disabled={running || baselineBusy}
          >
            {baselineBusy ? (
              <LoaderCircle className="spin" aria-hidden="true" />
            ) : (
              <ClipboardCheck aria-hidden="true" />
            )}
            Review baseline
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={onRun}
            disabled={running || baselineBusy}
          >
            {running ? (
              <LoaderCircle className="spin" aria-hidden="true" />
            ) : (
              <Play aria-hidden="true" />
            )}
            Run assurance
          </button>
        </div>
      </div>
      <div className="assurance-strip">
        <div>
          <span>Targets</span>
          <strong>{record.document.policy.targets.length}</strong>
        </div>
        <div>
          <span>Passed</span>
          <strong>{passed}</strong>
        </div>
        <div>
          <span>Approved baseline</span>
          <strong>{record.document.approved_baseline ? "Present" : "None"}</strong>
        </div>
        <div>
          <span>Current outcome</span>
          {run ? <StatusBadge outcome={run.outcome} /> : <span>Not run</span>}
        </div>
      </div>
      {run ? (
        <div className="diagnostic-layout">
          <DiagnosticSection
            title="Policy violations"
            items={run.policy_violations}
          />
          <DiagnosticSection title="Regressions" items={run.regressions} />
          <DiagnosticSection
            title="Operational errors"
            items={run.operational_errors.map((message) => ({
              target_id: "assurance",
              code: "operational.audit_error",
              severity: "high",
              control_key: null,
              message,
            }))}
          />
        </div>
      ) : (
        <EmptyView title="Run assurance to evaluate the current policy" />
      )}
    </section>
  );
}

function ReportExportControl({
  disabled,
  onExport,
}: {
  disabled: boolean;
  onExport: (format: ReportFormat) => void;
}) {
  const [format, setFormat] = useState<ReportFormat>("html");
  return (
    <div className="report-export-control">
      <label>
        <span className="visually-hidden">Report format</span>
        <select
          aria-label="Report format"
          value={format}
          disabled={disabled}
          onChange={(event) =>
            setFormat(event.target.value as ReportFormat)
          }
        >
          <option value="html">HTML report</option>
          <option value="markdown">Markdown</option>
          <option value="json">JSON evidence</option>
          <option value="sarif">SARIF 2.1.0</option>
          <option value="junit">JUnit XML</option>
        </select>
      </label>
      <button
        type="button"
        className="icon-button"
        aria-label="Download timestamped current report"
        title="Download timestamped report"
        disabled={disabled}
        onClick={() => onExport(format)}
      >
        <Download aria-hidden="true" />
      </button>
    </div>
  );
}

function AuditHistoryView({ history }: { history: AuditHistoryEntry[] }) {
  return (
    <section className="single-view" aria-labelledby="history-heading">
      <div className="page-heading">
        <div>
          <h1 id="history-heading">Audit history</h1>
          <p>Last {history.length} local audit sessions</p>
        </div>
      </div>
      {history.length ? (
        <div className="audit-history-table-wrap">
          <table className="audit-history-table">
            <thead>
              <tr>
                <th scope="col">Completed</th>
                <th scope="col">Scope</th>
                <th scope="col">Targets</th>
                <th scope="col">Score</th>
                <th scope="col">Outcome</th>
                <th scope="col">Audit ID</th>
              </tr>
            </thead>
            <tbody>
              {history.map((entry) => (
                <tr key={entry.audit_id}>
                  <th scope="row">{displayTimestamp(entry.completed_at)}</th>
                  <td>{entry.run_kind === "target" ? "Target audit" : "Assurance"}</td>
                  <td>
                    {entry.assessments.map((assessment) => (
                      <span className="history-target" key={assessment.target_id}>
                        {humanize(assessment.target_id)}
                      </span>
                    ))}
                  </td>
                  <td>
                    {entry.assessments.length === 1
                      ? `${entry.assessments[0].score} / 100`
                      : "Multiple targets"}
                  </td>
                  <td><StatusBadge outcome={entry.outcome} /></td>
                  <td><code>{entry.audit_id.slice(0, 8)}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyView title="Run an audit to start a local session history" />
      )}
    </section>
  );
}

function DiagnosticSection({
  title,
  items,
}: {
  title: string;
  items: AssurancePayload["policy_violations"];
}) {
  return (
    <section className="diagnostic-section">
      <div className="section-title">
        <h2>{title}</h2>
        <span>{items.length}</span>
      </div>
      {items.length ? (
        <ul>
          {items.map((item, index) => (
            <li key={`${item.target_id}-${item.code}-${index}`}>
              <AlertTriangle aria-hidden="true" />
              <div>
                <strong>{humanize(item.target_id)}</strong>
                <span>{item.message}</span>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="empty-copy">No current items.</p>
      )}
    </section>
  );
}

function EvidenceView({ run }: { run: AssurancePayload | null }) {
  const mappings = run
    ? run.assessments.flatMap((assessment) =>
        assessment.result.findings.flatMap((finding) =>
          finding.evidence_mappings.map((mapping) => ({
            ...mapping,
            finding: finding.name,
          })),
        ),
      )
    : [];
  const unique = Array.from(
    new Map(
      mappings.map((mapping) => [
        `${mapping.framework_id}-${mapping.requirement}-${mapping.finding}`,
        mapping,
      ]),
    ).values(),
  );
  return (
    <section className="single-view" aria-labelledby="evidence-heading">
      <div className="page-heading">
        <div>
          <h1 id="evidence-heading">Evidence</h1>
          <p>Framework relationships for the current in-memory run</p>
        </div>
      </div>
      {unique.length ? (
        <div className="evidence-table-wrap">
          <table className="evidence-table">
            <thead>
              <tr>
                <th scope="col">Control</th>
                <th scope="col">Framework</th>
                <th scope="col">Reference</th>
                <th scope="col">Relationship</th>
                <th scope="col">Limitation</th>
              </tr>
            </thead>
            <tbody>
              {unique.map((mapping) => (
                <tr key={`${mapping.framework_id}-${mapping.requirement}-${mapping.finding}`}>
                  <th scope="row">{mapping.finding}</th>
                  <td>{mapping.framework} {mapping.framework_version}</td>
                  <td>{mapping.requirement}</td>
                  <td>
                    <span className="neutral-tag">
                      {mapping.evidence_family}
                    </span>
                    <small className="confidence-label">
                      {mapping.confidence} confidence
                    </small>
                  </td>
                  <td>{mapping.limitations}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyView title="Run an assessment to inspect framework evidence" />
      )}
    </section>
  );
}

function WorkspaceView({
  record,
  bootstrap,
  onExport,
  onImport,
  onDelete,
}: {
  record: WorkspaceRecord;
  bootstrap: Bootstrap;
  onExport: () => void;
  onImport: () => void;
  onDelete: () => void;
}) {
  return (
    <section className="single-view workspace-view" aria-labelledby="workspace-heading">
      <div className="page-heading">
        <div>
          <h1 id="workspace-heading">Workspace</h1>
          <p>{record.document.name}</p>
        </div>
      </div>
      <dl className="workspace-metadata">
        <div>
          <dt>Workspace ID</dt>
          <dd>{record.document.workspace_id}</dd>
        </div>
        <div>
          <dt>Revision</dt>
          <dd>{record.revision}</dd>
        </div>
        <div>
          <dt>Workspace schema</dt>
          <dd>{bootstrap.workspace_schema_version}</dd>
        </div>
        <div>
          <dt>Evidence mapping set</dt>
          <dd>{bootstrap.mapping_set_version}</dd>
        </div>
        <div>
          <dt>Target scope</dt>
          <dd>
            {bootstrap.allow_private_targets
              ? "Private targets enabled for this session"
              : "Public addresses only"}
          </dd>
        </div>
        <div>
          <dt>Detailed response values</dt>
          <dd>Current run memory and explicit reports only</dd>
        </div>
        <div>
          <dt>Audit session history</dt>
          <dd>Up to 50 local session summaries</dd>
        </div>
      </dl>
      <div className="workspace-actions-band">
        <button type="button" className="secondary-button" onClick={onImport}>
          <Upload aria-hidden="true" />
          Import JSON
        </button>
        <button type="button" className="secondary-button" onClick={onExport}>
          <Download aria-hidden="true" />
          Export JSON
        </button>
        <button type="button" className="danger-button" onClick={onDelete}>
          <Trash2 aria-hidden="true" />
          Delete workspace
        </button>
      </div>
    </section>
  );
}

function BaselineReviewDialog({
  response,
  approving,
  onCancel,
  onApprove,
}: {
  response: BaselineCandidateResponse;
  approving: boolean;
  onCancel: () => void;
  onApprove: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const labelId = useMemo(() => crypto.randomUUID(), []);
  return (
    <div className="dialog-backdrop">
      <section
        className="dialog baseline-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelId}
      >
        <div className="dialog-heading">
          <div>
            <p className="eyebrow">Explicit approval required</p>
            <h2 id={labelId}>Review baseline candidate</h2>
          </div>
          <button
            type="button"
            className="icon-button"
            aria-label="Close baseline review"
            title="Close"
            onClick={onCancel}
            disabled={approving}
          >
            <X aria-hidden="true" />
          </button>
        </div>
        <div className="baseline-review-summary">
          <div>
            <span>Assurance outcome</span>
            <StatusBadge outcome={response.run.outcome} />
          </div>
          <div>
            <span>Compared with</span>
            <strong>
              {response.diff.previous_present
                ? "Approved baseline"
                : "No previous baseline"}
            </strong>
          </div>
          <div>
            <span>Changed targets</span>
            <strong>{response.diff.change_count}</strong>
          </div>
        </div>
        <div className="baseline-diff-list" aria-label="Baseline changes">
          {response.diff.targets.length ? (
            response.diff.targets.map((item) => (
              <section key={item.target_id}>
                <div>
                  <strong>{humanize(item.target_id)}</strong>
                  <span className="neutral-tag">{item.change}</span>
                </div>
                <p>
                  Score{" "}
                  <strong>
                    {item.previous_score ?? "new"} →{" "}
                    {item.candidate_score ?? "removed"}
                  </strong>
                </p>
                <p>
                  {item.changed_controls.length
                    ? `${item.changed_controls.length} control states changed`
                    : "No control-state changes"}
                </p>
              </section>
            ))
          ) : (
            <p className="empty-copy">
              The candidate matches the currently approved baseline.
            </p>
          )}
        </div>
        <label className="approval-check">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          <span>
            I reviewed this candidate and understand that future runs will use
            it for regression detection.
          </span>
        </label>
        <div className="dialog-actions">
          <button type="button" onClick={onCancel} disabled={approving}>
            Cancel
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={onApprove}
            disabled={!confirmed || approving}
          >
            {approving && (
              <LoaderCircle className="spin" aria-hidden="true" />
            )}
            Approve baseline
          </button>
        </div>
      </section>
    </div>
  );
}

function ImportPreviewDialog({
  preview,
  onCancel,
  onCommit,
}: {
  preview: WorkspaceImportPreview;
  onCancel: () => void;
  onCommit: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const labelId = useMemo(() => crypto.randomUUID(), []);
  const existingWorkspace = preview.existing_workspace;
  const replacing = existingWorkspace !== null;
  return (
    <div className="dialog-backdrop">
      <section
        className="dialog baseline-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelId}
      >
        <div className="dialog-heading">
          <div>
            <p className="eyebrow">Explicit import approval required</p>
            <h2 id={labelId}>Review workspace import</h2>
          </div>
          <button
            type="button"
            className="icon-button"
            aria-label="Close import review"
            title="Close"
            onClick={onCancel}
          >
            <X aria-hidden="true" />
          </button>
        </div>
        <div className="baseline-review-summary">
          <div>
            <span>Workspace</span>
            <strong>{preview.document.name}</strong>
          </div>
          <div>
            <span>Authorized targets</span>
            <strong>{preview.target_count}</strong>
          </div>
          <div>
            <span>Local state</span>
            <strong>{replacing ? "Will replace matching workspace" : "Will create workspace"}</strong>
          </div>
        </div>
        <p className="dialog-copy">
          Imported targets are stored only. No audit runs until you explicitly select Run.
          {preview.applied_migrations.length
            ? ` Applied migrations: ${preview.applied_migrations.join(", ")}.`
            : ""}
        </p>
        {existingWorkspace && (
          <p className="dialog-copy">
            This will replace the local workspace named {existingWorkspace.name}{" "}
            at revision {existingWorkspace.revision}.
          </p>
        )}
        <label className="approval-check">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          <span>I reviewed this workspace and approve this import.</span>
        </label>
        <div className="dialog-actions">
          <button type="button" onClick={onCancel}>Cancel</button>
          <button
            type="button"
            className="primary-button"
            onClick={onCommit}
            disabled={!confirmed}
          >
            {replacing ? "Replace workspace" : "Import workspace"}
          </button>
        </div>
      </section>
    </div>
  );
}

function TargetDialog({
  title,
  initial,
  requireWorkspaceName = false,
  onCancel,
  onSubmit,
}: {
  title: string;
  initial: TargetDraft;
  requireWorkspaceName?: boolean;
  onCancel?: () => void;
  onSubmit: (draft: TargetDraft, workspaceName: string) => void;
}) {
  const [draft, setDraft] = useState<TargetDraft>(initial);
  const [workspaceName, setWorkspaceName] = useState("Production Web Estate");
  const labelId = useMemo(() => crypto.randomUUID(), []);
  function submit(event: FormEvent) {
    event.preventDefault();
    onSubmit(draft, workspaceName.trim());
  }
  return (
    <div className="dialog-backdrop">
      <section
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelId}
      >
        <div className="dialog-heading">
          <h2 id={labelId}>{title}</h2>
          {onCancel && (
            <button
              type="button"
              className="icon-button"
              aria-label="Close dialog"
              title="Close"
              onClick={onCancel}
            >
              <X aria-hidden="true" />
            </button>
          )}
        </div>
        <form onSubmit={submit}>
          {requireWorkspaceName && (
            <label>
              Workspace name
              <input
                required
                maxLength={100}
                value={workspaceName}
                onChange={(event) => setWorkspaceName(event.target.value)}
              />
            </label>
          )}
          <label>
            Target label
            <input
              required
              maxLength={80}
              autoFocus={!requireWorkspaceName}
              value={draft.label}
              placeholder="Customer Portal"
              onChange={(event) =>
                setDraft({ ...draft, label: event.target.value })
              }
            />
          </label>
          <label>
            Authorized URL
            <input
              required
              type="url"
              value={draft.url}
              onChange={(event) =>
                setDraft({ ...draft, url: event.target.value })
              }
            />
          </label>
          <div className="form-grid">
            <label>
              Response profile
              <select
                value={draft.profile}
                onChange={(event) =>
                  setDraft({
                    ...draft,
                    profile: event.target.value as Profile,
                  })
                }
              >
                <option value="app">Application</option>
                <option value="brochure">Public brochure</option>
                <option value="api">API response</option>
              </select>
            </label>
            <label>
              Minimum score
              <input
                type="number"
                min={0}
                max={100}
                value={draft.minimumScore}
                onChange={(event) =>
                  setDraft({
                    ...draft,
                    minimumScore: Number(event.target.value),
                  })
                }
              />
            </label>
            <label>
              Reporting readiness
              <select
                value={draft.reporting}
                onChange={(event) =>
                  setDraft({
                    ...draft,
                    reporting: event.target
                      .value as PolicyTarget["reporting_readiness"],
                  })
                }
              >
                <option value="observe">Observe</option>
                <option value="recommended">Recommended</option>
                <option value="required">Required</option>
                <option value="not_applicable">Not applicable</option>
              </select>
            </label>
            <label>
              Cross-origin isolation
              <select
                value={draft.isolation}
                onChange={(event) =>
                  setDraft({
                    ...draft,
                    isolation: event.target
                      .value as PolicyTarget["cross_origin_isolation"],
                  })
                }
              >
                <option value="observe">Observe</option>
                <option value="recommended">Recommended</option>
                <option value="required">Required</option>
                <option value="not_applicable">Not applicable</option>
              </select>
            </label>
          </div>
          <div className="dialog-actions">
            {onCancel && (
              <button type="button" onClick={onCancel}>
                Cancel
              </button>
            )}
            <button type="submit" className="primary-button">
              {requireWorkspaceName ? "Create workspace" : "Save target"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function ScoreCell({ summary }: { summary?: TargetSummary }) {
  if (!summary) return <span className="muted-value">Not run</span>;
  return (
    <div className="table-score">
      <span>{summary.score}<small>/100</small></span>
      <i><span style={{ width: `${summary.score}%` }} /></i>
    </div>
  );
}

function StatusBadge({ outcome }: { outcome?: string }) {
  if (!outcome) return <span className="status-badge status-none">Not run</span>;
  const tone =
    outcome === "passed"
      ? "pass"
      : outcome === "operational_error"
        ? "error"
        : "review";
  return (
    <span className={`status-badge status-${tone}`}>
      {outcome === "operational_error" ? "Error" : humanize(outcome)}
    </span>
  );
}

function FindingIcon({ status }: { status: string }) {
  const tone = toneFor(status);
  if (tone === "pass") {
    return <CheckCircle2 aria-hidden="true" className="tone-pass" />;
  }
  if (tone === "error") {
    return <XCircle aria-hidden="true" className="tone-error" />;
  }
  if (tone === "review") {
    return <AlertTriangle aria-hidden="true" className="tone-review" />;
  }
  return <Info aria-hidden="true" className="tone-info" />;
}

function EmptyView({ title }: { title: string }) {
  return (
    <div className="empty-panel">
      <FileJson aria-hidden="true" />
      <h2>{title}</h2>
    </div>
  );
}

function FatalState({
  title,
  message,
}: {
  title: string;
  message: string;
}) {
  return (
    <main className="fatal-state">
      <ShieldCheck aria-hidden="true" />
      <h1>{title}</h1>
      <p>{message}</p>
    </main>
  );
}

function newWorkspaceDocument(
  workspaceName: string,
  draft: TargetDraft,
  bootstrap: Bootstrap,
): WorkspaceDocument {
  const timestamp = now();
  const target = targetFromDraft(draft, []);
  return {
    schema_version: bootstrap.workspace_schema_version,
    workspace_id: crypto.randomUUID(),
    name: workspaceName,
      policy: {
      schema_version: "1.0",
        methodology_version: bootstrap.methodology_version,
      name: `${slug(workspaceName)}-assurance`,
      defaults: {
        fail_on_severity: ["high"],
        allow_auto_profile: false,
      },
      targets: [target],
      },
      disabled_target_ids: [],
    approved_baseline: null,
    latest_summaries: {},
    audit_history: [],
    created_at: timestamp,
    updated_at: timestamp,
  };
}

function targetFromDraft(
  draft: TargetDraft,
  existing: PolicyTarget[],
  preservedId?: string,
): PolicyTarget {
  const proposed = preservedId ?? uniqueTargetId(slug(draft.label), existing);
  return {
    id: proposed,
    url: draft.url.trim(),
    profile: draft.profile,
    minimum_score: draft.minimumScore,
    maximum_score_drop: 0,
    required_controls:
      draft.profile === "api"
        ? ["strict-transport-security", "x-content-type-options"]
        : ["strict-transport-security", "content-security-policy"],
    reporting_readiness: draft.reporting,
    cross_origin_isolation: draft.isolation,
  };
}

function draftFromTarget(target: PolicyTarget): TargetDraft {
  return {
    label: humanize(target.id),
    url: target.url,
    profile: target.profile,
    minimumScore: target.minimum_score,
    reporting: target.reporting_readiness,
    isolation: target.cross_origin_isolation,
  };
}

function uniqueTargetId(candidate: string, existing: PolicyTarget[]): string {
  const base = candidate || "target";
  const used = new Set(existing.map((target) => target.id));
  if (!used.has(base)) return base;
  let suffix = 2;
  while (used.has(`${base}-${suffix}`)) suffix += 1;
  return `${base}-${suffix}`;
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function humanize(value: string): string {
  return value
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function headerLabel(value: string): string {
  return value
    .split("-")
    .map((part) => {
      const aliases: Record<string, string> = {
        csp: "CSP",
        hsts: "HSTS",
        x: "X",
      };
      return aliases[part] ?? `${part.charAt(0).toUpperCase()}${part.slice(1)}`;
    })
    .join("-");
}

function profileLabel(profile: Profile): string {
  return {
    app: "Application (app)",
    api: "API response (api)",
    brochure: "Public brochure (brochure)",
  }[profile];
}

function toneFor(status: string): "pass" | "review" | "error" | "info" {
  if (["pass", "observed"].includes(status)) return "pass";
  if (["warning", "review", "missing"].includes(status)) return "review";
  if (status === "error") return "error";
  return "info";
}

function statusLabel(status: string): string {
  return humanize(status === "not_applicable" ? "not applicable" : status);
}

function severityRank(severity: string): number {
  return { high: 4, medium: 3, low: 2, info: 1 }[severity] ?? 0;
}

function relativeTime(value?: string): string {
  if (!value) return "Not run";
  const difference = Date.now() - new Date(value).getTime();
  const minutes = Math.max(0, Math.round(difference / 60_000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function displayTimestamp(value: string): string {
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(timestamp);
}

function now(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00");
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "The workspace could not complete the request.";
}
