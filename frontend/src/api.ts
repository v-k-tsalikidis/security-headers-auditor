import type {
  BaselineApprovalResponse,
  BaselineCandidate,
  BaselineCandidateResponse,
  Bootstrap,
  ReportExport,
  ReportFormat,
  WorkspaceImportPreview,
  RunResponse,
  WorkspaceDocument,
  WorkspaceRecord,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

export class WorkspaceApi {
  constructor(private readonly token: string) {}

  bootstrap(): Promise<Bootstrap> {
    return this.request("/api/v1/bootstrap");
  }

  getWorkspace(workspaceId: string): Promise<WorkspaceRecord> {
    return this.request(`/api/v1/workspaces/${workspaceId}`);
  }

  createWorkspace(document: WorkspaceDocument): Promise<WorkspaceRecord> {
    return this.request("/api/v1/workspaces", {
      method: "POST",
      body: JSON.stringify(document),
    });
  }

  previewWorkspaceImport(
    document: WorkspaceDocument,
  ): Promise<WorkspaceImportPreview> {
    return this.request("/api/v1/workspace-imports/preview", {
      method: "POST",
      body: JSON.stringify({ document }),
    });
  }

  commitWorkspaceImport(
    preview: WorkspaceImportPreview,
  ): Promise<WorkspaceRecord> {
    return this.request("/api/v1/workspace-imports/commit", {
      method: "POST",
      body: JSON.stringify({
        document: preview.document,
        expected_revision: preview.expected_revision,
      }),
    });
  }

  saveWorkspace(record: WorkspaceRecord): Promise<WorkspaceRecord> {
    return this.request(
      `/api/v1/workspaces/${record.document.workspace_id}`,
      {
        method: "PUT",
        body: JSON.stringify({
          revision: record.revision,
          document: record.document,
        }),
      },
    );
  }

  runTarget(
    record: WorkspaceRecord,
    targetId?: string,
  ): Promise<RunResponse> {
    return this.request(
      `/api/v1/workspaces/${record.document.workspace_id}/run`,
      {
        method: "POST",
        body: JSON.stringify({
          revision: record.revision,
          ...(targetId ? { target_id: targetId } : {}),
        }),
      },
    );
  }

  createBaselineCandidate(
    record: WorkspaceRecord,
  ): Promise<BaselineCandidateResponse> {
    return this.request(
      `/api/v1/workspaces/${record.document.workspace_id}/baseline-candidate`,
      {
        method: "POST",
        body: JSON.stringify({ revision: record.revision }),
      },
    );
  }

  approveBaseline(
    record: WorkspaceRecord,
    candidate: BaselineCandidate,
  ): Promise<BaselineApprovalResponse> {
    return this.request(
      `/api/v1/workspaces/${record.document.workspace_id}/approved-baseline`,
      {
        method: "PUT",
        body: JSON.stringify({
          revision: record.revision,
          candidate,
        }),
      },
    );
  }

  exportCurrentReport(
    workspaceId: string,
    reportFormat: ReportFormat,
  ): Promise<ReportExport> {
    return this.request(
      `/api/v1/workspaces/${workspaceId}/reports/${reportFormat}`,
    );
  }

  deleteWorkspace(record: WorkspaceRecord): Promise<{ deleted: string }> {
    return this.request(
      `/api/v1/workspaces/${record.document.workspace_id}`,
      {
        method: "DELETE",
        body: JSON.stringify({ revision: record.revision }),
      },
    );
  }

  private async request<T>(
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const response = await fetch(path, {
      ...init,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...init.headers,
      },
      cache: "no-store",
      credentials: "same-origin",
    });
    const payload = (await response.json()) as T & { error?: string };
    if (!response.ok) {
      throw new ApiError(
        payload.error ?? `Workspace request failed with ${response.status}.`,
        response.status,
      );
    }
    return payload;
  }
}

export function consumeSessionToken(): string | null {
  const parameters = new URLSearchParams(window.location.hash.slice(1));
  const token = parameters.get("token");
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  return token;
}
