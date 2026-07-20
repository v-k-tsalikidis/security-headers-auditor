import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import type {
  AssurancePayload,
  AuditHistoryEntry,
  BaselineCandidate,
  Bootstrap,
  WorkspaceRecord,
} from "./types";

const workspaceId = "5f0f84f3-1775-4de5-b2c8-3768c9d03f45";

function record(
  revision = 0,
  baseline: BaselineCandidate | null = null,
  auditHistory: AuditHistoryEntry[] = [],
): WorkspaceRecord {
  return {
    revision,
    document: {
      schema_version: "1.2",
      workspace_id: workspaceId,
      name: "Production Web Estate",
      policy: {
        schema_version: "1.1",
        methodology_version: "0.5.0",
        name: "production-assurance",
        defaults: {
          fail_on_severity: ["high"],
          allow_auto_profile: false,
        },
        targets: [
          {
            id: "customer-portal",
            url: "https://example.test/",
            profile: "app",
            minimum_score: 75,
            maximum_score_drop: 0,
            required_controls: [
              "strict-transport-security",
              "content-security-policy",
            ],
            reporting_readiness: "observe",
            cross_origin_isolation: "not_applicable",
          },
        ],
      },
      disabled_target_ids: [],
      approved_baseline: baseline,
      latest_summaries: {},
      audit_history: auditHistory,
      created_at: "2026-07-19T10:00:00+00:00",
      updated_at: "2026-07-19T10:00:00+00:00",
    },
  };
}

const bootstrap: Bootstrap = {
  tool_version: "0.9.0",
  methodology_version: "0.5.0",
  workspace_schema_version: "1.2",
  mapping_set_version: "2026.07.2",
  allow_private_targets: false,
  workspaces: [
    {
      workspace_id: workspaceId,
      revision: 0,
      schema_version: "1.2",
      name: "Production Web Estate",
      updated_at: "2026-07-19T10:00:00+00:00",
    },
  ],
};

const run: AssurancePayload = {
  methodology_version: "0.5.0",
  mapping_set_version: "2026.07.2",
  policy_name: "production-assurance",
  policy_schema_version: "1.0",
  baseline_schema_version: null,
  outcome: "passed",
  exit_code: 0,
  assessments: [],
  policy_violations: [],
  regressions: [],
  operational_errors: [],
};

const candidate: BaselineCandidate = {
  schema_version: "1.0",
  methodology_version: "0.5.0",
  mapping_set_version: "2026.07.2",
  policy_name: "production-assurance",
  targets: {
    "customer-portal": {
      target: "https://example.test/",
      selected_profile: "app",
      score: 96,
      findings: {},
    },
  },
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("workspace baseline approval", () => {
  it("requires explicit review before persisting a candidate", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      let payload: unknown;
      if (path === "/api/v1/bootstrap") {
        payload = bootstrap;
      } else if (path === `/api/v1/workspaces/${workspaceId}`) {
        payload = record();
      } else if (path.endsWith("/baseline-candidate")) {
        payload = {
          record: record(1),
          run,
          candidate,
          diff: {
            previous_present: false,
            change_count: 1,
            targets: [
              {
                target_id: "customer-portal",
                change: "added",
                previous_score: null,
                candidate_score: 96,
                changed_controls: [],
              },
            ],
          },
        };
      } else if (path.endsWith("/approved-baseline")) {
        payload = {
          record: record(2, candidate),
          approved: candidate,
        };
      } else {
        return new Response(JSON.stringify({ error: "Not found" }), {
          status: 404,
        });
      }
      expect(init?.headers).toEqual(
        expect.objectContaining({ Authorization: "Bearer test-token" }),
      );
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App sessionToken="test-token" />);
    await screen.findByRole("heading", { name: "Targets" });
    await user.click(screen.getByRole("button", { name: "Assurance" }));
    await user.click(screen.getByRole("button", { name: "Review baseline" }));

    const approve = await screen.findByRole("button", {
      name: "Approve baseline",
    });
    expect(approve).toBeDisabled();
    await user.click(
      screen.getByRole("checkbox", {
        name: /I reviewed this candidate/,
      }),
    );
    expect(approve).toBeEnabled();
    await user.click(approve);

    await waitFor(() =>
      expect(
        screen.getByText("Present"),
      ).toBeInTheDocument(),
    );
    expect(
      fetchMock.mock.calls.some(([path]) =>
        String(path).endsWith("/approved-baseline"),
      ),
    ).toBe(true);
  });

  it("previews a first workspace import and does not run it automatically", async () => {
    let bootstrapRequests = 0;
    const imported = record();
    const emptyBootstrap: Bootstrap = { ...bootstrap, workspaces: [] };
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      let payload: unknown;
      if (path === "/api/v1/bootstrap") {
        bootstrapRequests += 1;
        payload = bootstrapRequests === 1 ? emptyBootstrap : bootstrap;
      } else if (path === "/api/v1/workspace-imports/preview") {
        payload = {
          document: imported.document,
          applied_migrations: [],
          target_count: 1,
          existing_workspace: null,
          expected_revision: null,
        };
      } else if (path === "/api/v1/workspace-imports/commit") {
        payload = imported;
      } else {
        return new Response(JSON.stringify({ error: "Not found" }), {
          status: 404,
        });
      }
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App sessionToken="test-token" />);
    await screen.findByRole("heading", { name: "Create workspace" });
    await user.click(screen.getAllByRole("button", { name: "Import" })[0]);
    const input = document.querySelector<HTMLInputElement>('input[type="file"]');
    expect(input).not.toBeNull();
    const file = new File([JSON.stringify(imported.document)], "workspace.json", {
      type: "application/json",
    });
    Object.defineProperty(file, "text", {
      value: async () => JSON.stringify(imported.document),
    });
    await user.upload(input!, file);

    await screen.findByRole("heading", { name: "Review workspace import" });
    const commit = screen.getByRole("button", { name: "Import workspace" });
    expect(commit).toBeDisabled();
    await user.click(
      screen.getByRole("checkbox", {
        name: "I reviewed this workspace and approve this import.",
      }),
    );
    await user.click(commit);

    await waitFor(() =>
      expect(
        screen.queryByRole("heading", { name: "Review workspace import" }),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getByText("Production Web Estate")).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some(([path]) => String(path).endsWith("/run")),
    ).toBe(false);
  });
});

describe("workspace audit history", () => {
  it("shows each persisted audit session separately", async () => {
    const history: AuditHistoryEntry[] = [
      {
        audit_id: "c8a07661-4a6a-4bff-9d8a-1b0168e09d72",
        completed_at: "2026-07-20T10:30:00+00:00",
        run_kind: "target",
        policy_name: "production-assurance",
        outcome: "passed",
        exit_code: 0,
        assessments: [
          {
            target_id: "customer-portal",
            target: "https://example.test/",
            selected_profile: "app",
            score: 96,
            outcome: "passed",
            exit_code: 0,
          },
        ],
      },
    ];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      const payload = path === "/api/v1/bootstrap" ? bootstrap : record(0, null, history);
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App sessionToken="test-token" />);
    await screen.findByRole("heading", { name: "Targets" });
    await user.click(screen.getByRole("button", { name: "History" }));

    await screen.findByRole("heading", { name: "Audit history" });
    expect(screen.getByText("Customer Portal")).toBeInTheDocument();
    expect(screen.getByText("96 / 100")).toBeInTheDocument();
    expect(screen.getByText("c8a07661")).toBeInTheDocument();
  });
});
