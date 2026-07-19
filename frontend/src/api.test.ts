import { afterEach, describe, expect, it, vi } from "vitest";

import { WorkspaceApi, consumeSessionToken } from "./api";
import type { WorkspaceDocument } from "./types";

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

describe("consumeSessionToken", () => {
  it("returns the fragment token and removes it from browser history", () => {
    window.history.replaceState(
      null,
      "",
      "/workspace?view=targets#token=session-secret",
    );

    expect(consumeSessionToken()).toBe("session-secret");
    expect(window.location.hash).toBe("");
    expect(window.location.pathname).toBe("/workspace");
    expect(window.location.search).toBe("?view=targets");
  });
});

describe("WorkspaceApi", () => {
  it("sends the memory token and same-origin request defaults", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ workspaces: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new WorkspaceApi("session-secret").bootstrap();

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/bootstrap",
      expect.objectContaining({
        cache: "no-store",
        credentials: "same-origin",
        headers: expect.objectContaining({
          Authorization: "Bearer session-secret",
        }),
      }),
    );
  });

  it("surfaces structured API conflicts", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: "Workspace revision conflict.",
            status: 409,
          }),
          {
            status: 409,
            headers: { "Content-Type": "application/json" },
          },
        ),
      ),
    );

    await expect(
      new WorkspaceApi("session-secret").bootstrap(),
    ).rejects.toEqual(
      expect.objectContaining({
        message: "Workspace revision conflict.",
        status: 409,
      }),
    );
  });

  it("uses the explicit preview endpoint before committing an import", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const document = {} as WorkspaceDocument;

    await new WorkspaceApi("session-secret").previewWorkspaceImport(document);

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/workspace-imports/preview",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ document }),
      }),
    );
  });
});
