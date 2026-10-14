import { afterEach, describe, expect, it, vi } from "vitest";

import { api, ApiError, setCsrfToken } from "./api";

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn().mockImplementation(async () =>
    new Response(body === undefined ? null : JSON.stringify(body), { status }),
  );
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(null);
});

describe("api client", () => {
  it("builds query strings, skipping empty values and repeating arrays", async () => {
    const fetch = mockFetch(200, { ok: true });
    await api.get("/incidents", { scope: "demo", status: ["new", "investigating"], q: "", x: undefined });
    expect(fetch.mock.calls[0][0]).toBe("/api/v1/incidents?scope=demo&status=new&status=investigating");
  });

  it("sends the CSRF token only on state-changing requests", async () => {
    const fetch = mockFetch(200, {});
    setCsrfToken("csrf-123");
    await api.get("/auth/me");
    await api.post("/agents", { name: "a" });
    const getHeaders = fetch.mock.calls[0][1].headers as Record<string, string>;
    const postHeaders = fetch.mock.calls[1][1].headers as Record<string, string>;
    expect(getHeaders["x-csrf-token"]).toBeUndefined();
    expect(postHeaders["x-csrf-token"]).toBe("csrf-123");
    expect(fetch.mock.calls[1][1].credentials).toBe("same-origin");
  });

  it("turns FastAPI validation errors into readable messages", async () => {
    mockFetch(422, { detail: [{ loc: ["body", "title"], msg: "String should have at least 3 characters" }] });
    const error = await api.post("/incidents", {}).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(422);
    expect((error as ApiError).message).toBe("title: String should have at least 3 characters");
  });

  it("returns undefined for 204 responses", async () => {
    mockFetch(204, undefined);
    await expect(api.post("/auth/logout")).resolves.toBeUndefined();
  });
});
