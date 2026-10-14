import { request } from "@playwright/test";
import crypto from "node:crypto";
import fs from "node:fs";

import { STATE_FILE } from "./helpers";

/**
 * Requires an existing administrator (E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD), created with
 * `aegis create-user`. Creates (or reuses) a viewer account for RBAC checks.
 */
export default async function globalSetup() {
  const baseURL = process.env.E2E_BASE_URL ?? "http://localhost:3000";
  const admin = { email: process.env.E2E_ADMIN_EMAIL ?? "", password: process.env.E2E_ADMIN_PASSWORD ?? "" };
  if (!admin.email || !admin.password) throw new Error("set E2E_ADMIN_EMAIL and E2E_ADMIN_PASSWORD");
  const ctx = await request.newContext({ baseURL });
  const login = await ctx.post("/api/v1/auth/login", { data: admin });
  if (!login.ok()) throw new Error(`admin login failed: ${login.status()}`);
  const { csrf_token } = (await login.json()) as { csrf_token: string };
  // A fresh viewer per run: no shared password, no reuse of stale accounts.
  const viewer = {
    email: `e2e-viewer-${crypto.randomBytes(4).toString("hex")}@aegis.lab`,
    password: `viewer-${crypto.randomBytes(12).toString("hex")}`,
  };
  const created = await ctx.post("/api/v1/users", {
    data: { email: viewer.email, display_name: "E2E Viewer", role: "viewer", password: viewer.password },
    headers: { "x-csrf-token": csrf_token },
  });
  if (!created.ok()) throw new Error(`viewer creation failed: ${created.status()} ${await created.text()}`);
  fs.writeFileSync(STATE_FILE, JSON.stringify({ admin, viewer }));
  await ctx.dispose();
}
