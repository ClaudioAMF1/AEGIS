import { type APIRequestContext, expect, type Page } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

export const STATE_FILE = path.join(__dirname, ".e2e-state.json");

export interface E2EState {
  admin: { email: string; password: string };
  viewer: { email: string; password: string };
}

export function state(): E2EState {
  return JSON.parse(fs.readFileSync(STATE_FILE, "utf8")) as E2EState;
}

export async function login(page: Page, who: "admin" | "viewer" = "admin") {
  const { email, password } = state()[who];
  await page.goto("/login");
  await page.getByLabel("e-mail").fill(email);
  await page.getByLabel("senha").fill(password);
  await page.getByRole("button", { name: "entrar" }).click();
  await expect(page).toHaveURL(/\/dashboard/);
}

/** Authenticated API call through the same origin (cookie + CSRF). */
export async function apiLogin(request: APIRequestContext, who: "admin" | "viewer" = "admin") {
  const { email, password } = state()[who];
  const response = await request.post("/api/v1/auth/login", { data: { email, password } });
  expect(response.ok()).toBeTruthy();
  return ((await response.json()) as { csrf_token: string }).csrf_token;
}

export async function setMode(page: Page, mode: "live" | "demo") {
  await page.getByRole("radio", { name: mode }).first().click();
}
