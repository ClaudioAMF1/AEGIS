import { expect, test } from "@playwright/test";

import { login, state } from "./helpers";

test("rejects wrong credentials with a generic message", async ({ page }) => {
  await page.goto("/login");
  // Uses the per-run viewer so repeated runs never lock out the administrator.
  await page.getByLabel("e-mail").fill(state().viewer.email);
  await page.getByLabel("senha").fill("definitely-not-the-password");
  await page.getByRole("button", { name: "entrar" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Credenciais" })).toHaveText(
    "Credenciais inválidas.",
  );
});

test("console routes redirect to login without a session", async ({ page }) => {
  await page.goto("/incidents");
  await expect(page).toHaveURL(/\/login\?next=%2Fincidents/);
});

test("login, navigate with keyboard shortcuts and logout", async ({ page }) => {
  await login(page);
  await expect(page.getByRole("heading", { name: "Central de operações" })).toBeVisible();
  await page.keyboard.press("g");
  await page.keyboard.press("a");
  await expect(page).toHaveURL(/\/alerts/);
  await page.getByRole("button", { name: "sair" }).click();
  await expect(page).toHaveURL(/\/login/);
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login/);
});

test("intro can be skipped and respects reduced motion", async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: "reduce" });
  const page = await context.newPage();
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Defesa cibernética");
  await expect(page.getByRole("dialog", { name: "Inicialização do AEGIS" })).toBeHidden({ timeout: 5000 });
  await page.getByRole("button", { name: "intro" }).click();
  await expect(page.getByRole("dialog", { name: "Inicialização do AEGIS" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog", { name: "Inicialização do AEGIS" })).toBeHidden();
  await context.close();
});
