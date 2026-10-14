import { expect, test } from "@playwright/test";

import { apiLogin, login, setMode } from "./helpers";

test("viewer sees data but no management controls, and the API refuses writes", async ({ page }) => {
  await login(page, "viewer");
  await setMode(page, "live");
  await page.goto("/endpoints");
  await expect(page.getByRole("heading", { name: "Dispositivos monitorados" })).toBeVisible();
  await expect(page.getByRole("button", { name: "cadastrar agente" })).toHaveCount(0);
  await page.goto("/settings");
  await expect(page.getByRole("tab", { name: "usuários" })).toHaveCount(0);
  await expect(page.getByRole("tab", { name: "auditoria" })).toHaveCount(0);

  // The UI hiding controls is not the barrier: the API enforces it.
  const csrf = await apiLogin(page.request, "viewer");
  const response = await page.request.post("/api/v1/agents", { data: { name: "nope" }, headers: { "x-csrf-token": csrf } });
  expect(response.status()).toBe(403);
});
