import { expect, test } from "@playwright/test";

import { apiLogin, login, setMode } from "./helpers";

test.describe.configure({ mode: "serial" });

test("demo scenario → alerts → incident investigation → assistant", async ({ page }) => {
  const csrf = await apiLogin(page.request);
  await page.request.post("/api/v1/demo/reset", { headers: { "x-csrf-token": csrf } });

  await login(page);
  await setMode(page, "demo");
  await page.goto("/settings");
  await page.getByRole("tab", { name: "modo demo" }).click();
  const scenario = page.locator("li", { hasText: "SSH brute force to persistence" });
  await scenario.getByRole("button", { name: "executar" }).click();
  await expect(page.getByText("completed").first()).toBeVisible();

  await page.goto("/alerts");
  await expect(page.getByRole("button", { name: "SSH Brute Force" })).toBeVisible();
  await page.getByRole("button", { name: "Reverse Shell Command Line" }).click();
  const drawer = page.getByRole("complementary", { name: "Detalhes" });
  await expect(drawer.getByText("T1059.004")).toBeVisible();
  await expect(drawer.getByText("evidências (1)")).toBeVisible();
  await drawer.getByRole("link", { name: "abrir investigação" }).click();

  await expect(page).toHaveURL(/\/incidents\/[0-9a-f-]+/);
  await expect(page.getByText("alertas vinculados")).toBeVisible();
  await page.getByRole("tab", { name: "linha do tempo" }).click();
  await expect(page.getByRole("img", { name: /Linha do tempo com \d+ eventos/ })).toBeVisible();
  await page.getByRole("tab", { name: "processos" }).click();
  await expect(page.getByText("◆ detecção").first()).toBeVisible();
  await page.getByRole("tab", { name: "grafo" }).click();
  await expect(page.getByRole("img", { name: /Grafo com \d+ entidades/ })).toBeVisible();
  await page.getByRole("tab", { name: "diário · evidências" }).click();
  await page.getByPlaceholder("Registrar observação, hipótese ou decisão…").fill("E2E: reverse shell confirmed from timeline.");
  await page.getByRole("button", { name: "comentar" }).click();
  await expect(page.getByText("E2E: reverse shell confirmed from timeline.")).toBeVisible();
  await page.getByRole("tab", { name: "resposta" }).click();
  await expect(page.getByText("prévia de impacto")).toBeVisible();

  await page.getByRole("link", { name: "perguntar ao assistente" }).click();
  await page.getByRole("button", { name: "perguntar" }).click();
  await expect(page.getByText("fatos observados")).toBeVisible();
  // every fact carries at least one event citation link
  await expect(page.locator("a[title^='evento ']").first()).toBeVisible();
});

test("events explorer filters on the server", async ({ page }) => {
  await login(page);
  await setMode(page, "demo");
  await page.goto("/events?process=crontab");
  await expect(page.getByText("crontab /tmp/.cache/c")).toBeVisible();
  await page.getByLabel("texto").fill("/dev/tcp/");
  await page.getByRole("button", { name: "↵" }).click();
  await expect(page.getByText(/evento\(s\)/)).toBeVisible();
});
