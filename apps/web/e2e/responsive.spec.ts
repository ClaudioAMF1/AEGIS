import { expect, test } from "@playwright/test";

import { login, setMode } from "./helpers";

const VIEWPORTS = [
  { name: "phone", width: 390, height: 844 },
  { name: "tablet", width: 820, height: 1180 },
  { name: "desktop", width: 1440, height: 900 },
];

for (const viewport of VIEWPORTS) {
  test(`console layout has no horizontal overflow on ${viewport.name}`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await login(page);
    await setMode(page, "demo");
    for (const route of ["/dashboard", "/alerts", "/incidents", "/analytics"]) {
      await page.goto(route);
      await page.waitForLoadState("networkidle");
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow, `${route} overflows by ${overflow}px`).toBeLessThanOrEqual(1);
    }
    if (viewport.width < 1024) {
      await page.getByRole("button", { name: "Abrir menu" }).click();
      await page.getByRole("dialog").getByRole("link", { name: "incidentes" }).click();
      await expect(page).toHaveURL(/\/incidents/);
    }
  });
}
