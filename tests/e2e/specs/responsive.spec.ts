import { expect, test } from "@playwright/test";
import { noHorizontalOverflow, register, trackConsole, unexpected } from "./helpers";

const WIDTHS = [375, 390, 768, 1024, 1280, 1440, 1920];

test("no horizontal overflow and usable navigation at every target width", async ({ page }) => {
  test.setTimeout(600_000); // 70 page loads; remote deployments need more than the default budget
  const errors = trackConsole(page);
  await register(page, "responsive");
  await page.getByRole("button", { name: "Open Nova Bank demo" }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible({ timeout: 60_000 });
  await page.getByRole("link", { name: "Incidents", exact: true }).click();
  await page.locator("table tbody tr").first().click();
  const incidentUrl = page.url();
  const routes = ["/", incidentUrl, "/events", "/assistant", "/hunts", "/detection-lab", "/simulation", "/investigations", "/graph", "/data-quality", "/ingest", "/analytics", "/threat-intel", "/detections", "/entities", "/admin/audit"];
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: width < 800 ? 844 : 900 });
    for (const route of routes) {
      await page.goto(route);
      await page.waitForLoadState("networkidle");
      const overflow = await noHorizontalOverflow(page);
      expect(overflow, `horizontal overflow of ${overflow}px on ${route} at ${width}px`).toBeLessThanOrEqual(1);
    }
    if (width < 1024) {
      await page.goto("/");
      await page.getByRole("button", { name: "Open navigation" }).click();
      await expect(page.locator(".sidebar.open")).toBeVisible();
      await page.locator(".sidebar").getByRole("link", { name: "Event Explorer" }).click();
      await expect(page.getByRole("heading", { name: "Event Explorer" })).toBeVisible();
    }
    if (width === 375 || width === 1440) {
      await page.goto(incidentUrl);
      await page.waitForLoadState("networkidle");
      await page.screenshot({ path: `screenshots/incident-${width}.png`, fullPage: true });
      await page.getByRole("tab", { name: "Attack Graph" }).click();
      await page.waitForLoadState("networkidle");
      await page.screenshot({ path: `screenshots/graph-${width}.png`, fullPage: true });
      await page.goto("/");
      await page.waitForLoadState("networkidle");
      await page.screenshot({ path: `screenshots/dashboard-${width}.png`, fullPage: true });
    }
  }
  await page.setViewportSize({ width: 375, height: 844 });
  await page.goto(incidentUrl);
  await page.getByRole("tab", { name: "Copilot" }).click();
  await page.getByLabel("Question").fill("Which users are affected?");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.getByText("Rule-based analysis").first()).toBeVisible({ timeout: 60_000 });
  expect(await noHorizontalOverflow(page)).toBeLessThanOrEqual(1);
  await page.screenshot({ path: "screenshots/ai-375.png", fullPage: true });
  expect(unexpected(errors)).toEqual([]);
});

test("keyboard: skip link, tabs with arrow keys, command palette", async ({ page }) => {
  await register(page, "keyboard");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  await page.keyboard.press("Control+K");
  await expect(page.getByRole("dialog", { name: "Command palette" })).toBeVisible();
  await page.keyboard.type("Event Explorer");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Event Explorer" })).toBeVisible();
});
