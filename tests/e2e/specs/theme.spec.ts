import { expect, test } from "@playwright/test";
import { noHorizontalOverflow, register, trackConsole, unexpected } from "./helpers";

test("light theme renders and persists; settings page loads", async ({ page }) => {
  const errors = trackConsole(page);
  await register(page, "theme");
  await page.getByRole("button", { name: "Open Nova Bank demo" }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible({ timeout: 60_000 });
  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.waitForLoadState("networkidle");
  await page.screenshot({ path: "screenshots/dashboard-light.png", fullPage: true });
  await page.getByRole("link", { name: "Settings" }).click();
  await expect(page.getByLabel("Business hours start (UTC)")).toHaveValue("7");
  await expect(page.getByLabel("Correlation window (minutes between related detections)")).toHaveValue("120");
  expect(await noHorizontalOverflow(page)).toBeLessThanOrEqual(1);
  expect(unexpected(errors)).toEqual([]);
});
