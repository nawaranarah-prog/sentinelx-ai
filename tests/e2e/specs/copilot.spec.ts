import { expect, test } from "@playwright/test";
import { register, trackConsole, unexpected } from "./helpers";

async function openDemo(page: import("@playwright/test").Page) {
  await register(page, "copilot");
  await page.getByRole("button", { name: "Open Nova Bank demo" }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible({ timeout: 90_000 });
}

test("copilot: investigate an incident, follow a citation, follow-up keeps focus", async ({ page }) => {
  test.setTimeout(300_000);
  const errors = trackConsole(page);
  await openDemo(page);
  await page.getByRole("link", { name: "Incidents", exact: true }).click();
  await page.locator("table tbody tr").first().click();
  await expect(page).toHaveURL(/\/incidents\/INC-\d+/);
  await page.getByRole("main").getByRole("link", { name: "Investigate", exact: true }).click();
  await expect(page).toHaveURL(/\/assistant\?/);
  await expect(page.getByText("Rule-based analysis").first()).toBeVisible({ timeout: 90_000 });
  await expect(page.getByText("Investigation scorecard").first()).toBeVisible();
  await expect(page.getByRole("complementary", { name: "Investigation context" }).getByText(/INC-\d+/).first()).toBeVisible();
  // Follow-up with a pronoun uses the conversation focus.
  await page.getByLabel("Question").fill("Which hosts are affected in it?");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.locator("article.msg.assistant")).toHaveCount(2, { timeout: 90_000 });
  // Citations are links to the real object.
  const cite = page.locator("article.msg.assistant").first().locator("a.cite[title^='EVT']").first();
  const uid = (await cite.textContent())!.trim();
  await cite.click();
  await expect(page.getByRole("heading", { name: uid })).toBeVisible();
  await page.screenshot({ path: "screenshots/event-deeplink.png", fullPage: true });
  expect(unexpected(errors)).toEqual([]);
});

test("hunt builder, detection lab, knowledge graph and data quality work on demo data", async ({ page }) => {
  test.setTimeout(300_000);
  const errors = trackConsole(page);
  await openDemo(page);
  await page.goto("/hunts");
  await page.getByLabel("Hunt description").fill("Find large uploads to external destinations");
  await page.getByRole("button", { name: /Generate search/ }).click();
  await expect(page.getByLabel(/Specification/)).toHaveValue(/large_transfer/);
  await page.getByRole("button", { name: /Run hunt/ }).click();
  await expect(page).toHaveURL(/\/hunts\/HUNT-\d+/, { timeout: 60_000 });
  await expect(page.getByText(/match(es)? ·/).first()).toBeVisible();
  await page.screenshot({ path: "screenshots/hunt.png", fullPage: true });

  await page.goto("/detection-lab");
  await expect(page.getByRole("heading", { name: "Rule quality" })).toBeVisible({ timeout: 90_000 });
  await page.getByRole("tab", { name: "Variation tests" }).click();
  await expect(page.getByText(/evaded|detected/).first()).toBeVisible({ timeout: 60_000 });

  await page.goto("/graph?q=t.nguyen");
  await page.getByRole("button", { name: /user t\.nguyen/ }).first().click();
  await expect(page.getByRole("columnheader", { name: "Relationship" })).toBeVisible();

  await page.goto("/data-quality");
  await expect(page.getByText("Field completeness")).toBeVisible();
  await expect(page.getByText("Correlate", { exact: true })).toBeVisible();
  expect(unexpected(errors)).toEqual([]);
});

test("investigate an attack: simulation → incident → gap → candidate → backtest → replay → report", async ({ page }) => {
  test.setTimeout(600_000);
  const errors = trackConsole(page);
  await openDemo(page);
  await page.goto("/investigate-attack");
  await page.getByRole("button", { name: "Run the workflow" }).click();
  await expect(page.getByRole("heading", { name: /12\. Generate the technical report/ })).toBeVisible({ timeout: 480_000 });
  await expect(page.getByText(/Evaded:/)).toBeVisible();
  await expect(page.getByText(/fires on the replayed attack/)).toBeVisible();
  await expect(page.getByText("all datasets pass")).toBeVisible();
  await expect(page.locator("li.st-failed")).toHaveCount(0);
  await page.screenshot({ path: "screenshots/investigate-attack.png", fullPage: true });
  expect(unexpected(errors)).toEqual([]);
});
