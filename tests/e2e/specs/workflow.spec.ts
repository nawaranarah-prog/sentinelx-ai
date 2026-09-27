import { expect, test } from "@playwright/test";
import { register, trackConsole, unexpected } from "./helpers";

test("analyst workflow: register, upload, detect, investigate, AI, report, audit, logout", async ({ page, request }) => {
  const errors = trackConsole(page);
  await register(page);

  // Upload a sample dataset exactly as a user would (file picker).
  const csv = await (await request.get("/api/ingest/samples/mixed.csv")).body();
  await page.getByRole("link", { name: "Upload security data" }).first().click();
  await expect(page.getByRole("heading", { name: "Upload security data" })).toBeVisible();
  await page.getByTestId("file-input").setInputFiles({ name: "nova_mixed.csv", mimeType: "text/csv", buffer: csv });
  await expect(page.getByText("Validation & normalization preview")).toBeVisible();
  await expect(page.locator(".chip", { hasText: "src_ip" })).toContainText("source_ip");
  await page.getByRole("button", { name: /Ingest .* valid rows/ }).click();
  await expect(page.getByText("Events ingested")).toBeVisible({ timeout: 90_000 });
  const detections = Number(await page.locator(".stat", { hasText: "Detections generated" }).locator(".value").innerText());
  const incidents = Number(await page.locator(".stat", { hasText: "Incidents generated" }).locator(".value").innerText());
  expect(detections).toBeGreaterThan(10);
  expect(incidents).toBeGreaterThan(3);
  await page.screenshot({ path: "screenshots/upload-result.png", fullPage: true });

  // Dashboard reflects the new data.
  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
  await page.screenshot({ path: "screenshots/dashboard.png", fullPage: true });

  // Incident workspace.
  await page.getByRole("link", { name: "Incidents", exact: true }).click();
  await page.locator("table tbody tr").first().click();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText("Why these were correlated:")).toBeVisible();
  await expect(page.getByRole("heading", { name: "SentinelX Risk Score" })).toBeVisible();
  await page.screenshot({ path: "screenshots/incident-overview.png", fullPage: true });
  for (const tab of ["Timeline", "Evidence", "Attack Graph", "MITRE ATT&CK", "Recommendations", "Case", "Audit History"]) {
    await page.getByRole("tab", { name: tab }).click();
    await expect(page.getByRole("tab", { name: tab })).toHaveAttribute("aria-selected", "true");
  }
  await page.getByRole("tab", { name: "Attack Graph" }).click();
  await expect(page.getByRole("img", { name: /Attack graph/ })).toBeVisible();
  await page.screenshot({ path: "screenshots/incident-graph.png", fullPage: true });
  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByText("Why did this trigger?").first()).toBeVisible();

  // Case management: note + status change.
  await page.getByRole("tab", { name: "Case" }).click();
  await page.getByLabel("Add note").fill("Confirmed with helpdesk: user did not initiate the VPN session.");
  await page.getByRole("button", { name: "Save note" }).click();
  await expect(page.getByText("Confirmed with helpdesk")).toBeVisible();
  await page.getByLabel("Status").selectOption("IN_PROGRESS");
  await expect(page.getByText("Status updated")).toBeVisible();

  // AI investigation grounded in the incident.
  await page.getByRole("tab", { name: "AI Investigation" }).click();
  await page.getByRole("button", { name: "What happened?" }).click();
  await expect(page.getByText("DEMO AI / LOCAL ANALYSIS").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("EVIDENCE", { exact: true })).toBeVisible();
  await expect(page.getByText(/Grounding check/)).toBeVisible();
  await page.getByLabel("Ask the assistant").fill("What should I investigate next?");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.getByText("RECOMMENDED NEXT STEPS").last()).toBeVisible({ timeout: 30_000 });
  await page.screenshot({ path: "screenshots/incident-ai.png", fullPage: true });

  // Report generation and export.
  await page.getByLabel("Generate report").selectOption("technical");
  await expect(page.getByRole("heading", { name: /Technical Investigation Report/ })).toBeVisible({ timeout: 30_000 });
  await expect(page.frameLocator("iframe").getByText("Timeline (evidence events)")).toBeVisible();
  const [pdf] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "PDF" }).click()]);
  expect(pdf.suggestedFilename()).toMatch(/\.pdf$/);
  await page.screenshot({ path: "screenshots/report.png", fullPage: true });

  // Event explorer with filters and raw JSON.
  await page.getByRole("link", { name: "Event Explorer" }).click();
  await page.getByLabel("User").fill("t.nguyen");
  await expect(page.getByText(/matching events/)).toBeVisible();
  await page.locator("table tbody tr").first().click();
  await page.getByRole("tab", { name: "Raw original" }).click();
  await expect(page.getByLabel("Raw event JSON")).toBeVisible();
  await page.keyboard.press("Escape");

  // Threat intelligence search.
  await page.getByRole("link", { name: "Threat Intelligence" }).click();
  await page.getByLabel("Indicator").fill("203.0.113.45");
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await expect(page.getByText("Sightings in telemetry")).toBeVisible();

  // Command palette.
  await page.keyboard.press("Control+K");
  await page.getByLabel("Search or command").fill("t.nguyen");
  await expect(page.getByRole("dialog", { name: "Command palette" }).getByRole("option", { name: /t\.nguyen/ }).first()).toBeVisible();
  await page.keyboard.press("Escape");

  // Audit log contains the workflow.
  await page.getByRole("link", { name: "Audit Log" }).click();
  for (const action of ["UPLOAD_DATA", "VIEW_INCIDENT", "QUERY_AI", "EXPORT_REPORT", "CHANGE_INCIDENT_STATUS"]) {
    await expect(page.getByRole("cell", { name: action }).first()).toBeVisible();
  }

  // Health page is honest about SQLite / AI.
  await page.getByRole("link", { name: "System Health" }).click();
  await expect(page.getByText("NOT CONFIGURED").first()).toBeVisible();

  // Logout.
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(unexpected(errors)).toEqual([]);
});

test("demo mode: Nova Bank workspace is generated by the real pipeline", async ({ page }) => {
  const errors = trackConsole(page);
  await register(page, "demo");
  await page.getByRole("button", { name: "Open Nova Bank demo" }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText("DEMO MODE").first()).toBeVisible();
  await page.getByRole("link", { name: "Incidents", exact: true }).click();
  await expect(page.locator("table tbody tr")).toHaveCount(7);
  await page.getByRole("link", { name: "MITRE ATT&CK" }).click();
  await expect(page.getByRole("heading", { name: "MITRE ATT&CK coverage" })).toBeVisible();
  await page.getByRole("link", { name: "Analytics" }).click();
  await expect(page.getByText("Anomaly score distribution")).toBeVisible();
  await page.screenshot({ path: "screenshots/analytics.png", fullPage: true });
  await page.getByRole("link", { name: "Users & Hosts" }).click();
  await page.locator("table tbody tr").first().click();
  await expect(page.getByText("Behavioral anomaly analysis")).toBeVisible();
  expect(unexpected(errors)).toEqual([]);
});

test("viewer role is read-only in the UI and API", async ({ page, request }) => {
  const adminEmail = await register(page, "owner");
  const viewer = `viewer-${Date.now()}@example.com`;
  await page.getByRole("link", { name: "Users & Roles" }).click();
  await page.getByLabel("Email").fill(viewer);
  await page.getByLabel("Role", { exact: true }).selectOption("VIEWER");
  await page.getByLabel(/Initial password/).fill("ViewerPass12345");
  await page.getByRole("button", { name: "Add member" }).click();
  await expect(page.getByRole("cell", { name: new RegExp(viewer) }).first()).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Email").fill(viewer);
  await page.getByLabel("Password").fill("ViewerPass12345");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Viewer", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Audit Log" })).toHaveCount(0);
  await page.goto("/ingest");
  await expect(page.getByText(/Upload requires the SOC Analyst or Admin role/)).toBeVisible();
  const r = await page.evaluate(async () => {
    const fd = new FormData();
    fd.append("file", new Blob(["timestamp,user\n2026-09-01T10:00:00Z,a\n"]), "a.csv");
    const res = await fetch("/api/ingest/upload", { method: "POST", body: fd, headers: { "X-SentinelX-CSRF": "1" } });
    return res.status;
  });
  expect(r).toBe(403);
  expect(adminEmail).toContain("@");
  void request;
});

