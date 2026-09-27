import { expect, type Page } from "@playwright/test";

export const PASSWORD = "E2eStrongPass123";

export function trackConsole(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(`pageerror: ${err.message}`));
  return errors;
}

/**
 * Console errors that are expected: HTTP statuses from deliberate negative checks, and Chrome's notice when
 * Playwright's frameLocator probes the report iframe, which is sandboxed without allow-scripts on purpose.
 */
export function unexpected(errors: string[]): string[] {
  return errors.filter((e) => !/status of 401|status of 403|status of 404|status of 422/.test(e)
    && !e.includes("Blocked script execution in 'about:srcdoc'"));
}

export async function register(page: Page, prefix = "analyst"): Promise<string> {
  const email = `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e4)}@example.com`;
  await page.goto("/register");
  await page.getByLabel("Full name").fill("E2E Analyst");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Confirm password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: "Welcome to SentinelX" })).toBeVisible();
  return email;
}

export async function noHorizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
}
