import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import { AIChat } from "../components/AIChat";
import { SeverityBadge } from "../components/ui";
import { IncidentsPage } from "../pages/Incidents";
import { IngestPage } from "../pages/Ingest";
import { ME, WORKSPACE, mockApi, renderApp } from "./utils";

const unauth = () => new Response(JSON.stringify({ detail: "Not authenticated" }), { status: 401, headers: { "content-type": "application/json" } });

describe("authentication", () => {
  it("redirects anonymous users to the login page and signs in", async () => {
    let loggedIn = false;
    const calls = mockApi({
      "/api/auth/me": () => (loggedIn ? ME : unauth()),
      "/api/auth/login": () => { loggedIn = true; return { access_token: "t" }; },
      "/api/workspaces/current": WORKSPACE,
      "/api/analytics/summary": { kpis: {}, range: {} },
      "/api/notifications": { unread: 0, items: [] },
      "/api/ai/status": { mode: "LOCAL", label: "DEMO AI / LOCAL ANALYSIS" },
      "/api/simulation": { available: false },
    });
    renderApp(<App />, "/incidents");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    const button = screen.getByRole("button", { name: "Sign in" });
    expect(button).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Email"), "ana@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "Secret12345");
    await userEvent.click(button);
    await waitFor(() => expect(calls.some((c) => c.url === "/api/auth/login")).toBe(true));
    const login = calls.find((c) => c.url === "/api/auth/login")!;
    expect(JSON.parse(String(login.init!.body))).toEqual({ email: "ana@example.com", password: "Secret12345" });
    expect((login.init!.headers as Record<string, string>)["X-SentinelX-CSRF"]).toBe("1");
  });

  it("shows server errors on failed login", async () => {
    mockApi({
      "/api/auth/me": unauth,
      "/api/auth/login": () => new Response(JSON.stringify({ detail: "Invalid email or password." }), { status: 401, headers: { "content-type": "application/json" } }),
    });
    renderApp(<App />, "/login");
    await userEvent.type(await screen.findByLabelText("Email"), "x@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "nope");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password.");
  });

  it("enforces the password policy client-side on registration", async () => {
    mockApi({ "/api/auth/me": unauth });
    renderApp(<App />, "/register");
    await userEvent.type(await screen.findByLabelText("Password"), "short");
    expect(screen.getByText(/Needs at least 10 characters/)).toBeInTheDocument();
  });
});

describe("navigation", () => {
  it("renders the shell with a mobile drawer toggle and hides admin links from analysts", async () => {
    mockApi({
      "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE, "/api/notifications": { unread: 3, items: [] },
      "/api/ai/status": { mode: "LOCAL", label: "DEMO AI / LOCAL ANALYSIS" }, "/api/simulation": { available: false },
      "/api/analytics/summary": {
        range: { start: "2026-09-20T00:00:00Z", end: "2026-09-26T00:00:00Z", bucket_hours: 6 },
        kpis: { events: 10, detections: 2, incidents: 1, open_incidents: 1, critical_open: 0, anomalous_windows: 0, anomaly_windows: 5, users: 2, hosts: 2, mean_risk_open: 40 },
        events_over_time: [], detections_by_severity: [], recent_incidents: [], top_users: [], top_hosts: [], detections_by_rule: [],
      },
    });
    renderApp(<App />, "/");
    expect(await screen.findByRole("heading", { name: "Security overview" })).toBeInTheDocument();
    const nav = screen.getByRole("complementary", { name: "Primary" });
    expect(within(nav).getByRole("link", { name: "Event Explorer" })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Audit Log" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Open navigation" }));
    expect(nav).toHaveClass("open");
    expect(screen.getByRole("button", { name: /Notifications, 3 unread/ })).toBeInTheDocument();
    expect(screen.getAllByText(/DEMO MODE/).length).toBeGreaterThan(0);
  });
});

describe("incidents", () => {
  it("lists incidents with severity, risk and status from the API", async () => {
    mockApi({
      "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE,
      "/api/incidents": { total: 1, page: 1, page_size: 25, items: [{
        id: 6, number: "INC-0006", title: "Brute force leading to data exfiltration", status: "NEW", severity: "critical",
        confidence: 0.99, risk_score: 100, risk_band: "Critical", first_seen: "2026-09-25T01:12:00Z", last_seen: "2026-09-25T02:46:00Z",
        users: ["t.nguyen"], hosts: ["NB-WS-TR07"], source_ips: [], destination_ips: [], stages: ["Credential Access", "Exfiltration"],
        tags: [], assigned_to_id: null, assigned_to: null, created_at: "", updated_at: "", origin: "correlation", detection_count: 11 }] },
    });
    renderApp(<Routes><Route path="/incidents" element={<IncidentsPage />} /></Routes>, "/incidents");
    expect(await screen.findByText("INC-0006")).toBeInTheDocument();
    expect(screen.getByText("Credential Access → Exfiltration")).toBeInTheDocument();
    expect(screen.getByRole("meter", { name: "Risk score" })).toHaveAttribute("aria-valuenow", "100");
    expect(screen.getByRole("cell", { name: "Unassigned" })).toBeInTheDocument();
  });

  it("labels severity in text, never by color alone", () => {
    renderApp(<SeverityBadge severity="high" />);
    expect(screen.getByText("high")).toBeInTheDocument();
  });
});

describe("upload", () => {
  it("rejects unsupported file types before uploading", async () => {
    const calls = mockApi({
      "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE, "/api/ingest/jobs": [], "/api/ingest/samples": [],
      "/api/ingest/schema": { fields: [], formats: [], limits: { max_upload_mb: 25, max_rows: 200000 } },
    });
    renderApp(<Routes><Route path="/ingest" element={<IngestPage />} /></Routes>, "/ingest");
    const input = await screen.findByTestId("file-input");
    await userEvent.upload(input, new File(["MZ"], "malware.exe", { type: "application/octet-stream" }), { applyAccept: false });
    expect(await screen.findByRole("alert")).toHaveTextContent("Unsupported file type");
    expect(calls.some((c) => c.url.includes("/api/ingest/preview"))).toBe(false);
  });

  it("previews a valid file with field mapping and validation counts", async () => {
    mockApi({
      "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE, "/api/ingest/jobs": [], "/api/ingest/samples": [],
      "/api/ingest/schema": { fields: [], formats: [], limits: { max_upload_mb: 25, max_rows: 200000 } },
      "/api/ingest/preview": { filename: "a.csv", file_format: "csv", columns: ["time", "src_ip"], field_mapping: { time: "timestamp", src_ip: "source_ip" },
        unmapped_columns: [], total_rows: 3, valid_rows: 2, rejected_rows: 1, duplicates_in_file: 0, warning_count: 0,
        errors: [{ row: 3, error: "missing required field 'timestamp'" }], warnings: [], sample: [] },
    });
    renderApp(<Routes><Route path="/ingest" element={<IngestPage />} /></Routes>, "/ingest");
    await userEvent.upload(await screen.findByTestId("file-input"), new File(["time,src_ip\n"], "a.csv", { type: "text/csv" }));
    expect(await screen.findByText(/Validation & normalization preview/)).toBeInTheDocument();
    expect(screen.getByText(/missing required field 'timestamp'/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ingest 2 valid rows" })).toBeEnabled();
  });
});

describe("AI assistant", () => {
  it("labels LOCAL mode, separates evidence and flags removed references", async () => {
    mockApi({
      "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE,
      "/api/ai/status": { mode: "LOCAL", label: "DEMO AI / LOCAL ANALYSIS", detail: "" },
      "/api/ai/suggestions": { suggestions: ["What happened?"] },
      "/api/ai/chat": {
        conversation_id: 1, user_message: { id: 1, role: "user", content: "What happened?" },
        message: { id: 2, role: "assistant", content: "", mode: "LOCAL", provider: "local", model: "sentinelx-local-analyst",
          structured: { summary: "INC-0006 summary", evidence: [{ statement: "38 failed logins", event_ids: ["NB-000123"], detection_ids: [5] },
            { statement: "invented", event_ids: [], detection_ids: [], unverified: true }],
            inference: ["Single actor"], uncertainty: ["Limited telemetry"], next_steps: ["Reset credentials"], techniques: [{ id: "T1110.001", reason: "" }],
            notices: ["DEMO AI / LOCAL ANALYSIS: deterministic analysis"], security_notes: ["Possible prompt-injection text found in data"] },
          sources: [], tool_calls: [{ tool: "get_incident", args: {}, ok: true }], validation: { passed: false, removed_event_ids: ["NB-999"] }, latency_ms: 12, created_at: "" },
      },
    });
    renderApp(<AIChat incidentId={6} />);
    await userEvent.click(await screen.findByRole("button", { name: "What happened?" }));
    expect(await screen.findByText("INC-0006 summary")).toBeInTheDocument();
    expect(screen.getAllByText("DEMO AI / LOCAL ANALYSIS").length).toBeGreaterThan(0);
    expect(screen.getByText("EVIDENCE")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "NB-000123" })).toHaveAttribute("href", "/events?q=NB-000123");
    expect(screen.getByText("unverified reference removed")).toBeInTheDocument();
    expect(screen.getByText(/prompt-injection/)).toBeInTheDocument();
    expect(screen.getByText("Grounding check: references removed")).toBeInTheDocument();
  });
});
