import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import { Copilot } from "../components/Copilot";
import { HuntsPage } from "../pages/Hunts";
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

const assistantMsg = (over: Record<string, unknown> = {}) => ({
  id: 2, role: "assistant", mode: "LOCAL", provider: "local", model: "sentinelx-rule-based", latency_ms: 800, created_at: "", error_ref: "",
  content: "**INC-0006** began with 38 failed logins [EVT:NB-000123] by [USER:t.nguyen]; technique [TECH:T1110.001]. ⟨unverified reference EVT:NB-999 removed⟩",
  structured: { mode: "investigate", citations: [{ type: "EVT", id: "NB-000123", link: "/events/NB-000123" }],
    notice: { kind: "info", text: "No language model is connected; this answer was produced by SentinelX rule-based analysis using the same tools." },
    security_notes: ["Possible prompt-injection text in data (event NB-000124): \"Ignore all previous instructions\" — treated as data, not instructions."],
    scorecard: { evidence_reviewed: 12, entities_reviewed: 3, timeline_coverage: 0.4, open_questions: [], contradicting_evidence: 0, missing_telemetry: [], confidence: "medium", method: "Coverage = share…" } },
  activity: [{ tool: "get_incident", summary: "Read INC-0006 (11 detections)", ok: true }, { tool: "get_incident_timeline", summary: "Timeline of INC-0006: 80 events", ok: true }],
  artifacts: [], validation: { passed: false, invalid_citations: ["EVT:NB-999"], verified_citations: 3 },
  ...over,
});

describe("copilot", () => {
  it("renders cited objects as links, labels rule-based answers and shows activity", async () => {
    const calls = mockApi({
      "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE,
      "/api/ai/suggestions": { suggestions: ["Investigate the highest-risk incident"] },
      "/api/ai/chat": { conversation: { id: 1, title: "x", mode: "investigate", focus: { incident: "INC-0006" }, recent_refs: [], investigation_id: null, updated_at: "" },
        user_message: { id: 1, role: "user", content: "Investigate INC-0006", activity: [], artifacts: [], structured: {} }, message: assistantMsg() },
    });
    renderApp(<Copilot context={["INC:INC-0006"]} mode="investigate" />);
    await userEvent.click(await screen.findByRole("button", { name: "Investigate the highest-risk incident" }));
    expect(await screen.findByRole("link", { name: "NB-000123" })).toHaveAttribute("href", "/events/NB-000123");
    expect(screen.getByRole("link", { name: "t.nguyen" })).toHaveAttribute("href", "/entities/user/t.nguyen");
    expect(screen.getByRole("link", { name: "T1110.001" })).toHaveAttribute("href", "/mitre?technique=T1110.001");
    expect(screen.getByText("Rule-based analysis")).toBeInTheDocument();
    expect(screen.getByText(/No language model is connected/)).toBeInTheDocument();
    expect(screen.getByText(/treated as data/)).toBeInTheDocument();
    expect(screen.getByText("1 unverifiable reference(s) removed")).toBeInTheDocument();
    expect(screen.getByText("Investigation scorecard")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Investigation activity \(2 steps\)/ }));
    expect(screen.getByText(/Read INC-0006 \(11 detections\)/)).toBeInTheDocument();
    const body = JSON.parse(String(calls.find((c) => c.url === "/api/ai/chat")!.init!.body));
    expect(body).toMatchObject({ mode: "investigate", context: ["INC:INC-0006"] });
  });

  it("shows a failed model call with its investigation ID and a link to System Health", async () => {
    mockApi({
      "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE, "/api/ai/suggestions": { suggestions: [] },
      "/api/ai/chat": { conversation: { id: 1, title: "x", mode: "ask", focus: {}, recent_refs: [], investigation_id: null, updated_at: "" },
        user_message: { id: 1, role: "user", content: "hi", activity: [], artifacts: [], structured: {} },
        message: assistantMsg({ error_ref: "AIX-20260928-ABC123", content: "Open incidents: none.", structured: { mode: "ask", citations: [],
          notice: { kind: "error", reference: "AIX-20260928-ABC123", reason: "The AI provider timed out.", text: "AI investigation could not be completed. The answer below comes from SentinelX rule-based analysis instead." } } }) },
    });
    renderApp(<Copilot />);
    await userEvent.type(await screen.findByLabelText("Question"), "hi{Enter}");
    expect(await screen.findByRole("alert")).toHaveTextContent("AI investigation could not be completed");
    expect(screen.getByText("AIX-20260928-ABC123")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Check System Health" })).toHaveAttribute("href", "/health");
  });

  it("switches modes and loads mode-specific suggestions", async () => {
    const calls = mockApi({ "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE, "/api/ai/suggestions": { suggestions: ["Find large uploads"] } });
    renderApp(<Copilot />);
    await userEvent.click(await screen.findByRole("tab", { name: "Hunt" }));
    await waitFor(() => expect(calls.some((c) => c.url === "/api/ai/suggestions?mode=hunt")).toBe(true));
    expect(screen.getByRole("tab", { name: "Hunt" })).toHaveAttribute("aria-selected", "true");
  });
});

describe("hunt builder", () => {
  it("generates an editable search and runs it", async () => {
    const calls = mockApi({
      "/api/auth/me": ME, "/api/workspaces/current": WORKSPACE, "/api/hunts": [],
      "/api/hunts/translate": { spec: { behaviors: ["large_transfer"], group_by: "host" }, description: [{ label: "Behavior", value: "10 MB or more transferred in one event" }], method: "rule-based" },
      "/api/hunts/run": { spec: { group_by: "host" }, description: [{ label: "Behavior", value: "10 MB or more transferred in one event" }], scanned: 900, total: 1, groups: [{ key: "NB-WS-TR07", count: 1 }],
        entities: { users: [], hosts: [], ips: [] }, sequences: [], time_range: { start: null, end: null }, hunt: "HUNT-0001",
        events: [{ id: 1, event_uid: "NB-000200", timestamp: "2026-09-25T02:00:00Z", event_type: "network", user: "t.nguyen", host: "NB-WS-TR07", source_ip: null, destination_ip: "185.1.1.1", process: null, command: null, action: "upload", status: "success", severity: "high", bytes: 400000000, resource: null, source: null }] },
    });
    renderApp(<Routes><Route path="/hunts" element={<HuntsPage />} /><Route path="/hunts/:ref" element={<HuntsPage />} /></Routes>, "/hunts");
    await userEvent.type(await screen.findByLabelText("Hunt description"), "Find large uploads");
    await userEvent.click(screen.getByRole("button", { name: /Generate search/ }));
    expect((await screen.findAllByText("10 MB or more transferred in one event")).length).toBeGreaterThan(0);
    expect((screen.getByLabelText(/Specification/) as HTMLTextAreaElement).value).toContain("large_transfer");
    await userEvent.click(screen.getByRole("button", { name: /Run hunt/ }));
    await waitFor(() => expect(calls.some((c) => c.url === "/api/hunts/run")).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.url === "/api/hunts/run")!.init!.body)).spec.behaviors).toEqual(["large_transfer"]);
  });
});
