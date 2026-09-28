import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Loading, Empty } from "./components/ui";
import { useSession } from "./lib/session";
import { LoginPage, RegisterPage } from "./pages/Auth";
import { Dashboard } from "./pages/Dashboard";

const Incidents = lazy(() => import("./pages/Incidents").then((m) => ({ default: m.IncidentsPage })));
const IncidentDetail = lazy(() => import("./pages/IncidentDetail").then((m) => ({ default: m.IncidentDetailPage })));
const Detections = lazy(() => import("./pages/Detections").then((m) => ({ default: m.DetectionsPage })));
const DetectionDetail = lazy(() => import("./pages/Detections").then((m) => ({ default: m.DetectionDetailPage })));
const Events = lazy(() => import("./pages/Events").then((m) => ({ default: m.EventsPage })));
const Ingest = lazy(() => import("./pages/Ingest").then((m) => ({ default: m.IngestPage })));
const Assistant = lazy(() => import("./pages/Assistant").then((m) => ({ default: m.AssistantPage })));
const Entities = lazy(() => import("./pages/Entities").then((m) => ({ default: m.EntitiesPage })));
const EntityProfile = lazy(() => import("./pages/Entities").then((m) => ({ default: m.EntityProfilePage })));
const ThreatIntel = lazy(() => import("./pages/ThreatIntel").then((m) => ({ default: m.ThreatIntelPage })));
const Mitre = lazy(() => import("./pages/Mitre").then((m) => ({ default: m.MitrePage })));
const Analytics = lazy(() => import("./pages/Analytics").then((m) => ({ default: m.AnalyticsPage })));
const Reports = lazy(() => import("./pages/Reports").then((m) => ({ default: m.ReportsPage })));
const ReportView = lazy(() => import("./pages/Reports").then((m) => ({ default: m.ReportViewPage })));
const Health = lazy(() => import("./pages/Health").then((m) => ({ default: m.HealthPage })));
const Settings = lazy(() => import("./pages/Settings").then((m) => ({ default: m.SettingsPage })));
const Hunts = lazy(() => import("./pages/Hunts").then((m) => ({ default: m.HuntsPage })));
const DetectionLab = lazy(() => import("./pages/DetectionLab").then((m) => ({ default: m.DetectionLabPage })));
const SimulationLab = lazy(() => import("./pages/SimulationLab").then((m) => ({ default: m.SimulationLabPage })));
const AttackInvestigation = lazy(() => import("./pages/AttackInvestigation").then((m) => ({ default: m.AttackInvestigationPage })));
const Investigations = lazy(() => import("./pages/Investigations").then((m) => ({ default: m.InvestigationsPage })));
const GraphExplorer = lazy(() => import("./pages/GraphExplorer").then((m) => ({ default: m.GraphExplorerPage })));
const DataQuality = lazy(() => import("./pages/DataQuality").then((m) => ({ default: m.DataQualityPage })));
const EventDetail = lazy(() => import("./pages/EventDetail").then((m) => ({ default: m.EventDetailPage })));
const AdminUsers = lazy(() => import("./pages/admin/Users").then((m) => ({ default: m.AdminUsersPage })));
const AdminRules = lazy(() => import("./pages/admin/Rules").then((m) => ({ default: m.AdminRulesPage })));
const AdminKnowledge = lazy(() => import("./pages/admin/Knowledge").then((m) => ({ default: m.AdminKnowledgePage })));
const AdminAudit = lazy(() => import("./pages/admin/Audit").then((m) => ({ default: m.AdminAuditPage })));
const AdminAI = lazy(() => import("./pages/admin/AIConfig").then((m) => ({ default: m.AdminAIPage })));
const AdminSystem = lazy(() => import("./pages/admin/SystemConfig").then((m) => ({ default: m.AdminSystemPage })));

function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useSession();
  const location = useLocation();
  if (loading) return <Loading label="Starting SentinelX…" />;
  if (!me) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

function AdminOnly({ children }: { children: ReactNode }) {
  const { isAdmin, role } = useSession();
  if (!role) return <Loading />;
  if (!isAdmin) return <Empty title="Administrator access required">Your role in this workspace does not include administration. The API enforces the same restriction.</Empty>;
  return <>{children}</>;
}

export function App() {
  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route element={<RequireAuth><Layout /></RequireAuth>}>
          <Route index element={<Dashboard />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="detections" element={<Detections />} />
          <Route path="detections/:id" element={<DetectionDetail />} />
          <Route path="events" element={<Events />} />
          <Route path="events/:uid" element={<EventDetail />} />
          <Route path="hunts" element={<Hunts />} />
          <Route path="hunts/:ref" element={<Hunts />} />
          <Route path="detection-lab" element={<DetectionLab />} />
          <Route path="simulation" element={<SimulationLab />} />
          <Route path="investigate-attack" element={<AttackInvestigation />} />
          <Route path="investigations" element={<Investigations />} />
          <Route path="investigations/:ref" element={<Investigations />} />
          <Route path="graph" element={<GraphExplorer />} />
          <Route path="data-quality" element={<DataQuality />} />
          <Route path="ingest" element={<Ingest />} />
          <Route path="assistant" element={<Assistant />} />
          <Route path="entities" element={<Entities />} />
          <Route path="entities/:kind/:name" element={<EntityProfile />} />
          <Route path="threat-intel" element={<ThreatIntel />} />
          <Route path="mitre" element={<Mitre />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="reports" element={<Reports />} />
          <Route path="reports/:id" element={<ReportView />} />
          <Route path="health" element={<Health />} />
          <Route path="settings" element={<Settings />} />
          <Route path="admin/users" element={<AdminOnly><AdminUsers /></AdminOnly>} />
          <Route path="admin/rules" element={<AdminOnly><AdminRules /></AdminOnly>} />
          <Route path="admin/knowledge" element={<AdminOnly><AdminKnowledge /></AdminOnly>} />
          <Route path="admin/audit" element={<AdminOnly><AdminAudit /></AdminOnly>} />
          <Route path="admin/ai" element={<AdminOnly><AdminAI /></AdminOnly>} />
          <Route path="admin/system" element={<AdminOnly><AdminSystem /></AdminOnly>} />
          <Route path="*" element={<Empty title="Page not found">The page you requested does not exist.</Empty>} />
        </Route>
      </Routes>
    </Suspense>
  );
}
