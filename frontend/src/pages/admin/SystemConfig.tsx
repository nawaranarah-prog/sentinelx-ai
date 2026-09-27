import { useWsQuery } from "../../lib/hooks";
import { Card, JsonBlock, KV, Loading } from "../../components/ui";

export function AdminSystemPage() {
  const q = useWsQuery<Record<string, any>>(["system-config"], "/api/system/config");
  if (q.isLoading) return <Loading />;
  const c = q.data!;
  return (
    <div className="stack">
      <div className="page-head"><div><h1>System configuration</h1><p>Effective, non-secret runtime configuration. Secrets are shown only as configured / not set.</p></div></div>
      <div className="grid grid-2">
        <Card title="Runtime">
          <KV items={[["Environment", c.environment], ["Version", c.version], ["Database", c.database_dialect === "postgresql" ? "PostgreSQL" : `${c.database_dialect} (development fallback — PostgreSQL NOT CONFIGURED)`],
            ["SECRET_KEY", c.secret_key], ["Registration", c.allow_registration ? "open" : "disabled"], ["Session lifetime", `${c.access_token_expire_minutes} min`],
            ["Secure cookies", c.cookie_secure ? "yes (HTTPS)" : "no (development)"], ["CORS origins", c.cors_origins.join(", ")]]} />
        </Card>
        <Card title="Limits">
          <KV items={[["Max upload", `${c.max_upload_mb} MB`], ["Max rows / upload", c.max_upload_rows.toLocaleString()],
            ["Rate limit (auth)", `${c.rate_limits_per_minute.auth}/min per IP`], ["Rate limit (AI)", `${c.rate_limits_per_minute.ai}/min per user`],
            ["Rate limit (upload)", `${c.rate_limits_per_minute.upload}/min per user`]]} />
        </Card>
        <Card title="Workspace analysis settings"><JsonBlock value={c.workspace_settings} label="Workspace settings" /></Card>
      </div>
    </div>
  );
}
