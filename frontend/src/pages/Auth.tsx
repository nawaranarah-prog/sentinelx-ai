import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { Logo } from "../components/Layout";
import { useSession } from "../lib/session";

function AuthAside() {
  return (
    <aside className="auth-aside">
      <div className="row"><Logo size={36} /><div><div className="brand-name" style={{ fontSize: 16 }}>SENTINELX AI</div><div style={{ color: "#7f8ea1" }}>Detect. Investigate. Understand.</div></div></div>
      <div>
        <h1 style={{ fontSize: 28, marginBottom: 12, color: "#e6edf6" }}>Security operations, from raw telemetry to explained incidents.</h1>
        <ul>
          <li>Ingest CSV / JSON telemetry and normalize it to one schema</li>
          <li>Ten detection rules with evidence-based explanations</li>
          <li>Isolation Forest + statistical behavioral baselines</li>
          <li>Correlated incidents mapped to MITRE ATT&amp;CK</li>
          <li>Investigation copilot that answers from your data and cites its evidence</li>
        </ul>
      </div>
      <p style={{ color: "#7f8ea1", fontSize: 12 }}>Portfolio project. Demo data describes the fictional Nova Bank and is entirely synthetic.</p>
    </aside>
  );
}

export function LoginPage() {
  const { me, login } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (me) return <Navigate to="/" replace />;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      navigate((location.state as { from?: string } | null)?.from ?? "/", { replace: true });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="auth-page">
      <AuthAside />
      <div className="auth-form-wrap">
        <div className="auth-card">
          <h1 style={{ marginBottom: 4 }}>Sign in</h1>
          <p className="muted" style={{ marginBottom: 20 }}>Access your SOC workspace.</p>
          <form onSubmit={submit} noValidate>
            <div className="field"><label htmlFor="email">Email</label>
              <input id="email" className="input" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></div>
            <div className="field"><label htmlFor="password">Password</label>
              <input id="password" className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></div>
            {error && <div className="field-error" role="alert">{error}</div>}
            <button className="btn btn-primary" type="submit" disabled={busy || !email || !password} style={{ height: 38, justifyContent: "center" }}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
          </form>
          <p className="muted mt-16">New to SentinelX? <Link to="/register">Create an account</Link></p>
        </div>
      </div>
    </div>
  );
}

export function RegisterPage() {
  const { me, register } = useSession();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "", confirm: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (me) return <Navigate to="/" replace />;
  const problems = [
    form.password.length < 10 && "at least 10 characters",
    !/[A-Za-z]/.test(form.password) && "a letter",
    !/\d/.test(form.password) && "a digit",
  ].filter(Boolean) as string[];
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problems.length) return setError(`Password needs ${problems.join(", ")}.`);
    if (form.password !== form.confirm) return setError("Passwords do not match.");
    setBusy(true);
    setError(null);
    try {
      await register(form.email, form.password, form.name);
      navigate("/", { replace: true });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });
  return (
    <div className="auth-page">
      <AuthAside />
      <div className="auth-form-wrap">
        <div className="auth-card">
          <h1 style={{ marginBottom: 4 }}>Create your account</h1>
          <p className="muted" style={{ marginBottom: 20 }}>You get a private workspace (you are its admin). You can open the Nova Bank demo afterwards.</p>
          <form onSubmit={submit} noValidate>
            <div className="field"><label htmlFor="name">Full name</label><input id="name" className="input" autoComplete="name" value={form.name} onChange={set("name")} /></div>
            <div className="field"><label htmlFor="remail">Email</label><input id="remail" className="input" type="email" autoComplete="email" required value={form.email} onChange={set("email")} /></div>
            <div className="field"><label htmlFor="rpass">Password</label>
              <input id="rpass" className="input" type="password" autoComplete="new-password" required value={form.password} onChange={set("password")} aria-describedby="pw-hint" />
              <span id="pw-hint" className="hint">{problems.length ? `Needs ${problems.join(", ")}.` : "Password meets the policy."}</span></div>
            <div className="field"><label htmlFor="rconfirm">Confirm password</label><input id="rconfirm" className="input" type="password" autoComplete="new-password" required value={form.confirm} onChange={set("confirm")} /></div>
            {error && <div className="field-error" role="alert">{error}</div>}
            <button className="btn btn-primary" type="submit" disabled={busy || !form.email} style={{ height: 38, justifyContent: "center" }}>{busy ? "Creating…" : "Create account"}</button>
          </form>
          <p className="muted mt-16">Already have an account? <Link to="/login">Sign in</Link></p>
        </div>
      </div>
    </div>
  );
}
