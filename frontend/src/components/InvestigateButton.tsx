import { Link } from "react-router-dom";
import { Search } from "lucide-react";
import type { CopilotMode } from "../lib/types";

/** Opens the copilot with an object in context and a first question (e.g. "Investigate INC-0006"). */
export function copilotUrl(opts: { context?: string[]; mode?: CopilotMode; q?: string; investigation?: string }) {
  const sp = new URLSearchParams();
  opts.context?.forEach((c) => sp.append("context", c));
  if (opts.mode) sp.set("mode", opts.mode);
  if (opts.q) sp.set("q", opts.q);
  if (opts.investigation) sp.set("investigation", opts.investigation);
  return `/assistant?${sp.toString()}`;
}

export function InvestigateButton({ context, q, mode = "investigate", label = "Investigate", small }: {
  context: string[]; q: string; mode?: CopilotMode; label?: string; small?: boolean;
}) {
  return (
    <Link className={`btn ${small ? "btn-sm" : ""}`} to={copilotUrl({ context, mode, q })} title={q}>
      <Search aria-hidden="true" /> {label}
    </Link>
  );
}
