import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useDebounced } from "../lib/hooks";
import { useSession } from "../lib/session";

type Item = { id: string; group: string; label: string; hint?: string; run: () => void };

export function CommandPalette({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const { theme, setTheme, workspaceId } = useSession();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const q = useDebounced(query.trim(), 200);

  useEffect(() => inputRef.current?.focus(), []);

  const search = useQuery({
    queryKey: ["ws", workspaceId, "palette-search", q],
    queryFn: () => api<{ results: { type: string; title: string; subtitle?: string; link: string }[] }>(`/api/search?q=${encodeURIComponent(q)}`),
    enabled: q.length >= 2,
  });

  const go = (path: string) => () => { navigate(path); onClose(); };
  const commands: Item[] = useMemo(() => [
    { id: "c-inc", group: "Commands", label: "Open incidents", run: go("/incidents") },
    { id: "c-up", group: "Commands", label: "Upload security data", run: go("/ingest") },
    { id: "c-ai", group: "Commands", label: "Open AI assistant", run: go("/assistant") },
    { id: "c-ev", group: "Commands", label: "Open Event Explorer", run: go("/events") },
    { id: "c-ti", group: "Commands", label: "Open Threat Intelligence", run: go("/threat-intel") },
    { id: "c-rep", group: "Commands", label: "Generate report", hint: "from an incident", run: go("/reports") },
    { id: "c-mitre", group: "Commands", label: "Open MITRE ATT&CK", run: go("/mitre") },
    { id: "c-set", group: "Commands", label: "Settings", run: go("/settings") },
    { id: "c-theme", group: "Commands", label: `Theme: switch to ${theme === "dark" ? "light" : "dark"}`, run: () => { setTheme(theme === "dark" ? "light" : "dark"); onClose(); } },
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [theme]);

  const items: Item[] = useMemo(() => {
    const ql = query.toLowerCase();
    const cmds = commands.filter((c) => !ql || c.label.toLowerCase().includes(ql));
    const results = (search.data?.results ?? []).map((r, i) => ({
      id: `r-${i}`, group: `Results · ${r.type}`, label: r.title, hint: r.subtitle, run: go(r.link),
    }));
    return [...results, ...cmds];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, search.data, commands]);

  useEffect(() => setActive(0), [items.length]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
    else if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(items.length - 1, a + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
    else if (e.key === "Enter" && items[active]) items[active].run();
  };

  let lastGroup = "";
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Command palette">
        <input ref={inputRef} className="palette-input" placeholder="Search incidents, users, hosts, IPs, techniques… or type a command"
          value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={onKey}
          role="combobox" aria-expanded="true" aria-controls="palette-list" aria-activedescendant={items[active]?.id} aria-label="Search or command" />
        <ul className="palette-list" id="palette-list" role="listbox">
          {search.isFetching && <li className="palette-group">Searching…</li>}
          {items.map((it, i) => {
            const header = it.group !== lastGroup ? <li className="palette-group" role="presentation">{it.group}</li> : null;
            lastGroup = it.group;
            return (
              <FragmentRow key={it.id} header={header}>
                <li role="option" aria-selected={i === active} id={it.id}>
                  <button aria-selected={i === active} onMouseEnter={() => setActive(i)} onClick={it.run} tabIndex={-1}>
                    <span style={{ flex: 1 }}>{it.label}</span>{it.hint && <span className="muted small">{it.hint}</span>}
                  </button>
                </li>
              </FragmentRow>
            );
          })}
          {q.length >= 2 && !search.isFetching && search.data?.results.length === 0 && <li className="palette-group">No matching objects</li>}
        </ul>
      </div>
    </div>
  );
}

function FragmentRow({ header, children }: { header: React.ReactNode; children: React.ReactNode }) {
  return <>{header}{children}</>;
}
