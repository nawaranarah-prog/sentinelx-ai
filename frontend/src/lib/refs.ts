/** Citation tokens written by the copilot ([INC:INC-0006], [EVT:NB-000123] …) and deep links for SentinelX objects. */

export const CITATION = /\[(INC|EVT|USER|HOST|IP|DET|RULE|TECH|IOC|INV|HUNT|DOMAIN|PROC):([^\]\s][^\]]{0,120})\]/g;

export function linkFor(kind: string, id: string): string {
  const e = encodeURIComponent(id);
  switch (kind) {
    case "INC": return `/incidents/${e}`;
    case "EVT": return `/events/${e}`;
    case "USER": return `/entities/user/${e}`;
    case "HOST": return `/entities/host/${e}`;
    case "IP": case "IOC": case "DOMAIN": return `/threat-intel?q=${e}`;
    case "DET": return `/detections/${encodeURIComponent(id.replace(/^DET-/i, ""))}`;
    case "RULE": return `/detection-lab?rule=${e}`;
    case "TECH": return `/mitre?technique=${e}`;
    case "INV": return `/investigations/${e}`;
    case "HUNT": return `/hunts/${e}`;
    case "PROC": return `/graph?q=${e}`;
    default: return "/";
  }
}

export function citationLabel(kind: string, id: string): string {
  if (kind === "DET") return `DET-${id.replace(/^DET-/i, "")}`;
  if (kind === "RULE" || kind === "TECH" || kind === "INC" || kind === "INV" || kind === "HUNT") return id;
  return id;
}

const escapeLabel = (s: string) => s.replace(/[[\]\\*_`]/g, (c) => `\\${c}`);

/** Turn citation tokens into markdown links to the object's page (rendered as chips). */
export function citationsToMarkdown(text: string): string {
  return text.replace(CITATION, (_m, kind: string, id: string) =>
    `[${escapeLabel(citationLabel(kind, id))}](${linkFor(kind, id)} "${kind}")`);
}

/** Context chip for the copilot: "INC:INC-0006". */
export const ctxToken = (kind: string, id: string | number) => `${kind}:${id}`;
