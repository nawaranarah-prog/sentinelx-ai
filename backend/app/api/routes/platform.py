"""Platform features: hunting, detection lab, simulation, investigations, knowledge graph, behavior analytics."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.analysis import dna as dna_mod
from app.analysis import entities as ent
from app.analysis import hunts as hunt_mod
from app.analysis import investigations as inv_mod
from app.analysis import knowledge_graph as kg
from app.analysis import quality
from app.analysis import simulation as sim
from app.analysis.detection_lab import (
    RuleSpecError,
    backtest,
    evasion_tests,
    next_custom_key,
    regression,
    rule_quality,
    validate_rule_spec,
)
from app.api.deps import AdminCtx, AnalystCtx, ReadCtx, WorkspaceContext
from app.api.routes.incidents import get_incident_or_404
from app.api.serializers import iso
from app.audit.service import record
from app.database.session import get_db, utcnow
from app.models import DetectionRule, Event, Hunt, Investigation, InvestigationItem, SimulationRun
from app.services.hunt_actions import incident_from_hunt
from app.services.pipeline import run_pipeline, workspace_lock

router = APIRouter(prefix="/api", tags=["platform"])


def _bh(ctx: WorkspaceContext) -> tuple[int, int]:
    b = (ctx.workspace.settings or {}).get("business_hours") or [7, 20]
    return int(b[0]), int(b[1])


# ------------------------------------------------------------------------------------------------ hunts
class HuntTranslateIn(BaseModel):
    text: str = Field(min_length=3, max_length=500)


class HuntRunIn(BaseModel):
    spec: dict
    name: str = Field(default="", max_length=255)
    natural_language: str = Field(default="", max_length=500)
    translation: str = Field(default="manual", max_length=24)
    save: bool = True


class HuntIncidentIn(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    event_ids: list[str] | None = None


class HuntRuleIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    severity: str = "medium"
    count: int = Field(default=1, ge=1, le=10000)
    window_minutes: int = Field(default=60, ge=1, le=10080)
    group_by: str = "host"


def hunt_payload(h: Hunt) -> dict:
    return {"id": h.id, "number": h.number, "name": h.name, "natural_language": h.natural_language, "spec": h.spec,
            "translation": h.translation, "last_run_at": iso(h.last_run_at), "last_result_count": h.last_result_count,
            "created_at": iso(h.created_at), "description": hunt_mod.describe(hunt_mod.validate_spec(h.spec))}


def _hunt(db: Session, ctx: WorkspaceContext, ref: str) -> Hunt:
    q = db.query(Hunt).filter(Hunt.workspace_id == ctx.workspace_id)
    h = q.filter(Hunt.number == ref.upper()).first() if ref.upper().startswith("HUNT-") else \
        q.filter(Hunt.id == int(ref)).first() if ref.isdigit() else None
    if h is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return h


@router.post("/hunts/translate")
def translate_hunt(body: HuntTranslateIn, ctx: WorkspaceContext = ReadCtx):
    t = hunt_mod.translate(body.text)
    return {"spec": t["spec"], "description": hunt_mod.describe(t["spec"]), "method": t["method"],
            "behaviors": hunt_mod.BEHAVIORS}


@router.post("/hunts/run")
def run_hunt(body: HuntRunIn, request: Request, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    try:
        res = hunt_mod.run(db, ctx.workspace_id, body.spec, _bh(ctx))
    except (hunt_mod.HuntError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid hunt: {exc}") from None
    number = None
    if body.save and ctx.role != "VIEWER":
        number = f"HUNT-{db.query(Hunt).filter_by(workspace_id=ctx.workspace_id).count() + 1:04d}"
        db.add(Hunt(workspace_id=ctx.workspace_id, number=number, name=(body.name or body.natural_language or "Hunt")[:255],
                    natural_language=body.natural_language, spec=res["spec"], translation=body.translation,
                    last_run_at=utcnow(), last_result_count=res["total"], created_by_id=ctx.user.id))
        db.commit()
    record(db, "RUN_HUNT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="hunt", target_id=number or "",
           details={"matches": res["total"]}, request=request)
    return {**res, "hunt": number}


@router.get("/hunts")
def list_hunts(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return [hunt_payload(h) for h in db.query(Hunt).filter_by(workspace_id=ctx.workspace_id).order_by(Hunt.id.desc()).limit(100)]


@router.get("/hunts/{ref}")
def get_hunt(ref: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    h = _hunt(db, ctx, ref)
    return {**hunt_payload(h), "result": hunt_mod.run(db, ctx.workspace_id, h.spec, _bh(ctx))}


@router.post("/hunts/{ref}/incident", status_code=201)
def hunt_to_incident(ref: str, body: HuntIncidentIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
                     db: Session = Depends(get_db)):
    h = _hunt(db, ctx, ref)
    try:
        inc = incident_from_hunt(db, ctx.workspace, h, body.title, body.event_ids, ctx.user.id)
    except LookupError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    db.commit()
    record(db, "CREATE_INCIDENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="incident", target_id=inc.id,
           details={"from_hunt": h.number}, request=request)
    return {"id": inc.id, "number": inc.number}


@router.post("/hunts/{ref}/candidate-rule", status_code=201)
def hunt_to_rule(ref: str, body: HuntRuleIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
                 db: Session = Depends(get_db)):
    h = _hunt(db, ctx, ref)
    s = h.spec
    spec = {"name": body.name, "description": f"Candidate rule generated from hunt {h.number}: {h.natural_language or h.name}",
            "severity": body.severity, "stage": "Custom",
            "match": {"event_types": s.get("event_types"), "status": s.get("status"), "actions": s.get("actions"),
                      "text_any": s.get("text_any"), "text_all": s.get("text_all"), "users": s.get("users"),
                      "hosts": s.get("hosts"),
                      "behaviors": [b for b in s.get("behaviors", []) if b in ("off_hours", "external_destination", "large_transfer")]},
            "threshold": {"count": body.count, "window_minutes": body.window_minutes, "group_by": body.group_by}}
    return _create_candidate(db, ctx, spec, request, source=h.number)


# ------------------------------------------------------------------------------------------------ detection lab
class CandidateIn(BaseModel):
    spec: dict


class SandboxIn(BaseModel):
    scenario: str
    variations: dict = Field(default_factory=dict)
    controls: list[str] = Field(default_factory=list)
    candidate_rule: str | None = None


def _create_candidate(db: Session, ctx: WorkspaceContext, spec: dict, request: Request, source: str = "manual") -> dict:
    try:
        clean = validate_rule_spec(spec)
    except (RuleSpecError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid rule: {exc}") from None
    key = next_custom_key(db, ctx.workspace_id)
    rule = DetectionRule(workspace_id=ctx.workspace_id, rule_key=key, name=clean["name"], description=clean["description"] or clean["name"],
                         severity=clean["severity"], enabled=False, kind="candidate", parameters={"spec": clean},
                         mitre_techniques=clean["mitre"], stage=clean["stage"], updated_by_id=ctx.user.id)
    db.add(rule)
    db.commit()
    record(db, "CHANGE_RULE", user=ctx.user, workspace_id=ctx.workspace_id, target_type="rule", target_id=key,
           details={"created_candidate": clean["name"], "source": source}, request=request)
    return {"rule_key": key, "id": rule.id, "spec": clean, "status": "candidate"}


def _rule(db: Session, ctx: WorkspaceContext, key: str) -> DetectionRule:
    r = db.query(DetectionRule).filter_by(workspace_id=ctx.workspace_id, rule_key=key.upper()).first()
    if r is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return r


@router.get("/lab/quality")
def lab_quality(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return rule_quality(db, ctx.workspace)


@router.get("/lab/candidates")
def lab_candidates(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    rows = db.query(DetectionRule).filter(DetectionRule.workspace_id == ctx.workspace_id,
                                          DetectionRule.kind.in_(["candidate", "custom"])).order_by(DetectionRule.id.desc())
    return [{"rule_key": r.rule_key, "name": r.name, "kind": r.kind, "enabled": r.enabled, "severity": r.severity,
             "spec": (r.parameters or {}).get("spec"), "last_backtest": (r.parameters or {}).get("last_backtest"),
             "updated_at": iso(r.updated_at)} for r in rows]


@router.post("/lab/candidates", status_code=201)
def lab_create_candidate(body: CandidateIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
                         db: Session = Depends(get_db)):
    return _create_candidate(db, ctx, body.spec, request)


@router.post("/lab/suggest-candidate")
def lab_suggest(body: SandboxIn, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    """Template-based candidate for a detection gap found by gap analysis (shown for the analyst to edit)."""
    gap = sim.gap_analysis(db, ctx.workspace, body.scenario, body.variations)
    templates = {
        "SX-001": {"name": "Sustained failed logins for one account", "severity": "high", "stage": "Credential Access",
                   "mitre": ["T1110.001"], "description": "Low-and-slow password guessing: 12+ failures for one account "
                                                          "within 4 hours (SX-001 only looks at short bursts).",
                   "match": {"event_types": ["authentication"], "status": "failure"},
                   "threshold": {"count": 12, "window_minutes": 240, "group_by": "user"}},
        "SX-002": {"name": "Login success after sustained failures", "severity": "high", "stage": "Initial Access",
                   "mitre": ["T1110", "T1078"], "description": "Many failures for an account followed by activity over hours.",
                   "match": {"event_types": ["authentication"], "status": "failure"},
                   "threshold": {"count": 15, "window_minutes": 180, "group_by": "user"}},
        "SX-009": {"name": "Uploads to external destinations", "severity": "medium", "stage": "Exfiltration",
                   "mitre": ["T1048"], "description": "Cumulative external uploads above 50 MB in an hour.",
                   "match": {"event_types": ["network"], "behaviors": ["external_destination", "large_transfer"]},
                   "threshold": {"count": 2, "window_minutes": 60, "group_by": "host"}},
        "SX-006": {"name": "Slow internal SMB sweep", "severity": "medium", "stage": "Discovery", "mitre": ["T1046"],
                   "description": "One host contacting many internal hosts on SMB within an hour.",
                   "match": {"event_types": ["network"], "text_any": []},
                   "threshold": {"count": 25, "window_minutes": 60, "group_by": "source_ip", "distinct": "destination_ip"}},
        "SX-005": {"name": "PowerShell from user workstation", "severity": "medium", "stage": "Execution",
                   "mitre": ["T1059.001"], "description": "PowerShell executed interactively by a user account.",
                   "match": {"event_types": ["process"], "text_any": ["powershell"]},
                   "threshold": {"count": 1, "window_minutes": 60, "group_by": "host"}},
    }
    spec = next((templates[r] for r in gap["rules_evaded"] if r in templates), None)
    return {"gap": gap, "suggested_spec": spec, "method": "template" if spec else None}


@router.post("/lab/rules/{key}/backtest")
def lab_backtest(key: str, request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    r = _rule(db, ctx, key)
    res = backtest(db, ctx.workspace, r)
    params = dict(r.parameters or {})
    params["last_backtest"] = {k: res[k] for k in ("alerts", "alerts_overlapping_incidents", "alerts_outside_incidents",
                                                    "benign_baseline_alerts", "scenario_coverage", "ran_at")}
    r.parameters = params
    db.commit()
    record(db, "BACKTEST_RULE", user=ctx.user, workspace_id=ctx.workspace_id, target_type="rule", target_id=r.rule_key,
           details={"alerts": res["alerts"], "benign_alerts": res["benign_baseline_alerts"]}, request=request)
    return res


@router.post("/lab/regression")
def lab_regression(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db), candidate: str | None = None):
    cand = _rule(db, ctx, candidate) if candidate else None
    return regression(db, ctx.workspace, cand)


@router.get("/lab/evasion")
def lab_evasion(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return evasion_tests(db, ctx.workspace)


@router.post("/lab/sandbox")
def lab_sandbox(body: SandboxIn, request: Request, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    extra = []
    if body.candidate_rule:
        c = _rule(db, ctx, body.candidate_rule)
        extra = [c]
    try:
        res = sim.sandbox(db, ctx.workspace, body.scenario, body.variations, body.controls, extra_rules=extra)
    except (sim.SimulationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if ctx.role != "VIEWER":
        sim.record_run(db, ctx.workspace_id, ctx.user.id, "sandbox", body.scenario, body.variations, body.controls, False, res)
        db.commit()
    return res


@router.post("/lab/rules/{key}/activate")
def lab_activate(key: str, request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    r = _rule(db, ctx, key)
    if r.kind not in ("candidate", "custom"):
        raise HTTPException(status_code=422, detail="Only custom rules can be activated here.")
    if not (r.parameters or {}).get("last_backtest"):
        raise HTTPException(status_code=422, detail="Backtest the candidate before activating it.")
    r.kind, r.enabled, r.version = "custom", True, r.version + 1
    r.updated_at, r.updated_by_id = utcnow(), ctx.user.id
    db.commit()
    with workspace_lock(ctx.workspace_id):
        stats = run_pipeline(db, ctx.workspace)
        db.commit()
    record(db, "CHANGE_RULE", user=ctx.user, workspace_id=ctx.workspace_id, target_type="rule", target_id=r.rule_key,
           details={"activated": True, "new_detections": stats["detections_created"]}, request=request)
    return {"rule_key": r.rule_key, "enabled": True, "detections_created": stats["detections_created"]}


@router.delete("/lab/rules/{key}")
def lab_discard(key: str, request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    r = _rule(db, ctx, key)
    if r.kind != "candidate":
        raise HTTPException(status_code=422, detail="Only candidate (inactive) rules can be discarded.")
    db.delete(r)
    db.commit()
    record(db, "CHANGE_RULE", user=ctx.user, workspace_id=ctx.workspace_id, target_type="rule", target_id=key,
           details={"discarded_candidate": True}, request=request)
    return {"ok": True}


# ------------------------------------------------------------------------------------------------ simulation
class WhatIfIn(BaseModel):
    controls: list[str] = Field(min_length=1, max_length=6)


class CounterfactualIn(BaseModel):
    remove_detection_ids: list[int] = Field(min_length=1, max_length=50)


@router.get("/sim/scenarios")
def scenarios(ctx: WorkspaceContext = ReadCtx):
    return {"scenarios": sim.scenario_catalogue(), "controls": [{"id": k, **v} for k, v in sim.CONTROLS.items()]}


@router.post("/sim/gap")
def gap(body: SandboxIn, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    try:
        return sim.gap_analysis(db, ctx.workspace, body.scenario, body.variations)
    except (sim.SimulationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.post("/sim/persist")
def persist(body: SandboxIn, request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    try:
        res = sim.persist(db, ctx.workspace, body.scenario, body.variations)
    except (sim.SimulationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    run = sim.record_run(db, ctx.workspace_id, ctx.user.id, "persisted", body.scenario, body.variations, [], True, res)
    db.commit()
    record(db, "START_SIMULATION", user=ctx.user, workspace_id=ctx.workspace_id, target_type="simulation", target_id=run.id,
           details={"scenario": body.scenario, "events": res["events"]}, request=request)
    return {**res, "run_id": run.id}


@router.get("/sim/runs")
def runs(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    rows = db.query(SimulationRun).filter_by(workspace_id=ctx.workspace_id).order_by(SimulationRun.id.desc()).limit(30)
    return [{"id": r.id, "kind": r.kind, "scenario": r.scenario, "variations": r.variations, "controls": r.controls,
             "persisted": bool(r.persisted), "created_at": iso(r.created_at),
             "rules_fired": (r.results.get("baseline") or {}).get("rules_fired"),
             "incidents": [i["number"] for i in r.results.get("incidents", [])]} for r in rows]


@router.post("/incidents/{incident_ref}/what-if")
def what_if(incident_ref: str, body: WhatIfIn, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_ref)
    bad = [c for c in body.controls if c not in sim.CONTROLS]
    if bad:
        raise HTTPException(status_code=422, detail=f"Unknown controls: {bad}")
    return sim.incident_what_if(db, inc, body.controls)


@router.post("/incidents/{incident_ref}/counterfactual")
def counterfactual(incident_ref: str, body: CounterfactualIn, ctx: WorkspaceContext = ReadCtx,
                   db: Session = Depends(get_db)):
    return sim.counterfactual(db, get_incident_or_404(db, ctx, incident_ref), body.remove_detection_ids)


@router.get("/incidents/{incident_ref}/similar")
def similar(incident_ref: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_ref)
    return {"dna": inc.dna, "similar": dna_mod.similar_incidents(db, ctx.workspace_id, inc, 8), "weights": dna_mod.WEIGHTS}


@router.get("/incidents/{incident_ref}/knowledge-graph")
def incident_kg(incident_ref: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return kg.incident_subgraph(db, ctx.workspace_id, get_incident_or_404(db, ctx, incident_ref))


@router.get("/analytics/families")
def families(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return {"families": dna_mod.families(db, ctx.workspace_id), "threshold": dna_mod.FAMILY_THRESHOLD,
            "weights": dna_mod.WEIGHTS}


# ------------------------------------------------------------------------------------------------ investigations
class InvestigationIn(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    incident: str | None = None


class ItemIn(BaseModel):
    kind: str
    text: str = Field(min_length=1, max_length=4000)
    status: str = "open"
    supporting: list[str] = Field(default_factory=list)
    contradicting: list[str] = Field(default_factory=list)


class ItemStatusIn(BaseModel):
    status: str


def _inv(db: Session, ctx: WorkspaceContext, ref: str) -> Investigation:
    inv = inv_mod.resolve(db, ctx.workspace_id, ref)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.get("/investigations")
def list_investigations(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return [inv_mod.payload(db, i, with_items=False) for i in
            db.query(Investigation).filter_by(workspace_id=ctx.workspace_id).order_by(Investigation.updated_at.desc()).limit(100)]


@router.post("/investigations", status_code=201)
def create_investigation(body: InvestigationIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
                         db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, body.incident) if body.incident else None
    inv = inv_mod.create(db, ctx.workspace_id, ctx.user.id, body.title, inc)
    db.commit()
    record(db, "UPDATE_INCIDENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="investigation",
           target_id=inv.number, details={"created": body.title}, request=request)
    return inv_mod.payload(db, inv)


@router.get("/investigations/{ref}")
def get_investigation(ref: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    from app.models import AIConversation

    inv = _inv(db, ctx, ref)
    convs = db.query(AIConversation).filter_by(workspace_id=ctx.workspace_id, investigation_id=inv.id).all()
    return {**inv_mod.payload(db, inv), "conversations": [{"id": c.id, "title": c.title} for c in convs]}


@router.post("/investigations/{ref}/items", status_code=201)
def add_item(ref: str, body: ItemIn, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    inv = _inv(db, ctx, ref)
    try:
        item = inv_mod.add_item(db, inv, body.kind, body.text, supporting=body.supporting, contradicting=body.contradicting,
                                status=body.status, user_id=ctx.user.id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    db.commit()
    return inv_mod.item_payload(item)


@router.patch("/investigations/{ref}/items/{item_id}")
def update_item(ref: str, item_id: int, body: ItemStatusIn, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    inv = _inv(db, ctx, ref)
    item = db.query(InvestigationItem).filter_by(id=item_id, investigation_id=inv.id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    if body.status not in inv_mod.STATUSES[item.kind]:
        raise HTTPException(status_code=422, detail=f"status must be one of {inv_mod.STATUSES[item.kind]}")
    item.status = body.status
    inv.updated_at = utcnow()
    db.commit()
    return inv_mod.item_payload(item)


@router.patch("/investigations/{ref}")
def close_investigation(ref: str, body: ItemStatusIn, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    inv = _inv(db, ctx, ref)
    if body.status not in ("OPEN", "CLOSED"):
        raise HTTPException(status_code=422, detail="status must be OPEN or CLOSED")
    inv.status = body.status
    db.commit()
    return inv_mod.payload(db, inv, with_items=False)


# ------------------------------------------------------------------------------------------------ graph
@router.get("/graph/search")
def graph_search(q: str, kind: str | None = None, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return [kg.node_payload(n) for n in kg.search_nodes(db, ctx.workspace_id, q, kind, 30)]


@router.get("/graph/nodes/{node_id}")
def graph_node(node_id: int, rel: str | None = None, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    from app.models import GraphNode

    node = db.query(GraphNode).filter_by(id=node_id, workspace_id=ctx.workspace_id).first()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"node": kg.node_payload(node), **kg.neighbors(db, ctx.workspace_id, node_id, [rel] if rel else None, 120)}


@router.get("/graph/paths")
def graph_paths(source: str, target: str, max_depth: int = 5, ctx: WorkspaceContext = ReadCtx,
                db: Session = Depends(get_db)):
    a, b = kg.find_node(db, ctx.workspace_id, source), kg.find_node(db, ctx.workspace_id, target)
    if a is None or b is None:
        raise HTTPException(status_code=404, detail=f"{'Source' if a is None else 'Target'} not found in the knowledge graph")
    return {"source": kg.node_payload(a), "target": kg.node_payload(b),
            **kg.find_paths(db, ctx.workspace_id, a.id, b.id, max_depth=min(max_depth, 7))}


@router.get("/graph/relations")
def graph_relations(ctx: WorkspaceContext = ReadCtx):
    return {"relations": kg.RELATIONS, "kinds": kg.NODE_KINDS}


# ------------------------------------------------------------------------------------------------ behavior analytics
def _kind(kind: str) -> str:
    if kind not in ("user", "host", "ip"):
        raise HTTPException(status_code=404, detail="Unknown entity type")
    return kind


@router.get("/entities/{kind}/{name}/baseline")
def entity_baseline(kind: str, name: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return ent.baseline(db, ctx.workspace_id, _kind(kind), name)


@router.get("/entities/{kind}/{name}/life-story")
def entity_story(kind: str, name: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return ent.life_story(db, ctx.workspace_id, _kind(kind), name)


@router.get("/entities/{kind}/{name}/risk-history")
def entity_risk_history(kind: str, name: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return ent.risk_history(db, ctx.workspace_id, _kind(kind), name)


@router.get("/entities/user/{name}/peers")
def entity_peers(name: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return ent.peer_group(db, ctx.workspace_id, name)


@router.get("/analytics/changes")
def changes(hours: float = 24, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return ent.environment_changes(db, ctx.workspace_id, max(1.0, min(hours, 720.0)))


@router.get("/analytics/risk-movers")
def movers(kind: str = "user", ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return ent.risk_movers(db, ctx.workspace_id, _kind(kind), 15)


@router.get("/analytics/unexplained")
def unexplained(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return ent.unknown_unknowns(db, ctx.workspace_id)


@router.get("/system/data-quality")
def data_quality(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return quality.data_quality(db, ctx.workspace_id)


@router.get("/system/pipeline")
def pipeline(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return quality.pipeline_status(db, ctx.workspace)


# ------------------------------------------------------------------------------------------------ deep links
@router.get("/events/by-uid/{uid}")
def event_by_uid(uid: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    e = db.query(Event).filter_by(workspace_id=ctx.workspace_id, event_uid=uid).first()
    if e is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"id": e.id, "event_uid": e.event_uid}


@router.get("/resolve")
def resolve(ref: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    from app.analysis.resolver import resolve_references

    return resolve_references(db, ctx.workspace_id, ref, limit=10)

