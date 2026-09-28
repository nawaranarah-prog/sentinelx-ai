from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base, JSONType, utcnow


class GraphNode(Base):
    """Security knowledge graph node (user, host, ip, process, domain, incident, detection, technique, ioc...)."""

    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("workspace_id", "kind", "key", name="uq_graph_node"),
                      Index("ix_graph_nodes_ws_kind", "workspace_id", "kind"))

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(24))
    key: Mapped[str] = mapped_column(String(255))
    label: Mapped[str] = mapped_column(String(255))
    props: Mapped[dict] = mapped_column(JSONType, default=dict)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (UniqueConstraint("workspace_id", "src_id", "dst_id", "rel", name="uq_graph_edge"),
                      Index("ix_graph_edges_src", "workspace_id", "src_id"),
                      Index("ix_graph_edges_dst", "workspace_id", "dst_id"))

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    src_id: Mapped[int] = mapped_column(ForeignKey("graph_nodes.id", ondelete="CASCADE"))
    dst_id: Mapped[int] = mapped_column(ForeignKey("graph_nodes.id", ondelete="CASCADE"))
    rel: Mapped[str] = mapped_column(String(32))
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    sample_event_uids: Mapped[list] = mapped_column(JSONType, default=list)
    props: Mapped[dict] = mapped_column(JSONType, default=dict)


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (UniqueConstraint("workspace_id", "number", name="uq_investigation_number"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    number: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="OPEN")
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    focus: Mapped[dict] = mapped_column(JSONType, default=dict)
    scorecard: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class InvestigationItem(Base):
    """Structured investigation memory: facts, hypotheses, conclusions, notes and open questions."""

    __tablename__ = "investigation_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    text: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="open")
    supporting: Mapped[list] = mapped_column(JSONType, default=list)
    contradicting: Mapped[list] = mapped_column(JSONType, default=list)
    source: Mapped[str] = mapped_column(String(16), default="analyst")
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Hunt(Base):
    __tablename__ = "hunts"
    __table_args__ = (UniqueConstraint("workspace_id", "number", name="uq_hunt_number"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    number: Mapped[str] = mapped_column(String(24))
    name: Mapped[str] = mapped_column(String(255))
    natural_language: Mapped[str] = mapped_column(Text, default="")
    spec: Mapped[dict] = mapped_column(JSONType, default=dict)
    translation: Mapped[str] = mapped_column(String(24), default="manual")
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_result_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))
    scenario: Mapped[str] = mapped_column(String(64))
    variations: Mapped[dict] = mapped_column(JSONType, default=dict)
    controls: Mapped[list] = mapped_column(JSONType, default=list)
    persisted: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[dict] = mapped_column(JSONType, default=dict)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AIError(Base):
    """Technical details of failed AI investigations (shown to admins on System Health, never to end users)."""

    __tablename__ = "ai_errors"

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int | None] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=True)
    reference: Mapped[str] = mapped_column(String(40), index=True)
    provider: Mapped[str] = mapped_column(String(32), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    category: Mapped[str] = mapped_column(String(48))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
