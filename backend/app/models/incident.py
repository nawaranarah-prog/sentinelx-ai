from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base, JSONType, utcnow

INCIDENT_STATUSES = ("NEW", "IN_PROGRESS", "CONTAINED", "RESOLVED", "FALSE_POSITIVE")
OPEN_STATUSES = ("NEW", "IN_PROGRESS", "CONTAINED")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("workspace_id", "number", name="uq_incident_number"),
        Index("ix_incidents_ws_status", "workspace_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    number: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(24), default="NEW")
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_band: Mapped[str] = mapped_column(String(16), default="Low")
    risk_factors: Mapped[list] = mapped_column(JSONType, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    users: Mapped[list] = mapped_column(JSONType, default=list)
    hosts: Mapped[list] = mapped_column(JSONType, default=list)
    source_ips: Mapped[list] = mapped_column(JSONType, default=list)
    destination_ips: Mapped[list] = mapped_column(JSONType, default=list)
    stages: Mapped[list] = mapped_column(JSONType, default=list)
    correlation_reason: Mapped[str] = mapped_column(Text, default="")
    correlation_keys: Mapped[dict] = mapped_column(JSONType, default=dict)
    anomaly_summary: Mapped[dict] = mapped_column(JSONType, default=dict)
    checklist: Mapped[list] = mapped_column(JSONType, default=list)
    tags: Mapped[list] = mapped_column(JSONType, default=list)
    origin: Mapped[str] = mapped_column(String(16), default="correlation")
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True, index=True)
    role: Mapped[str] = mapped_column(String(16), default="evidence")


class MITRETechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    tactic: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)
    detection_guidance: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(255))


class IncidentTechnique(Base):
    __tablename__ = "incident_techniques"
    __table_args__ = (UniqueConstraint("incident_id", "technique_id", name="uq_incident_technique"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(ForeignKey("mitre_techniques.id"))
    reason: Mapped[str] = mapped_column(Text)
    detection_ids: Mapped[list] = mapped_column(JSONType, default=list)
    event_uids: Mapped[list] = mapped_column(JSONType, default=list)
    mapping_confidence: Mapped[str] = mapped_column(String(16), default="high")


class IncidentStatusHistory(Base):
    __tablename__ = "incident_status_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    from_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    to_status: Mapped[str] = mapped_column(String(24))
    changed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    changed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="note")
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CaseAssignment(Base):
    __tablename__ = "case_assignments"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Bookmark(Base):
    __tablename__ = "bookmarks"
    __table_args__ = (UniqueConstraint("user_id", "workspace_id", "target_type", "target_id", name="uq_bookmark"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    target_type: Mapped[str] = mapped_column(String(24))
    target_id: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
