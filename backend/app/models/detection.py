from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base, JSONType, utcnow


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (UniqueConstraint("workspace_id", "rule_key", name="uq_rule_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    rule_key: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    parameters: Mapped[dict] = mapped_column(JSONType, default=dict)
    mitre_techniques: Mapped[list] = mapped_column(JSONType, default=list)
    stage: Mapped[str] = mapped_column(String(48), default="")
    kind: Mapped[str] = mapped_column(String(16), default="builtin")
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class Detection(Base):
    __tablename__ = "detections"
    __table_args__ = (
        UniqueConstraint("workspace_id", "dedupe_key", name="uq_detection_dedupe"),
        Index("ix_detections_ws_ts", "workspace_id", "timestamp"),
        Index("ix_detections_ws_incident", "workspace_id", "incident_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True)
    rule_key: Mapped[str] = mapped_column(String(16), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    host: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    explanation: Mapped[str] = mapped_column(Text)
    evidence_summary: Mapped[dict] = mapped_column(JSONType, default=dict)
    mitre: Mapped[list] = mapped_column(JSONType, default=list)
    false_positives: Mapped[list] = mapped_column(JSONType, default=list)
    recommendations: Mapped[list] = mapped_column(JSONType, default=list)
    stage: Mapped[str] = mapped_column(String(48), default="")
    status: Mapped[str] = mapped_column(String(24), default="OPEN")
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    evidence_links: Mapped[list["DetectionEvent"]] = relationship(cascade="all, delete-orphan")


class DetectionEvent(Base):
    __tablename__ = "detection_events"

    detection_id: Mapped[int] = mapped_column(ForeignKey("detections.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True, index=True)


class AnomalyResult(Base):
    __tablename__ = "anomaly_results"
    __table_args__ = (Index("ix_anomaly_ws_entity", "workspace_id", "entity_type", "entity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    run_id: Mapped[str] = mapped_column(String(40), index=True)
    entity_type: Mapped[str] = mapped_column(String(16))
    entity: Mapped[str] = mapped_column(String(128))
    window_start: Mapped[datetime] = mapped_column(DateTime)
    window_end: Mapped[datetime] = mapped_column(DateTime)
    features: Mapped[dict] = mapped_column(JSONType, default=dict)
    baseline_flags: Mapped[list] = mapped_column(JSONType, default=list)
    top_deviations: Mapped[list] = mapped_column(JSONType, default=list)
    if_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    if_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    if_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    method: Mapped[str] = mapped_column(String(48))
    model_info: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
