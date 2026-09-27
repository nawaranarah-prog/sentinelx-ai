from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base, JSONType, utcnow


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_format: Mapped[str] = mapped_column(String(16))
    source_label: Mapped[str] = mapped_column(String(64), default="upload")
    status: Mapped[str] = mapped_column(String(24), default="QUEUED")
    stage: Mapped[str] = mapped_column(String(32), default="QUEUED")
    total_rows: Mapped[int] = mapped_column(Integer, default=0)
    processed_rows: Mapped[int] = mapped_column(Integer, default=0)
    accepted_rows: Mapped[int] = mapped_column(Integer, default=0)
    rejected_rows: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_rows: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSONType, default=list)
    warnings: Mapped[list] = mapped_column(JSONType, default=list)
    field_mapping: Mapped[dict] = mapped_column(JSONType, default=dict)
    detections_created: Mapped[int] = mapped_column(Integer, default=0)
    incidents_created: Mapped[int] = mapped_column(Integer, default=0)
    incidents_updated: Mapped[int] = mapped_column(Integer, default=0)
    anomalies_flagged: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("workspace_id", "fingerprint", name="uq_event_fingerprint"),
        Index("ix_events_ws_ts", "workspace_id", "timestamp"),
        Index("ix_events_ws_user", "workspace_id", "user"),
        Index("ix_events_ws_host", "workspace_id", "host"),
        Index("ix_events_ws_src", "workspace_id", "source_ip"),
        Index("ix_events_ws_dst", "workspace_id", "destination_ip"),
        Index("ix_events_ws_type", "workspace_id", "event_type"),
        Index("ix_events_ws_sev", "workspace_id", "severity"),
        Index("ix_events_ws_uid", "workspace_id", "event_uid"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"))
    ingestion_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_uid: Mapped[str] = mapped_column(String(128))
    fingerprint: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    event_type: Mapped[str] = mapped_column(String(32), default="other")
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host: Mapped[str | None] = mapped_column(String(128), nullable=True)
    process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_metadata: Mapped[dict] = mapped_column("metadata", JSONType, default=dict)
    raw: Mapped[dict] = mapped_column(JSONType, default=dict)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("workspace_id", "hostname", name="uq_host"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(128))
    ip_addresses: Mapped[list] = mapped_column(JSONType, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    criticality_source: Mapped[str] = mapped_column(String(16), default="inferred")
    role_hint: Mapped[str] = mapped_column(String(64), default="")


class Asset(Base):
    """Named business resources (file shares, databases, applications) observed in telemetry."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("workspace_id", "name", name="uq_asset"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    asset_type: Mapped[str] = mapped_column(String(32), default="resource")
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
