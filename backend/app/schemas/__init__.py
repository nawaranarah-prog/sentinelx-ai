"""Request bodies (validated by Pydantic and documented in OpenAPI)."""

from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

RoleName = Literal["ADMIN", "SOC_ANALYST", "VIEWER"]
IncidentStatus = Literal["NEW", "IN_PROGRESS", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]
Severity = Literal["low", "medium", "high", "critical"]


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    full_name: str = Field(default="", max_length=120)

    @field_validator("full_name")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class ProfileUpdateIn(BaseModel):
    full_name: str | None = Field(default=None, max_length=120)
    theme: Literal["dark", "light", "system"] | None = None


class WorkspaceCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class WorkspaceSettingsIn(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    business_hours: tuple[int, int] | None = None
    correlation_window_minutes: int | None = Field(default=None, ge=5, le=1440)
    anomaly_if_threshold: float | None = Field(default=None, ge=0.4, le=0.9)

    @field_validator("business_hours")
    @classmethod
    def _bh(cls, v):
        if v is not None and not (0 <= v[0] < v[1] <= 24):
            raise ValueError("business_hours must be [start, end] with 0 <= start < end <= 24")
        return v


class MemberCreateIn(BaseModel):
    email: EmailStr
    role: RoleName
    full_name: str = Field(default="", max_length=120)
    password: str | None = Field(default=None, max_length=256)


class MemberUpdateIn(BaseModel):
    role: RoleName


class RuleUpdateIn(BaseModel):
    enabled: bool | None = None
    severity: Severity | None = None
    parameters: dict | None = None


class IncidentStatusIn(BaseModel):
    status: IncidentStatus
    note: str = Field(default="", max_length=2000)


class AssignIn(BaseModel):
    user_id: int | None = None


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)
    kind: Literal["note", "comment"] = "note"


class ChecklistIn(BaseModel):
    index: int = Field(ge=0)
    done: bool


class TagsIn(BaseModel):
    tags: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("tags")
    @classmethod
    def _clean(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(t.strip()[:40] for t in v if t.strip()))


class DetectionStatusIn(BaseModel):
    status: Literal["OPEN", "DISMISSED"]


class IndicatorIn(BaseModel):
    value: str = Field(min_length=1, max_length=255)
    indicator_type: Literal["ip", "domain", "hash", "hostname", "username"] | None = None
    severity: Severity = "medium"
    confidence: float = Field(default=0.7, ge=0, le=1)
    description: str = Field(default="", max_length=2000)
    source: str = Field(default="Analyst submission", max_length=120)
    tags: list[str] = Field(default_factory=list, max_length=20)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: int | None = None
    incident_id: int | None = None


class ReportIn(BaseModel):
    incident_id: int
    report_type: Literal["incident", "technical", "executive"] = "incident"
    include_ai_summary: bool = True


class SavedSearchIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    query: dict = Field(default_factory=dict)


class HostUpdateIn(BaseModel):
    criticality: Literal["low", "medium", "high", "critical"]
