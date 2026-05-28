from datetime import UTC, datetime
from uuid import uuid4
from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON
from phishwatch.app.db.base import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def uuid_str() -> str:
    return str(uuid4())

JsonType = JSON().with_variant(JSONB, "postgresql")
UuidType = String(36).with_variant(UUID(as_uuid=False), "postgresql")


class Seed(Base):
    __tablename__ = "seeds"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=uuid_str)
    input_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    apex_domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    path: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    variants: Mapped[list["Variant"]] = relationship(back_populates="seed", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="seed", cascade="all, delete-orphan")


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=uuid_str)
    seed_id: Mapped[str | None] = mapped_column(UuidType, ForeignKey("seeds.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    message: Mapped[str] = mapped_column(Text, default="Analysis queued")
    request: Mapped[dict] = mapped_column(JsonType, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Variant(Base):
    __tablename__ = "variants"
    __table_args__ = (UniqueConstraint("seed_id", "fqdn", "attack_family", "attack_rule", name="uq_variant_seed_fqdn_rule"),)
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=uuid_str)
    seed_id: Mapped[str] = mapped_column(UuidType, ForeignKey("seeds.id"), index=True, nullable=False)
    fqdn: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    unicode_fqdn: Mapped[str] = mapped_column(String(255), nullable=False)
    punycode_fqdn: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    tld: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    attack_family: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    attack_rule: Mapped[str] = mapped_column(String(64), nullable=False)
    edit_distance: Mapped[int] = mapped_column(Integer, default=0)
    skeleton: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    seed: Mapped[Seed] = relationship(back_populates="variants")
    observations: Mapped[list["Observation"]] = relationship(back_populates="variant", cascade="all, delete-orphan")
    verifications: Mapped[list["Verification"]] = relationship(back_populates="variant", cascade="all, delete-orphan")
    finding: Mapped["Finding | None"] = relationship(back_populates="variant")


class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=uuid_str)
    variant_id: Mapped[str] = mapped_column(UuidType, ForeignKey("variants.id"), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_event: Mapped[str] = mapped_column(String(128), nullable=False)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict] = mapped_column(JsonType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    variant: Mapped[Variant] = relationship(back_populates="observations")


class Verification(Base):
    __tablename__ = "verifications"
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=uuid_str)
    variant_id: Mapped[str] = mapped_column(UuidType, ForeignKey("variants.id"), index=True, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    dns_status: Mapped[str] = mapped_column(String(32), default="SKIPPED")
    dns_json: Mapped[dict] = mapped_column(JsonType, default=dict)
    tls_status: Mapped[str] = mapped_column(String(32), default="SKIPPED")
    tls_json: Mapped[dict] = mapped_column(JsonType, default=dict)
    http_status: Mapped[str] = mapped_column(String(32), default="SKIPPED")
    http_json: Mapped[dict] = mapped_column(JsonType, default=dict)
    mx_status: Mapped[str] = mapped_column(String(32), default="SKIPPED")
    mx_json: Mapped[dict] = mapped_column(JsonType, default=dict)
    variant: Mapped[Variant] = relationship(back_populates="verifications")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_score", "risk_score"),)
    id: Mapped[str] = mapped_column(UuidType, primary_key=True, default=uuid_str)
    seed_id: Mapped[str] = mapped_column(UuidType, ForeignKey("seeds.id"), index=True, nullable=False)
    variant_id: Mapped[str] = mapped_column(UuidType, ForeignKey("variants.id"), unique=True, index=True, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    factors: Mapped[dict] = mapped_column(JsonType, default=dict)
    explanation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    seed: Mapped[Seed] = relationship(back_populates="findings")
    variant: Mapped[Variant] = relationship(back_populates="finding")
