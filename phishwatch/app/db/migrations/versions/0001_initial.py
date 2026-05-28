"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-28
"""
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

json_type = postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite")
uuid_type = postgresql.UUID(as_uuid=False).with_variant(sa.String(length=36), "sqlite")


def upgrade() -> None:
    op.create_table("seeds", sa.Column("id", uuid_type, primary_key=True), sa.Column("input_url", sa.Text(), nullable=False), sa.Column("normalized_url", sa.Text(), nullable=False), sa.Column("apex_domain", sa.String(255), nullable=False), sa.Column("hostname", sa.String(255), nullable=False), sa.Column("path", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_seeds_apex_domain", "seeds", ["apex_domain"])
    op.create_index("ix_seeds_hostname", "seeds", ["hostname"])
    op.create_table("analysis_jobs", sa.Column("id", uuid_type, primary_key=True), sa.Column("seed_id", uuid_type, sa.ForeignKey("seeds.id"), nullable=True), sa.Column("status", sa.String(32), nullable=False), sa.Column("message", sa.Text(), nullable=False), sa.Column("request", json_type, nullable=False), sa.Column("error", sa.Text(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_analysis_jobs_status", "analysis_jobs", ["status"])
    op.create_table("variants", sa.Column("id", uuid_type, primary_key=True), sa.Column("seed_id", uuid_type, sa.ForeignKey("seeds.id"), nullable=False), sa.Column("fqdn", sa.String(255), nullable=False), sa.Column("unicode_fqdn", sa.String(255), nullable=False), sa.Column("punycode_fqdn", sa.String(255), nullable=False), sa.Column("tld", sa.String(64), nullable=False), sa.Column("attack_family", sa.String(64), nullable=False), sa.Column("attack_rule", sa.String(64), nullable=False), sa.Column("edit_distance", sa.Integer(), nullable=False), sa.Column("skeleton", sa.String(255), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("seed_id", "fqdn", "attack_family", "attack_rule", name="uq_variant_seed_fqdn_rule"))
    for col in ["seed_id", "fqdn", "punycode_fqdn", "tld", "attack_family", "skeleton"]:
        op.create_index(f"ix_variants_{col}", "variants", [col])
    op.create_table("observations", sa.Column("id", uuid_type, primary_key=True), sa.Column("variant_id", uuid_type, sa.ForeignKey("variants.id"), nullable=False), sa.Column("source", sa.String(64), nullable=False), sa.Column("source_event", sa.String(128), nullable=False), sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True), sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True), sa.Column("raw_ref", sa.Text(), nullable=True), sa.Column("payload", json_type, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_observations_variant_id", "observations", ["variant_id"])
    op.create_index("ix_observations_source", "observations", ["source"])
    op.create_table("verifications", sa.Column("id", uuid_type, primary_key=True), sa.Column("variant_id", uuid_type, sa.ForeignKey("variants.id"), nullable=False), sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False), sa.Column("dns_status", sa.String(32), nullable=False), sa.Column("dns_json", json_type, nullable=False), sa.Column("tls_status", sa.String(32), nullable=False), sa.Column("tls_json", json_type, nullable=False), sa.Column("http_status", sa.String(32), nullable=False), sa.Column("http_json", json_type, nullable=False), sa.Column("mx_status", sa.String(32), nullable=False), sa.Column("mx_json", json_type, nullable=False))
    op.create_index("ix_verifications_variant_id", "verifications", ["variant_id"])
    op.create_table("findings", sa.Column("id", uuid_type, primary_key=True), sa.Column("seed_id", uuid_type, sa.ForeignKey("seeds.id"), nullable=False), sa.Column("variant_id", uuid_type, sa.ForeignKey("variants.id"), nullable=False, unique=True), sa.Column("risk_score", sa.Float(), nullable=False), sa.Column("severity", sa.String(32), nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("factors", json_type, nullable=False), sa.Column("explanation", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    for col in ["seed_id", "variant_id", "severity", "status"]:
        op.create_index(f"ix_findings_{col}", "findings", [col])
    op.create_index("ix_findings_score", "findings", ["risk_score"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("verifications")
    op.drop_table("observations")
    op.drop_table("variants")
    op.drop_table("analysis_jobs")
    op.drop_table("seeds")
