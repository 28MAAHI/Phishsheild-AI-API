"""Initial schema: sources, phishing_urls, url_sightings, collection_runs.

Revision ID: 0001
Revises:
Create Date: 2026-10-07
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

BigId = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
SmallId = sa.SmallInteger().with_variant(sa.Integer(), "sqlite")
Json = sa.JSON().with_variant(JSONB(), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "sources",
        sa.Column("id", SmallId, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("homepage", sa.String(512)),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "phishing_urls",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("url_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("scheme", sa.String(5), nullable=False),
        sa.Column("hostname", sa.String(253), nullable=False),
        sa.Column("domain", sa.String(253)),
        sa.Column("registered_domain", sa.String(253)),
        sa.Column("tld", sa.String(63)),
        sa.Column("port", sa.Integer()),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("is_ip", sa.Boolean(), nullable=False),
        sa.Column("threat_type", sa.String(64)),
        sa.Column("confidence", sa.Numeric(4, 3)),
        sa.Column("status", sa.String(32)),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
                           name="ck_phishing_urls_confidence"),
    )
    for col in ("hostname", "domain", "registered_domain", "threat_type", "status", "first_seen", "last_seen",
                "created_at"):
        op.create_index(f"ix_phishing_urls_{col}", "phishing_urls", [col])

    op.create_table(
        "url_sightings",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("url_id", BigId, sa.ForeignKey("phishing_urls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", SmallId, sa.ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source_reference", sa.String(128)),
        sa.Column("threat_type", sa.String(64)),
        sa.Column("confidence", sa.Numeric(4, 3)),
        sa.Column("status", sa.String(32)),
        sa.Column("tags", Json),
        sa.Column("source_first_seen", TS),
        sa.Column("first_collected_at", TS, nullable=False),
        sa.Column("last_collected_at", TS, nullable=False),
        sa.Column("source_metadata", Json),
        sa.UniqueConstraint("url_id", "source_id", name="uq_url_sightings_url_source"),
        sa.CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)",
                           name="ck_url_sightings_confidence"),
    )
    op.create_index("ix_url_sightings_source_id", "url_sightings", ["source_id"])
    op.create_index("ix_url_sightings_threat_type", "url_sightings", ["threat_type"])
    op.create_index("ix_url_sightings_last_collected_at", "url_sightings", ["last_collected_at"])

    op.create_table(
        "collection_runs",
        sa.Column("id", BigId, primary_key=True),
        sa.Column("source_id", SmallId, sa.ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("finished_at", TS),
        sa.Column("records_received", sa.Integer(), nullable=False),
        sa.Column("records_valid", sa.Integer(), nullable=False),
        sa.Column("records_invalid", sa.Integer(), nullable=False),
        sa.Column("records_duplicate_in_feed", sa.Integer(), nullable=False),
        sa.Column("records_new", sa.Integer(), nullable=False),
        sa.Column("records_existing", sa.Integer(), nullable=False),
        sa.Column("error_type", sa.String(64)),
        sa.Column("error_message", sa.Text()),
        sa.Column("details", Json),
        sa.CheckConstraint("status IN ('running','succeeded','failed','skipped')", name="ck_collection_runs_status"),
    )
    op.create_index("ix_collection_runs_source_started", "collection_runs", ["source_id", "started_at"])
    op.create_index("ix_collection_runs_status", "collection_runs", ["status"])


def downgrade() -> None:
    op.drop_table("collection_runs")
    op.drop_table("url_sightings")
    op.drop_table("phishing_urls")
    op.drop_table("sources")
