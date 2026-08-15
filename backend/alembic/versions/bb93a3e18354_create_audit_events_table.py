"""create audit events table

Revision ID: bb93a3e18354
Revises: d3a25c1b2686
Create Date: 2026-08-15 19:21:35.368761
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "bb93a3e18354"
down_revision: Union[str, Sequence[str], None] = "d3a25c1b2686"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the persistent security audit trail."""

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_audit_events_action",
        "audit_events",
        ["action"],
        unique=False,
    )

    op.create_index(
        "ix_audit_events_actor",
        "audit_events",
        ["actor"],
        unique=False,
    )

    op.create_index(
        "ix_audit_events_created_at",
        "audit_events",
        ["created_at"],
        unique=False,
    )

    op.create_index(
        "ix_audit_events_id",
        "audit_events",
        ["id"],
        unique=False,
    )

    op.create_index(
        "ix_audit_events_target",
        "audit_events",
        ["target"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the persistent security audit trail."""

    op.drop_index("ix_audit_events_target", table_name="audit_events")
    op.drop_index("ix_audit_events_id", table_name="audit_events")
    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_actor", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_table("audit_events")
