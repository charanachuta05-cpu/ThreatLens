"""remove legacy threat indicators table

Revision ID: 3df2d6c13c10
Revises: 575033c3ea94
Create Date: 2026-08-27
"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "3df2d6c13c10"
down_revision: Union[str, Sequence[str], None] = "575033c3ea94"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Remove the obsolete legacy threat_indicators table."""
    op.drop_table("threat_indicators")


def downgrade() -> None:
    """Restore the legacy threat_indicators table."""
    op.create_table(
        "threat_indicators",
        # Original table definition.
        # This downgrade exists for migration reversibility.
        op.Column("id", op.Integer(), nullable=False),
        op.Column("indicator_type", op.String(length=50), nullable=False),
        op.Column("value", op.String(length=255), nullable=False),
        op.Column("severity", op.String(length=20), nullable=True),
        op.Column("source", op.String(length=100), nullable=False),
        op.Column("description", op.Text(), nullable=True),
        op.Column("created_at", op.DateTime(), nullable=True),
        op.Column("updated_at", op.DateTime(), nullable=True),
        op.PrimaryKeyConstraint("id"),
        op.UniqueConstraint("value"),
    )

    op.create_index(
        "ix_threat_indicators_id",
        "threat_indicators",
        ["id"],
        unique=False,
    )

    op.create_index(
        "ix_threat_indicators_value",
        "threat_indicators",
        ["value"],
        unique=True,
    )