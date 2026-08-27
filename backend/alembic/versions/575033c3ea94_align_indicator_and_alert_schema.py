"""align indicator and alert schema

Revision ID: 575033c3ea94
Revises: 302ead1ed564
Create Date: 2026-08-27 08:55:18.429959
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "575033c3ea94"
down_revision: Union[str, Sequence[str], None] = "302ead1ed564"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Align live schema with current SQLAlchemy models."""

    # Existing rows must already have timestamps before enforcing
    # NOT NULL. The pre-migration safety check verifies this.
    op.alter_column(
        "alerts",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )

    op.alter_column(
        "indicators",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )

    # Expand the persisted tag capacity to match the model.
    op.alter_column(
        "indicators",
        "tags",
        existing_type=sa.String(length=500),
        type_=sa.String(length=1000),
        existing_nullable=True,
    )

    # SQLAlchemy's current model represents value uniqueness as a
    # unique index rather than a table-level unique constraint.
    op.drop_constraint(
        "indicators_value_key",
        "indicators",
        type_="unique",
    )

    op.create_index(
        "ix_indicators_value",
        "indicators",
        ["value"],
        unique=True,
    )

    op.create_index(
        "ix_indicators_indicator_type",
        "indicators",
        ["indicator_type"],
        unique=False,
    )

    op.create_index(
        "ix_indicators_severity",
        "indicators",
        ["severity"],
        unique=False,
    )

    op.create_index(
        "ix_indicators_source",
        "indicators",
        ["source"],
        unique=False,
    )


def downgrade() -> None:
    """Restore the previous database schema."""

    op.drop_index(
        "ix_indicators_source",
        table_name="indicators",
    )

    op.drop_index(
        "ix_indicators_severity",
        table_name="indicators",
    )

    op.drop_index(
        "ix_indicators_indicator_type",
        table_name="indicators",
    )

    op.drop_index(
        "ix_indicators_value",
        table_name="indicators",
    )

    op.create_unique_constraint(
        "indicators_value_key",
        "indicators",
        ["value"],
    )

    op.alter_column(
        "indicators",
        "tags",
        existing_type=sa.String(length=1000),
        type_=sa.String(length=500),
        existing_nullable=True,
    )

    op.alter_column(
        "indicators",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
    )

    op.alter_column(
        "alerts",
        "created_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
    )
