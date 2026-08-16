"""add indicator relationship to alerts

Revision ID: 302ead1ed564
Revises: bb93a3e18354
Create Date: 2026-08-16 00:01:27.721915

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "302ead1ed564"
down_revision: Union[str, Sequence[str], None] = "bb93a3e18354"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the indicator relationship to alerts."""

    op.add_column(
        "alerts",
        sa.Column(
            "indicator_id",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_alerts_indicator_id",
        "alerts",
        ["indicator_id"],
        unique=False,
    )

    op.create_foreign_key(
        "fk_alerts_indicator_id_indicators",
        "alerts",
        "indicators",
        ["indicator_id"],
        ["id"],
    )


def downgrade() -> None:
    """Temporary no-op downgrade for the previously applied empty revision."""

    pass
