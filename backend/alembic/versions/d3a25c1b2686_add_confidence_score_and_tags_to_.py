"""add confidence score and tags to indicators

Revision ID: d3a25c1b2686
Revises: a1357699d25f
Create Date: 2026-08-08 20:14:57.146161
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d3a25c1b2686"
down_revision: Union[str, Sequence[str], None] = "a1357699d25f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add confidence score and tags to indicators."""

    op.add_column(
        "indicators",
        sa.Column(
            "confidence_score",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.add_column(
        "indicators",
        sa.Column(
            "tags",
            sa.String(length=500),
            nullable=True,
        ),
    )

    # Remove the temporary server default after existing rows
    # have been populated with 0.
    op.alter_column(
        "indicators",
        "confidence_score",
        server_default=None,
    )


def downgrade() -> None:
    """Remove confidence score and tags from indicators."""

    op.drop_column("indicators", "tags")
    op.drop_column("indicators", "confidence_score")