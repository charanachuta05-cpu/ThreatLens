from enum import Enum

from sqlalchemy import (
    Column,
    DateTime,
    Enum as SqlEnum,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class IncidentPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentResolutionType(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN = "BENIGN"
    DUPLICATE = "DUPLICATE"


incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column(
        "incident_id",
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "alert_id",
        Integer,
        ForeignKey("alerts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


incident_indicators = Table(
    "incident_indicators",
    Base.metadata,
    Column(
        "incident_id",
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "indicator_id",
        Integer,
        ForeignKey("indicators.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    title = Column(
        String(255),
        nullable=False,
    )

    description = Column(
        Text,
        nullable=False,
    )

    priority = Column(
        SqlEnum(IncidentPriority),
        nullable=False,
        default=IncidentPriority.MEDIUM,
        index=True,
    )

    status = Column(
        SqlEnum(IncidentStatus),
        nullable=False,
        default=IncidentStatus.OPEN,
        index=True,
    )

    created_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    assigned_to = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    resolved_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )


    resolution_type = Column(
        SqlEnum(IncidentResolutionType),
        nullable=True,
        index=True,
    )

    resolution_summary = Column(
        Text,
        nullable=True,
    )

    resolved_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    creator = relationship(
        "User",
        foreign_keys=[created_by],
    )

    assignee = relationship(
        "User",
        foreign_keys=[assigned_to],
    )


    resolver = relationship(
        "User",
        foreign_keys=[resolved_by],
    )

    alerts = relationship(
        "Alert",
        secondary=incident_alerts,
    )

    indicators = relationship(
        "Indicator",
        secondary=incident_indicators,
    )

    notes = relationship(
        "IncidentNote",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentNote.created_at",
    )


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    incident_id = Column(
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    author_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    content = Column(
        Text,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    incident = relationship(
        "Incident",
        back_populates="notes",
    )

    author = relationship(
        "User",
        foreign_keys=[author_id],
    )
