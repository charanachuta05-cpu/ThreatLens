from enum import Enum

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.sql import func

from app.core.database import Base


class IndicatorType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    indicator_type = Column(
        String(20),
        nullable=False,
        index=True,
    )

    value = Column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )

    severity = Column(
        String(20),
        nullable=False,
        index=True,
    )

    threat_score = Column(
        Integer,
        nullable=False,
        default=10,
    )

    reputation_score = Column(
        Integer,
        nullable=False,
        default=0,
    )

    confidence_score = Column(
        Integer,
        nullable=False,
        default=0,
    )

    source = Column(
        String(100),
        nullable=False,
        index=True,
    )

    description = Column(
        String(500),
        nullable=True,
    )

    tags = Column(
        String(1000),
        nullable=True,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )