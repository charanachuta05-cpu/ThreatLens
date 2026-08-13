from datetime import datetime

from pydantic import BaseModel, ConfigDict


class HuntResult(BaseModel):
    id: int
    indicator_type: str
    value: str
    severity: str
    threat_score: int
    reputation_score: int
    source: str
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )
