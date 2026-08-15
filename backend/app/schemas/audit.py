from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    id: int
    action: str
    actor: str
    target: str
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )
