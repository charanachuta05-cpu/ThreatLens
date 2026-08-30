from datetime import datetime

from pydantic import BaseModel, EmailStr, ConfigDict


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AccessRequestResponse(BaseModel):
    id: int
    user_id: int
    username: str
    email: EmailStr
    requested_role: str
    status: str
    reviewed_by: int | None
    created_at: datetime
    reviewed_at: datetime | None


class AccessRequestStatusResponse(BaseModel):
    id: int
    requested_role: str
    status: str
    created_at: datetime
    reviewed_at: datetime | None
