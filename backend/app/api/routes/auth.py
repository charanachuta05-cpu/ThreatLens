from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.schemas.user import (
    UserCreate,
    UserLogin,
    UserResponse,
    TokenResponse,
)

from app.core.security import (
    verify_password,
    create_access_token,
)

from app.services.user_service import (
    create_user,
    get_user_by_email,
    get_user_by_username,
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# -------------------------
# User Registration
# -------------------------

@router.post(
    "/register",
    response_model=UserResponse
)
def register_user(
    user: UserCreate,
    db: Session = Depends(get_db)
):

    existing_email = get_user_by_email(
        db,
        user.email
    )

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )


    existing_username = get_user_by_username(
        db,
        user.username
    )

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )


    return create_user(
        db,
        user
    )


# -------------------------
# User Login
# -------------------------

@router.post(
    "/login",
    response_model=TokenResponse
)
def login_user(
    user: UserLogin,
    db: Session = Depends(get_db)
):

    db_user = get_user_by_email(
        db,
        user.email
    )

    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )


    if not verify_password(
        user.password,
        db_user.hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )


    access_token = create_access_token(
        {
            "sub": str(db_user.id),
            "email": db_user.email,
            "role": db_user.role,
        }
    )


    return {
        "access_token": access_token,
        "token_type": "bearer"
    }