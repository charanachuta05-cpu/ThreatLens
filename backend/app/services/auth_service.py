from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User
from app.schemas import user


def get_user_from_token(token: str, db: Session) -> User | None:
    """
    Decode a JWT token and return the authenticated user.
    Returns None if the token is invalid or the user does not exist.
    """

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )

        user_id = payload.get("sub")

        if user_id is None:
            return None

    except JWTError:
        return None

    user = (
        db.query(User)
        .filter(User.id == int(user_id))
        .first()
    )

    print("JWT user_id:", user_id)
    print("DB URL:", settings.DATABASE_URL)
    print("Found user:", user)

    return user