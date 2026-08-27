from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User


def get_user_from_token(token: str, db: Session) -> User | None:
    """
    Decode a JWT token and return the authenticated active user.
    Returns None if the token is invalid, malformed, expired,
    the user does not exist, or the user is inactive.
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

        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            return None

    except JWTError:
        return None

    return (
        db.query(User)
        .filter(
            User.id == user_id,
            User.is_active.is_(True),
        )
        .first()
    )
