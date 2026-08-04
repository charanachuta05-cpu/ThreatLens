from jose import JWTError, jwt

from app.core.config import settings


def verify_websocket_token(token: str) -> dict:
    """
    Verify JWT token used for WebSocket authentication.
    Returns the decoded payload.
    """

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )

        return payload

    except JWTError:
        return None