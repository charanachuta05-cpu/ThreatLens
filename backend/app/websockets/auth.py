from sqlalchemy.orm import Session

from app.services.auth_service import get_user_from_token


def verify_websocket_token(token: str, db: Session):
    """
    Verify the WebSocket JWT token and return the authenticated user.
    Returns None if authentication fails.
    """
    return get_user_from_token(token, db)