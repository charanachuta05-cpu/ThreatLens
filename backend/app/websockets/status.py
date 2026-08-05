from fastapi import APIRouter

from app.websockets.manager import manager


router = APIRouter(
    prefix="/ws",
    tags=["WebSocket"],
)


@router.get("/users")
def connected_users():
    return manager.get_connected_users()