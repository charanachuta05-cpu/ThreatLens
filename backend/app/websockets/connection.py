from dataclasses import dataclass
from fastapi import WebSocket


@dataclass
class Connection:
    websocket: WebSocket
    user_id: int
    username: str
    role: str   