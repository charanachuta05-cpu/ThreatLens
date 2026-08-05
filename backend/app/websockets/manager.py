from fastapi import WebSocket

from app.models.user import User
from app.websockets.connection import Connection


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[Connection] = []

    async def connect(
        self,
        websocket: WebSocket,
        user: User,
    ):
        await websocket.accept()

        connection = Connection(
            websocket=websocket,
            user_id=user.id,
            username=user.username,
            role=user.role,
        )

        self.active_connections.append(connection)

    def disconnect(self, websocket: WebSocket):
        self.active_connections = [
            connection
            for connection in self.active_connections
            if connection.websocket != websocket
        ]

    async def broadcast(
        self,
        message: dict,
    ):
        """
        Send a message to all connected users.
        """

        disconnected = []

        for connection in self.active_connections:
            try:
                await connection.websocket.send_json(message)

            except Exception:
                disconnected.append(connection.websocket)

        for websocket in disconnected:
            self.disconnect(websocket)

    async def send_to_user(
        self,
        user_id: int,
        message: dict,
    ):
        """
        Send a message to a specific connected user.
        """

        for connection in self.active_connections:

            if connection.user_id == user_id:
                try:
                    await connection.websocket.send_json(message)

                except Exception:
                    self.disconnect(connection.websocket)

                break

    async def broadcast_to_role(
        self,
        role: str,
        message: dict,
    ):
        """
        Send a message to all users with a specific role.
        """

        disconnected = []

        for connection in self.active_connections:

            if connection.role != role:
                continue

            try:
                await connection.websocket.send_json(message)

            except Exception:
                disconnected.append(connection.websocket)

        for websocket in disconnected:
            self.disconnect(websocket)

    async def broadcast_to_roles(
        self,
        roles: list[str],
        message: dict,
    ):
        """
        Send a message to users matching any role.
        """

        disconnected = []

        for connection in self.active_connections:

            if connection.role not in roles:
                continue

            try:
                await connection.websocket.send_json(message)

            except Exception:
                disconnected.append(connection.websocket)

        for websocket in disconnected:
            self.disconnect(websocket)

    def get_connected_users(self):
        """
        Return metadata of currently connected users.
        """

        return [
            {
                "user_id": connection.user_id,
                "username": connection.username,
                "role": connection.role,
            }
            for connection in self.active_connections
        ]


manager = ConnectionManager()