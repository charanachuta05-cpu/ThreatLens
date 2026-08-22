from types import SimpleNamespace

import pytest

from app.websockets.manager import ConnectionManager


class FakeWebSocket:
    def __init__(self, *, fail_send=False):
        self.accepted = False
        self.messages = []
        self.fail_send = fail_send

    async def accept(self):
        self.accepted = True

    async def send_json(self, message):
        if self.fail_send:
            raise RuntimeError("socket unavailable")

        self.messages.append(message)


@pytest.mark.asyncio
async def test_connect_stores_authenticated_user_metadata():
    manager = ConnectionManager()

    websocket = FakeWebSocket()

    user = SimpleNamespace(
        id=1,
        username="admin",
        role="admin",
    )

    await manager.connect(websocket, user)

    assert websocket.accepted is True
    assert manager.get_connected_users() == [
        {
            "user_id": 1,
            "username": "admin",
            "role": "admin",
        }
    ]


def test_disconnect_removes_connection():
    manager = ConnectionManager()

    websocket = FakeWebSocket()

    manager.active_connections.append(
        SimpleNamespace(
            websocket=websocket,
            user_id=1,
            username="admin",
            role="admin",
        )
    )

    manager.disconnect(websocket)

    assert manager.active_connections == []
    assert manager.get_connected_users() == []


@pytest.mark.asyncio
async def test_broadcast_sends_to_all_connections():
    manager = ConnectionManager()

    first = FakeWebSocket()
    second = FakeWebSocket()

    manager.active_connections.extend(
        [
            SimpleNamespace(
                websocket=first,
                user_id=1,
                username="admin",
                role="admin",
            ),
            SimpleNamespace(
                websocket=second,
                user_id=2,
                username="analyst",
                role="analyst",
            ),
        ]
    )

    message = {
        "type": "alert",
        "alert_id": 100,
    }

    await manager.broadcast(message)

    assert first.messages == [message]
    assert second.messages == [message]


@pytest.mark.asyncio
async def test_send_to_user_targets_only_matching_user():
    manager = ConnectionManager()

    first = FakeWebSocket()
    second = FakeWebSocket()

    manager.active_connections.extend(
        [
            SimpleNamespace(
                websocket=first,
                user_id=1,
                username="admin",
                role="admin",
            ),
            SimpleNamespace(
                websocket=second,
                user_id=2,
                username="analyst",
                role="analyst",
            ),
        ]
    )

    message = {"type": "private-alert"}

    await manager.send_to_user(2, message)

    assert first.messages == []
    assert second.messages == [message]


@pytest.mark.asyncio
async def test_broadcast_to_role_targets_matching_role_only():
    manager = ConnectionManager()

    admin = FakeWebSocket()
    analyst = FakeWebSocket()
    viewer = FakeWebSocket()

    manager.active_connections.extend(
        [
            SimpleNamespace(
                websocket=admin,
                user_id=1,
                username="admin",
                role="admin",
            ),
            SimpleNamespace(
                websocket=analyst,
                user_id=2,
                username="analyst",
                role="analyst",
            ),
            SimpleNamespace(
                websocket=viewer,
                user_id=3,
                username="viewer",
                role="viewer",
            ),
        ]
    )

    message = {"type": "analyst-alert"}

    await manager.broadcast_to_role("analyst", message)

    assert admin.messages == []
    assert analyst.messages == [message]
    assert viewer.messages == []


@pytest.mark.asyncio
async def test_broadcast_to_roles_targets_any_matching_role():
    manager = ConnectionManager()

    admin = FakeWebSocket()
    analyst = FakeWebSocket()
    viewer = FakeWebSocket()

    manager.active_connections.extend(
        [
            SimpleNamespace(
                websocket=admin,
                user_id=1,
                username="admin",
                role="admin",
            ),
            SimpleNamespace(
                websocket=analyst,
                user_id=2,
                username="analyst",
                role="analyst",
            ),
            SimpleNamespace(
                websocket=viewer,
                user_id=3,
                username="viewer",
                role="viewer",
            ),
        ]
    )

    message = {"type": "security-alert"}

    await manager.broadcast_to_roles(
        ["admin", "analyst"],
        message,
    )

    assert admin.messages == [message]
    assert analyst.messages == [message]
    assert viewer.messages == []


@pytest.mark.asyncio
async def test_broadcast_removes_failed_connections():
    manager = ConnectionManager()

    healthy = FakeWebSocket()
    failed = FakeWebSocket(fail_send=True)

    manager.active_connections.extend(
        [
            SimpleNamespace(
                websocket=healthy,
                user_id=1,
                username="admin",
                role="admin",
            ),
            SimpleNamespace(
                websocket=failed,
                user_id=2,
                username="analyst",
                role="analyst",
            ),
        ]
    )

    message = {"type": "alert"}

    await manager.broadcast(message)

    assert healthy.messages == [message]
    assert failed not in [
        connection.websocket
        for connection in manager.active_connections
    ]

    assert manager.get_connected_users() == [
        {
            "user_id": 1,
            "username": "admin",
            "role": "admin",
        }
    ]


@pytest.mark.asyncio
async def test_send_to_user_removes_failed_connection():
    manager = ConnectionManager()

    failed = FakeWebSocket(fail_send=True)

    manager.active_connections.append(
        SimpleNamespace(
            websocket=failed,
            user_id=2,
            username="analyst",
            role="analyst",
        )
    )

    await manager.send_to_user(
        2,
        {"type": "alert"},
    )

    assert manager.active_connections == []


@pytest.mark.asyncio
async def test_broadcast_to_role_removes_failed_connection():
    manager = ConnectionManager()

    failed = FakeWebSocket(fail_send=True)

    manager.active_connections.append(
        SimpleNamespace(
            websocket=failed,
            user_id=2,
            username="analyst",
            role="analyst",
        )
    )

    await manager.broadcast_to_role(
        "analyst",
        {"type": "alert"},
    )

    assert manager.active_connections == []


@pytest.mark.asyncio
async def test_broadcast_to_roles_removes_failed_connection():
    manager = ConnectionManager()

    failed = FakeWebSocket(fail_send=True)

    manager.active_connections.append(
        SimpleNamespace(
            websocket=failed,
            user_id=2,
            username="analyst",
            role="analyst",
        )
    )

    await manager.broadcast_to_roles(
        ["admin", "analyst"],
        {"type": "alert"},
    )

    assert manager.active_connections == []
