from uuid import uuid4

import pytest

from app.core.database import SessionLocal
from app.core.security import create_access_token, hash_password
from app.models.access_request import AccessRequest
from app.models.audit import AuditEvent
from app.models.user import User


TEST_PREFIX = "access_request_test_"


def make_headers(
    user_id: int,
    email: str,
    role: str,
) -> dict[str, str]:
    token = create_access_token(
        {
            "sub": str(user_id),
            "email": email,
            "role": role,
        }
    )

    return {
        "Authorization": f"Bearer {token}",
    }


def create_test_user(
    role: str = "viewer",
) -> tuple[int, str, dict[str, str]]:
    unique = uuid4().hex[:10]
    username = f"{TEST_PREFIX}{unique}"
    email = f"{username}@example.com"

    db = SessionLocal()

    try:
        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(
                "Password123!"
            ),
            role=role,
            is_active=True,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        user_id = user.id

    finally:
        db.close()

    return (
        user_id,
        email,
        make_headers(
            user_id,
            email,
            role,
        ),
    )


def cleanup_user(
    user_id: int,
) -> None:
    db = SessionLocal()

    try:
        db.query(AccessRequest).filter(
            AccessRequest.user_id == user_id
        ).delete(
            synchronize_session=False
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == f"user:{user_id}",
            AuditEvent.action.in_(
                (
                    "REQUEST_ANALYST_ACCESS",
                    "APPROVE_ANALYST_ACCESS",
                    "REJECT_ANALYST_ACCESS",
                )
            ),
        ).delete(
            synchronize_session=False
        )

        db.query(User).filter(
            User.id == user_id
        ).delete(
            synchronize_session=False
        )

        db.commit()

    finally:
        db.close()


@pytest.fixture
def viewer_user():
    user_id, email, headers = create_test_user(
        "viewer"
    )

    try:
        yield user_id, email, headers
    finally:
        cleanup_user(user_id)


@pytest.fixture
def analyst_user():
    user_id, email, headers = create_test_user(
        "analyst"
    )

    try:
        yield user_id, email, headers
    finally:
        cleanup_user(user_id)


def test_viewer_can_request_analyst_access(
    client,
    viewer_user,
):
    user_id, email, headers = viewer_user

    response = client.post(
        "/users/access-requests",
        headers=headers,
    )

    assert response.status_code == 201

    data = response.json()

    assert data["user_id"] == user_id
    assert data["email"] == email
    assert data["requested_role"] == "analyst"
    assert data["status"] == "pending"
    assert data["reviewed_by"] is None
    assert data["reviewed_at"] is None


def test_viewer_can_read_own_request_status(
    client,
    viewer_user,
):
    _, _, headers = viewer_user

    create_response = client.post(
        "/users/access-requests",
        headers=headers,
    )

    assert create_response.status_code == 201

    response = client.get(
        "/users/access-requests/me",
        headers=headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["requested_role"] == "analyst"
    assert data["status"] == "pending"
    assert data["reviewed_at"] is None


def test_viewer_without_request_gets_null_status(
    client,
    viewer_user,
):
    _, _, headers = viewer_user

    response = client.get(
        "/users/access-requests/me",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json() is None


def test_duplicate_pending_request_is_blocked(
    client,
    viewer_user,
):
    _, _, headers = viewer_user

    first = client.post(
        "/users/access-requests",
        headers=headers,
    )

    assert first.status_code == 201

    second = client.post(
        "/users/access-requests",
        headers=headers,
    )

    assert second.status_code == 409


def test_viewer_cannot_read_admin_request_queue(
    client,
    viewer_user,
):
    _, _, headers = viewer_user

    response = client.get(
        "/users/access-requests/pending",
        headers=headers,
    )

    assert response.status_code == 403


def test_analyst_cannot_read_admin_request_queue(
    client,
    analyst_user,
):
    _, _, headers = analyst_user

    response = client.get(
        "/users/access-requests/pending",
        headers=headers,
    )

    assert response.status_code == 403


def test_admin_can_see_pending_request(
    client,
    admin_headers,
    viewer_user,
):
    user_id, email, viewer_headers = viewer_user

    create_response = client.post(
        "/users/access-requests",
        headers=viewer_headers,
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    response = client.get(
        "/users/access-requests/pending",
        headers=admin_headers,
    )

    assert response.status_code == 200

    requests = response.json()

    match = next(
        (
            request
            for request in requests
            if request["id"] == request_id
        ),
        None,
    )

    assert match is not None
    assert match["user_id"] == user_id
    assert match["email"] == email
    assert match["requested_role"] == "analyst"
    assert match["status"] == "pending"


def test_admin_can_approve_analyst_request(
    client,
    admin_headers,
    viewer_user,
):
    user_id, _, viewer_headers = viewer_user

    create_response = client.post(
        "/users/access-requests",
        headers=viewer_headers,
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    response = client.post(
        f"/users/access-requests/{request_id}/approve",
        headers=admin_headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "approved"
    assert data["requested_role"] == "analyst"
    assert data["reviewed_by"] is not None
    assert data["reviewed_at"] is not None

    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )

        request = (
            db.query(AccessRequest)
            .filter(
                AccessRequest.id == request_id
            )
            .first()
        )

        assert user is not None
        assert user.role == "analyst"

        assert request is not None
        assert request.status == "approved"

        audit = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.action
                == "APPROVE_ANALYST_ACCESS",
                AuditEvent.target
                == f"user:{user_id}",
            )
            .first()
        )

        assert audit is not None

    finally:
        db.close()


def test_reviewed_request_cannot_be_approved_twice(
    client,
    admin_headers,
    viewer_user,
):
    _, _, viewer_headers = viewer_user

    create_response = client.post(
        "/users/access-requests",
        headers=viewer_headers,
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    first = client.post(
        f"/users/access-requests/{request_id}/approve",
        headers=admin_headers,
    )

    assert first.status_code == 200

    second = client.post(
        f"/users/access-requests/{request_id}/approve",
        headers=admin_headers,
    )

    assert second.status_code == 409


def test_admin_can_reject_analyst_request(
    client,
    admin_headers,
    viewer_user,
):
    user_id, _, viewer_headers = viewer_user

    create_response = client.post(
        "/users/access-requests",
        headers=viewer_headers,
    )

    assert create_response.status_code == 201

    request_id = create_response.json()["id"]

    response = client.post(
        f"/users/access-requests/{request_id}/reject",
        headers=admin_headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "rejected"
    assert data["reviewed_by"] is not None
    assert data["reviewed_at"] is not None

    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )

        assert user is not None
        assert user.role == "viewer"

        audit = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.action
                == "REJECT_ANALYST_ACCESS",
                AuditEvent.target
                == f"user:{user_id}",
            )
            .first()
        )

        assert audit is not None

    finally:
        db.close()


def test_analyst_cannot_request_analyst_access(
    client,
    analyst_user,
):
    _, _, headers = analyst_user

    response = client.post(
        "/users/access-requests",
        headers=headers,
    )

    assert response.status_code == 400


def test_admin_cannot_request_analyst_access(
    client,
    admin_headers,
):
    response = client.post(
        "/users/access-requests",
        headers=admin_headers,
    )

    assert response.status_code == 400


def test_unauthenticated_user_cannot_request_access(
    client,
):
    response = client.post(
        "/users/access-requests"
    )

    assert response.status_code == 401
