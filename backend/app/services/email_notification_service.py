import logging
from datetime import datetime
from html import escape

import httpx

from app.core.config import settings
from app.models.access_request import AccessRequest
from app.models.user import User


logger = logging.getLogger("ThreatLens")


def _format_timestamp(value: datetime) -> str:
    return value.strftime("%d %b %Y, %H:%M UTC")


def _build_access_request_email(
    request: AccessRequest,
    user: User,
) -> str:
    username = escape(user.username)
    email = escape(user.email)
    requested_role = escape(
        request.requested_role.title()
    )
    request_id = escape(str(request.id))
    timestamp = escape(
        _format_timestamp(request.created_at)
    )

    review_url = (
        settings.FRONTEND_URL.rstrip("/")
        + "/settings"
    )

    review_url = escape(
        review_url,
        quote=True,
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >
  <title>ThreatLens Access Request</title>
</head>

<body
  style="
    margin:0;
    padding:0;
    background:#07111f;
    font-family:
      -apple-system,
      BlinkMacSystemFont,
      'Segoe UI',
      Arial,
      sans-serif;
    color:#e5edf7;
  "
>
  <table
    role="presentation"
    width="100%"
    cellspacing="0"
    cellpadding="0"
    border="0"
    style="
      width:100%;
      background:#07111f;
      padding:32px 16px;
    "
  >
    <tr>
      <td align="center">

        <table
          role="presentation"
          width="600"
          cellspacing="0"
          cellpadding="0"
          border="0"
          style="
            width:100%;
            max-width:600px;
            background:#0d1828;
            border:1px solid #1d344d;
            border-radius:14px;
            overflow:hidden;
          "
        >

          <tr>
            <td
              style="
                padding:24px 28px;
                background:#10243a;
                border-bottom:1px solid #1d344d;
              "
            >
              <div
                style="
                  font-size:22px;
                  font-weight:700;
                  color:#f8fafc;
                "
              >
                ThreatLens
              </div>

              <div
                style="
                  margin-top:5px;
                  font-size:12px;
                  color:#7dd3fc;
                  letter-spacing:.08em;
                  text-transform:uppercase;
                "
              >
                Security Operations Center
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:30px 28px 10px">

              <div
                style="
                  display:inline-block;
                  padding:6px 10px;
                  border-radius:999px;
                  background:#382b0c;
                  color:#fbbf24;
                  font-size:11px;
                  font-weight:700;
                  letter-spacing:.05em;
                  text-transform:uppercase;
                "
              >
                Administrator Action Required
              </div>

              <h1
                style="
                  margin:18px 0 10px;
                  font-size:24px;
                  line-height:1.3;
                  color:#f8fafc;
                "
              >
                New Analyst Access Request
              </h1>

              <p
                style="
                  margin:0;
                  color:#94a3b8;
                  font-size:14px;
                  line-height:1.7;
                "
              >
                A ThreatLens user has requested
                elevated Analyst permissions and
                is waiting for administrator review.
              </p>

            </td>
          </tr>

          <tr>
            <td style="padding:18px 28px">

              <table
                role="presentation"
                width="100%"
                cellspacing="0"
                cellpadding="0"
                border="0"
                style="
                  background:#081321;
                  border:1px solid #1d344d;
                  border-radius:10px;
                "
              >

                <tr>
                  <td
                    style="
                      padding:14px 16px;
                      color:#64748b;
                      font-size:12px;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    Requester
                  </td>

                  <td
                    align="right"
                    style="
                      padding:14px 16px;
                      color:#e2e8f0;
                      font-size:13px;
                      font-weight:600;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    {username}
                  </td>
                </tr>

                <tr>
                  <td
                    style="
                      padding:14px 16px;
                      color:#64748b;
                      font-size:12px;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    Email
                  </td>

                  <td
                    align="right"
                    style="
                      padding:14px 16px;
                      color:#e2e8f0;
                      font-size:13px;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    {email}
                  </td>
                </tr>

                <tr>
                  <td
                    style="
                      padding:14px 16px;
                      color:#64748b;
                      font-size:12px;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    Requested Role
                  </td>

                  <td
                    align="right"
                    style="
                      padding:14px 16px;
                      color:#7dd3fc;
                      font-size:13px;
                      font-weight:700;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    {requested_role}
                  </td>
                </tr>

                <tr>
                  <td
                    style="
                      padding:14px 16px;
                      color:#64748b;
                      font-size:12px;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    Request ID
                  </td>

                  <td
                    align="right"
                    style="
                      padding:14px 16px;
                      color:#e2e8f0;
                      font-size:13px;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    #{request_id}
                  </td>
                </tr>

                <tr>
                  <td
                    style="
                      padding:14px 16px;
                      color:#64748b;
                      font-size:12px;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    Status
                  </td>

                  <td
                    align="right"
                    style="
                      padding:14px 16px;
                      color:#fbbf24;
                      font-size:13px;
                      font-weight:700;
                      border-bottom:1px solid #172a3e;
                    "
                  >
                    Pending
                  </td>
                </tr>

                <tr>
                  <td
                    style="
                      padding:14px 16px;
                      color:#64748b;
                      font-size:12px;
                    "
                  >
                    Submitted
                  </td>

                  <td
                    align="right"
                    style="
                      padding:14px 16px;
                      color:#e2e8f0;
                      font-size:13px;
                    "
                  >
                    {timestamp}
                  </td>
                </tr>

              </table>

            </td>
          </tr>

          <tr>
            <td
              align="center"
              style="padding:8px 28px 28px"
            >

              <a
                href="{review_url}"
                style="
                  display:inline-block;
                  padding:12px 22px;
                  background:#0284c7;
                  color:#ffffff;
                  text-decoration:none;
                  border-radius:8px;
                  font-size:13px;
                  font-weight:700;
                "
              >
                Review Access Request
              </a>

            </td>
          </tr>

          <tr>
            <td
              style="
                padding:20px 28px;
                background:#081321;
                border-top:1px solid #1d344d;
                color:#64748b;
                font-size:11px;
                line-height:1.6;
              "
            >
              This is an automated security
              notification from ThreatLens.
              Analyst access is not granted until
              an administrator explicitly approves
              the request inside ThreatLens.
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>
</body>
</html>
"""


def send_analyst_access_request_email(
    request: AccessRequest,
    user: User,
) -> bool:
    """
    Notify the ThreatLens administrator about a
    newly-created Analyst access request.

    Email delivery is best-effort and must never
    determine whether the access request succeeds.
    """

    if not settings.EMAIL_NOTIFICATIONS_ENABLED:
        return False

    # Never send real external email from pytest.
    if settings.APP_ENV == "test":
        return False

    if (
        not settings.RESEND_API_KEY
        or not settings.ACCESS_REQUEST_ADMIN_EMAIL
        or not settings.EMAIL_FROM
    ):
        logger.warning(
            "Access request email skipped because "
            "email configuration is incomplete."
        )
        return False

    payload = {
        "from": settings.EMAIL_FROM,
        "to": [
            settings.ACCESS_REQUEST_ADMIN_EMAIL
        ],
        "subject": (
            "ThreatLens Security | "
            "New Analyst Access Request"
        ),
        "html": _build_access_request_email(
            request,
            user,
        ),
        "tags": [
            {
                "name": "category",
                "value": "analyst_access_request",
            },
            {
                "name": "request_id",
                "value": str(request.id),
            },
        ],
    }

    try:
        with httpx.Client(
            timeout=settings.EMAIL_TIMEOUT_SECONDS
        ) as client:
            response = client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": (
                        "Bearer "
                        f"{settings.RESEND_API_KEY}"
                    ),
                    "Content-Type":
                        "application/json",
                },
                json=payload,
            )

            response.raise_for_status()

        logger.info(
            "Analyst access request email sent "
            "for request_id=%s",
            request.id,
        )

        return True

    except (
        httpx.HTTPError,
        ValueError,
    ) as exc:
        logger.warning(
            "Analyst access request email "
            "delivery failed for request_id=%s: %s",
            request.id,
            type(exc).__name__,
        )

        return False
