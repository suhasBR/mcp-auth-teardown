"""
Server #1: Static API Key Auth
--------------------------------
The strawman. Zero external dependencies — runs 60 seconds after clone.

Attack surface: one leaked key = full access to ALL tools, ALL users, forever.
No token expiry. No user binding. No audit trail of WHO called it.
Blast radius: unlimited until manual rotation.
"""
import logging
import os

import uvicorn
from dotenv import load_dotenv
from fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from data import PAYMENTS, USERS, add_payment, cancel_payment_by_id

load_dotenv()

API_KEY = os.getenv("MCP_API_KEY", "sk-apikey-demo-1234-definitely-not-a-secret")
PORT = int(os.getenv("SERVER_1_PORT", "8001"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] server-1-apikey | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("server-1-apikey")

mcp = FastMCP("payment-agent-apikey")


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Check X-API-Key header on every request. Audit log every outcome."""

    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("x-api-key", "")
        client = request.client.host if request.client else "unknown"

        if key != API_KEY:
            log.warning(
                "REJECTED | ip=%s path=%s reason=invalid_api_key",
                client,
                request.url.path,
            )
            return JSONResponse({"error": "Unauthorized: invalid or missing X-API-Key"}, status_code=401)

        # Note what's missing from this log: there is no authenticated user identity.
        # We know WHICH key was used, but not WHO is operating the agent or on whose behalf.
        log.info("ACCEPTED | ip=%s path=%s", client, request.url.path)
        return await call_next(request)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_payments(user_id: str) -> dict:
    """List all payments for a user."""
    payments = [p for p in PAYMENTS if p["user_id"] == user_id]
    # Audit gap: we log user_id, but it came from the CALLER — nothing verifies
    # the agent is actually authorized to read this user's data.
    log.info("AUDIT | action=list_payments | user_id=%s | count=%d | auth=api_key", user_id, len(payments))
    return {"user_id": user_id, "payments": payments}


@mcp.tool()
def book_payment(user_id: str, amount: float, to: str, memo: str) -> dict:
    """Book a new payment on behalf of a user."""
    if user_id not in USERS:
        return {"error": f"Unknown user: {user_id!r}"}
    if amount <= 0:
        return {"error": "Amount must be positive"}

    payment = add_payment(user_id, amount, to, memo)
    log.info(
        "AUDIT | action=book_payment | user_id=%s | amount=%.2f | to=%r | payment_id=%s | auth=api_key",
        user_id, amount, to, payment["id"],
    )
    return {"ok": True, "payment": payment}


@mcp.tool()
def cancel_payment(payment_id: str) -> dict:
    """Cancel a pending payment."""
    result = cancel_payment_by_id(payment_id)
    log.info(
        "AUDIT | action=cancel_payment | payment_id=%s | ok=%s | auth=api_key",
        payment_id, result.get("ok"),
    )
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # http_app() returns the underlying Starlette app for streamable-HTTP transport.
    # If you're on an older fastmcp, try sse_app() or get_asgi_app() instead.
    app = mcp.http_app()
    app.add_middleware(APIKeyMiddleware)

    log.info("Server #1 (API key) starting on http://127.0.0.1:%d", PORT)
    log.info("API key loaded from env: %s", "YES" if os.getenv("MCP_API_KEY") else "NO — using insecure default")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
