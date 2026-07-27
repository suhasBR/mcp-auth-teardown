"""
Server #2: OAuth Proxy (FastMCP Auth0Provider) — hardened
----------------------------------------------------------
Pattern: FastMCP holds a confidential Auth0 application credential and acts
as an OAuth proxy. MCP clients authenticate through FastMCP, which bridges
the OIDC flow to Auth0. FastMCP issues its own short-lived JWTs to clients.

Hardening applied vs a naive proxy implementation:
  ✓ Short token lifetime (1h via fastmcp_access_token_expiry_seconds)
  ✓ sub ↔ user_id binding on every tool call (prevents confused deputy)
  ✓ sub is sourced from the upstream Auth0 JWT via get_access_token().claims
  ✓ Audit log includes the Auth0 sub on every action

Architectural limits that REMAIN even with all hardening applied:
  ✗ Server holds the Auth0 app secret. Server compromise = attacker can
    impersonate the OAuth application and intercept consent flows.
    Blast radius is the entire Auth0 application, not one user session.
  ✗ FastMCP issues its OWN JWTs to MCP clients (HS256, no sub on the wire).
    User identity is only available via FastMCP's server-side session state —
    NOT from the incoming token itself. A stateless validator cannot verify
    the user without talking to this server.
  ✗ Auth0's audit log shows "application authorized" — it does NOT record
    individual tool calls or parameters. The tool-level trail lives only here.
  ✗ Downstream calls carry the FastMCP credential, not the user's Auth0 token.
    RFC 8693 token exchange (Server #3) is required for a proper delegation chain.

Run:
    cp .env.example .env   # fill in your Auth0 values
    pip install -r requirements.txt
    python server.py
"""
import logging
import os
import sys

import uvicorn
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.auth0 import Auth0Provider
from fastmcp.server.dependencies import get_access_token
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from data import PAYMENTS, USERS, add_payment, cancel_payment_by_id

load_dotenv()

AUTH0_DOMAIN        = os.getenv("AUTH0_DOMAIN", "")
AUTH0_CLIENT_ID     = os.getenv("AUTH0_CLIENT_ID", "")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET", "")
AUTH0_AUDIENCE      = os.getenv("AUTH0_AUDIENCE", "")
PORT     = int(os.getenv("SERVER_2_PORT", "8002"))
BASE_URL = f"http://127.0.0.1:{PORT}"

if not all([AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_AUDIENCE]):
    sys.exit(
        "Missing required Auth0 env vars.\n"
        "Copy .env.example → .env and fill in:\n"
        "  AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_AUDIENCE"
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] server-2-proxy | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("server-2-proxy")

# fastmcp_access_token_expiry_seconds: issue 1h FastMCP tokens instead of
# mirroring Auth0's 24h default. Reduces replay window without touching Auth0.
auth = Auth0Provider(
    config_url=f"https://{AUTH0_DOMAIN}/.well-known/openid-configuration",
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    audience=AUTH0_AUDIENCE,
    base_url=BASE_URL,
    fastmcp_access_token_expiry_seconds=3600,
)

mcp = FastMCP("payment-agent-proxy", auth=auth)


# ---------------------------------------------------------------------------
# Sub binding helper
# ---------------------------------------------------------------------------

def _check_sub(user_id: str) -> dict | None:
    """Verify the token's sub matches the requested user_id.

    Returns an error dict to return immediately if binding fails, else None.

    Note: get_access_token() here returns the UPSTREAM Auth0 JWT (stored in
    FastMCP's server-side session state), not the incoming FastMCP JWT.
    The incoming FastMCP JWT carries no sub — user identity is only available
    through this server-side lookup. This is a structural limit of the proxy
    pattern vs the resource-server pattern (Server #3).
    """
    token = get_access_token()
    if token is None:
        return {"error": "Unauthorized: no token present"}

    token_sub = token.claims.get("sub", "")
    expected_sub = USERS.get(user_id, {}).get("auth0_sub", "")

    if not expected_sub:
        # auth0_sub not configured in data.py — warn and skip (dev mode).
        # In production, treat a missing mapping as a hard rejection.
        log.warning(
            "SECURITY | auth0_sub not configured for user_id=%s — sub binding skipped. "
            "Fill in data.py to enforce.",
            user_id,
        )
        return None

    if token_sub != expected_sub:
        log.warning(
            "SECURITY | sub mismatch REJECTED | user_id=%s | token_sub=%s | expected_sub=%s",
            user_id, token_sub, expected_sub,
        )
        return {"error": f"Unauthorized: token subject does not match user '{user_id}'"}

    return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool
def list_payments(user_id: str) -> dict:
    """List all payments for a user."""
    if err := _check_sub(user_id):
        return err

    payments = [p for p in PAYMENTS if p["user_id"] == user_id]
    token = get_access_token()
    sub = token.claims.get("sub", "unknown") if token else "unknown"
    log.info(
        "AUDIT | action=list_payments | user_id=%s | sub=%s | count=%d | auth=oauth_proxy",
        user_id, sub, len(payments),
    )
    return {"user_id": user_id, "payments": payments}


@mcp.tool
def book_payment(user_id: str, amount: float, to: str, memo: str) -> dict:
    """Book a new payment on behalf of a user."""
    if user_id not in USERS:
        return {"error": f"Unknown user: {user_id!r}"}
    if amount <= 0:
        return {"error": "Amount must be positive"}
    if err := _check_sub(user_id):
        return err

    token = get_access_token()
    sub = token.claims.get("sub", "unknown") if token else "unknown"
    payment = add_payment(user_id, amount, to, memo)
    log.info(
        "AUDIT | action=book_payment | user_id=%s | sub=%s | amount=%.2f | to=%r | payment_id=%s | auth=oauth_proxy",
        user_id, sub, amount, to, payment["id"],
    )
    return {"ok": True, "payment": payment}


@mcp.tool
def cancel_payment(payment_id: str) -> dict:
    """Cancel a pending payment."""
    # Look up which user owns this payment, then check sub binding.
    payment = next((p for p in PAYMENTS if p["id"] == payment_id), None)
    if payment is None:
        return {"error": f"Payment {payment_id!r} not found"}
    if err := _check_sub(payment["user_id"]):
        return err

    token = get_access_token()
    sub = token.claims.get("sub", "unknown") if token else "unknown"
    result = cancel_payment_by_id(payment_id)
    log.info(
        "AUDIT | action=cancel_payment | payment_id=%s | sub=%s | ok=%s | auth=oauth_proxy",
        payment_id, sub, result.get("ok"),
    )
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _write_token(key: str, value: str) -> None:
    """Write/update a token key in the root tokens.env."""
    from pathlib import Path
    env_path = Path(__file__).parent.parent / "tokens.env"
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    updated = False
    for i, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[i] = f"{key}={value}"
            updated = True
            break
    if not updated:
        lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n")


class DemoBearerCapture(BaseHTTPMiddleware):
    """DEMO ONLY — logs + saves the incoming FastMCP JWT to tokens.env."""
    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer ") and request.url.path == "/mcp":
            token = auth_header[len("Bearer "):]
            log.warning("DEMO | fastmcp_token=%s", token)
            _write_token("SERVER_2_FASTMCP_TOKEN", token)
        return await call_next(request)


if __name__ == "__main__":
    log.info("Server #2 (OAuth proxy, hardened) starting on %s", BASE_URL)
    log.info("Auth0 domain   : %s", AUTH0_DOMAIN)
    log.info("Auth0 audience : %s", AUTH0_AUDIENCE)
    log.info("Token lifetime : 3600s (FastMCP-issued)")
    log.info("Callback URL   : %s/auth/callback  ← must be in Auth0 Allowed Callback URLs", BASE_URL)
    app = mcp.http_app()
    app.add_middleware(DemoBearerCapture)
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
