"""
Server #3: Resource Server (Auth0MCPProvider)
---------------------------------------------
Pattern: The MCP server holds ZERO credentials. It is a pure OAuth 2.0
resource server. Auth0 is the Authorization Server. MCP clients authenticate
directly with Auth0 via OAuth 2.1 + PKCE, then present the resulting JWT.

This is Auth0's "Auth for MCP" pattern:
  https://auth0.com/ai/docs/mcp/get-started/authorization-for-your-mcp-server

Auth0 tenant setup required (see .env.example for values):
  1. Settings → Advanced → enable "Resource Parameter Compatibility Profile"
  2. Settings → Advanced → enable "Include Issuer in Authorization Responses"
  3. Promote your connection to domain-level (for DCR with third-party clients)
  4. Applications → APIs → Create API
       Identifier: http://127.0.0.1:8003/mcp  (must match SERVER_3_PORT)
       Signing:    RS256

Why this fixes Server #2's architectural gaps:
  ✓ Server holds NO Auth0 credentials — nothing to steal, no blast radius.
  ✓ The incoming Bearer token IS the Auth0 JWT — sub is on the wire.
    Sub binding is stateless; no session lookup required.
  ✓ Auth0 validates `aud` cryptographically — Server #2 tokens are rejected
    (aud = api://payment-agent-v2 ≠ http://127.0.0.1:8003/mcp).
  ✓ RFC 8693 token exchange produces a delegated downstream token attributed
    to the user's sub. Full audit chain: user → agent → MCP server → downstream.
  ✓ Auth0's audit log records the OAuth events (token issuance, revocation).

Run:
    cp .env.example .env   # fill in AUTH0_DOMAIN + AUTH0_AUDIENCE_V3
    pip install -r requirements.txt
    python server.py
"""
import logging
import os
import sys

import uvicorn
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

import auth
import token_exchange as tex
from data import PAYMENTS, USERS, add_payment, cancel_payment_by_id

load_dotenv()

AUTH0_DOMAIN       = os.getenv("AUTH0_DOMAIN", "")
AUTH0_AUDIENCE_V3  = os.getenv("AUTH0_AUDIENCE_V3", "")
DOWNSTREAM_AUD     = os.getenv("DOWNSTREAM_AUDIENCE", "")
PORT     = int(os.getenv("SERVER_3_PORT", "8003"))
BASE_URL = f"http://127.0.0.1:{PORT}"

if not all([AUTH0_DOMAIN, AUTH0_AUDIENCE_V3]):
    sys.exit(
        "Missing required env vars.\n"
        "Copy .env.example → .env and fill in:\n"
        "  AUTH0_DOMAIN, AUTH0_AUDIENCE_V3"
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] server-3-resourceserver | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("server-3-resourceserver")

# RemoteAuthProvider + JWTVerifier: equivalent to Auth0MCPProvider (which is
# not yet on PyPI 3.4.4). Holds zero credentials — pure resource server.
#   JWTVerifier: fetches Auth0's JWKS, validates RS256 sig + iss + aud + exp
#   RemoteAuthProvider: advertises Auth0 as the AS in OAuth discovery metadata
#     so MCP clients can find Auth0 and do PKCE/DCR automatically
verifier = JWTVerifier(
    jwks_uri=f"https://{AUTH0_DOMAIN}/.well-known/jwks.json",
    issuer=f"https://{AUTH0_DOMAIN}/",
    audience=AUTH0_AUDIENCE_V3,
    algorithm="RS256",
)
auth_provider = RemoteAuthProvider(
    token_verifier=verifier,
    authorization_servers=[f"https://{AUTH0_DOMAIN}/"],
    base_url=BASE_URL,
)

mcp = FastMCP("payment-agent-resourceserver", auth=auth_provider)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool
def list_payments(user_id: str) -> dict:
    """List all payments for a user."""
    token = get_access_token()
    if err := auth.check_sub(token, user_id):
        return err

    payments = [p for p in PAYMENTS if p["user_id"] == user_id]
    sub = token.claims.get("sub", "unknown") if token else "unknown"
    log.info(
        "AUDIT | action=list_payments | sub=%s | user_id=%s | count=%d | auth=resource_server",
        sub, user_id, len(payments),
    )
    return {"user_id": user_id, "payments": payments}


@mcp.tool
async def book_payment(user_id: str, amount: float, to: str, memo: str) -> dict:
    """Book a new payment on behalf of a user."""
    if user_id not in USERS:
        return {"error": f"Unknown user: {user_id!r}"}
    if amount <= 0:
        return {"error": "Amount must be positive"}

    token = get_access_token()
    if err := auth.check_sub(token, user_id):
        return err

    sub = token.claims.get("sub", "unknown") if token else "unknown"

    # RFC 8693 — exchange the incoming token for a downstream-scoped token.
    # Only attempted if DOWNSTREAM_AUDIENCE is configured.
    exchange_status = "skipped"
    if DOWNSTREAM_AUD and token:
        try:
            await tex.exchange_token(
                subject_token=token.token,
                target_audience=DOWNSTREAM_AUD,
                scope="payments:write",
            )
            exchange_status = "ok"
        except Exception as exc:
            # Auth0 token exchange requires Enterprise plan or Actions workaround.
            # Log and continue — the payment is still booked locally.
            exchange_status = f"failed:{exc.__class__.__name__}"
            log.warning("token_exchange failed: %s", exc)

    payment = add_payment(user_id, amount, to, memo)
    log.info(
        "AUDIT | action=book_payment | sub=%s | user_id=%s | amount=%.2f | to=%r | "
        "payment_id=%s | token_exchange=%s | auth=resource_server",
        sub, user_id, amount, to, payment["id"], exchange_status,
    )
    return {"ok": True, "payment": payment}


@mcp.tool
async def cancel_payment(payment_id: str) -> dict:
    """Cancel a pending payment."""
    payment = next((p for p in PAYMENTS if p["id"] == payment_id), None)
    if payment is None:
        return {"error": f"Payment {payment_id!r} not found"}

    token = get_access_token()
    if err := auth.check_sub(token, payment["user_id"]):
        return err

    sub = token.claims.get("sub", "unknown") if token else "unknown"

    exchange_status = "skipped"
    if DOWNSTREAM_AUD and token:
        try:
            await tex.exchange_token(
                subject_token=token.token,
                target_audience=DOWNSTREAM_AUD,
                scope="payments:cancel",
            )
            exchange_status = "ok"
        except Exception as exc:
            exchange_status = f"failed:{exc.__class__.__name__}"
            log.warning("token_exchange failed: %s", exc)

    result = cancel_payment_by_id(payment_id)
    log.info(
        "AUDIT | action=cancel_payment | sub=%s | payment_id=%s | ok=%s | "
        "token_exchange=%s | auth=resource_server",
        sub, payment_id, result.get("ok"), exchange_status,
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
    """DEMO ONLY — logs + saves the incoming Auth0 JWT to tokens.env.
    Only writes tokens whose aud matches this server — prevents attack #3
    from overwriting ALICE_AUTH0_TOKEN with a server-2 token mid-demo."""
    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer ") and request.url.path == "/mcp":
            token = auth_header[len("Bearer "):]
            try:
                import base64 as _b64, json as _json
                p = token.split(".")[1]
                p += "=" * (4 - len(p) % 4)
                aud = _json.loads(_b64.urlsafe_b64decode(p)).get("aud", "")
                if aud == AUTH0_AUDIENCE_V3:
                    log.warning("DEMO | auth0_token=%s", token)
                    _write_token("ALICE_AUTH0_TOKEN", token)
            except Exception:
                pass
        return await call_next(request)


if __name__ == "__main__":
    log.info("Server #3 (resource server) starting on %s", BASE_URL)
    log.info("Auth0 domain  : %s", AUTH0_DOMAIN)
    log.info("Downstream aud: %s", DOWNSTREAM_AUD or "(not configured — token exchange skipped)")
    log.info("Auth0 will validate aud = %s/mcp", BASE_URL)
    app = mcp.http_app()
    app.add_middleware(DemoBearerCapture)
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
