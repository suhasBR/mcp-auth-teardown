"""
auth.py — sub ↔ user_id binding for Server #3.

FastMCP's Auth0MCPProvider already enforces the hard JWT guarantees at the
HTTP layer — signature (RS256 via Auth0 JWKS), iss, aud, and exp. Any
request with a bad token gets a 401 before tools ever run.

This module handles the one check that FastMCP cannot do automatically:
verifying that the authenticated user (token.claims["sub"]) is actually
the same person as the user_id being operated on.

Key difference from Server #2:
  - Here, token is the INCOMING Auth0 JWT — sub is on the wire.
  - Server #2's sub came from FastMCP's server-side session state (a proxy
    layer with no sub in the actual Bearer token). This is cleaner and
    allows stateless validation.
"""
import logging

from fastmcp.server.auth import AccessToken

from data import USERS

log = logging.getLogger("server-3-resourceserver")


def check_sub(token: AccessToken | None, user_id: str) -> dict | None:
    """Verify the token's sub matches the Auth0 sub registered for user_id.

    Returns {"error": "..."} if binding fails, None if ok.

    Call this at the top of every tool that takes a user_id parameter.
    For cancel_payment, look up the payment's owner first, then call here.
    """
    if token is None:
        return {"error": "Unauthorized: no token present"}

    token_sub = token.claims.get("sub", "")
    expected_sub = USERS.get(user_id, {}).get("auth0_sub", "")

    if not expected_sub:
        # auth0_sub not yet filled in data.py — warn and allow (dev mode).
        # In production, treat a missing mapping as a hard rejection.
        log.warning(
            "SECURITY | auth0_sub not configured for user_id=%s — sub binding skipped. "
            "Fill in data.py to enforce.",
            user_id,
        )
        return None

    if token_sub != expected_sub:
        log.warning(
            "SECURITY | sub mismatch REJECTED | user_id=%s | token_sub=%s | expected=%s",
            user_id, token_sub, expected_sub,
        )
        return {
            "error": (
                f"Unauthorized: token sub '{token_sub}' does not match user '{user_id}'. "
                f"You cannot act on behalf of a different user."
            )
        }

    return None
