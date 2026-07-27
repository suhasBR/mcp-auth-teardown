"""
token_exchange.py — RFC 8693 On-Behalf-Of token exchange.

When the MCP server needs to call a downstream API (e.g. a payment processor),
it cannot forward the user's incoming token — that token's audience is this
MCP server, not the downstream API. RFC 8693 solves this cleanly:

  1. MCP server receives token (aud = this server)
  2. Exchanges it at Auth0 for a new, narrower token (aud = downstream API)
  3. Calls downstream with the exchanged token

Every hop in the chain is attributed to the original user's sub.
This is the audit trail Server #2 cannot produce.

Auth0 note:
  Token exchange requires the Enterprise plan OR an Auth0 Actions workaround
  (inject a custom grant handler). If you're on a free/pro plan, this call will
  return a 403. Either upgrade or document the limitation in the blog post —
  it's a legitimate architecture observation worth calling out.
"""
import os

import httpx

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")


async def exchange_token(
    subject_token: str,
    target_audience: str,
    scope: str = "",
) -> str:
    """Exchange an incoming access token for a narrower downstream token.

    Args:
        subject_token:    The raw access token the MCP client presented.
        target_audience:  The `aud` of the downstream API you want to call.
        scope:            Space-separated scopes to request (optional).

    Returns:
        Raw access token string for the downstream call.

    Raises:
        httpx.HTTPStatusError: If Auth0 rejects the exchange (e.g. not on
            Enterprise plan). Catch this in the caller and log accordingly.
    """
    if not AUTH0_DOMAIN:
        raise RuntimeError("AUTH0_DOMAIN env var not set")

    payload: dict[str, str] = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": target_audience,
    }
    if scope:
        payload["scope"] = scope

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]
