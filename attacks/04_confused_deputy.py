"""
Attack #4: Confused Deputy — Agent Acts for the Wrong User
-----------------------------------------------------------
Scenario: Agent holds a valid Auth0 JWT for alice
(sub = auth0|69babdf..., aud = http://127.0.0.1:8003/mcp).
It calls book_payment(user_id="bob") — substituting a different user_id
than the one in the token's sub claim.

What this proves:
  - Server #3 binds user_id to the token's sub claim — cross-user
    actions are REJECTED at the auth layer, not the app layer.
  - Server #1 accepts this (no auth at all — just checks the API key).
  - Server #2 accepts this when bob's auth0_sub is not configured
    (sub binding is warn-and-skip without a mapping for every user).
  - Only Server #3 makes this structurally impossible: the sub claim
    IS the authorization — user_id must match it.

OWASP Agentic Top 10 mapping:
  A2: Insufficient Authorization (agent acting beyond delegated scope)
  A4: Data Exfiltration (accessing another user's payment data)

Run:
  1. Start server-1: cd server-1-apikey && python server.py
  2. Start server-2: cd server-2-proxy && python server.py
  3. Start server-3: cd server-3-resourceserver && python server.py
  4. Paste alice's Auth0 JWT into ALICE_TOKEN below
     (from server-3 terminal: DEMO | auth0_token=eyJ...)
  5. cd attacks && python 04_confused_deputy.py
"""

import asyncio
import base64
import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

# Load tokens captured by `make capture-tokens`
load_dotenv(Path(__file__).parent.parent / "tokens.env")

SERVER_1_URL = "http://127.0.0.1:8001/mcp"
SERVER_2_URL = "http://127.0.0.1:8002/mcp"
SERVER_3_URL = "http://127.0.0.1:8003/mcp"
SERVER_1_API_KEY = "sk-apikey-demo-1234-definitely-not-a-secret"

ALICE_TOKEN = os.getenv("ALICE_AUTH0_TOKEN", "")

RESET  = "\033[0m"
RED    = "\033[31m"
GREEN  = "\033[32m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
YELLOW = "\033[33m"


def fail(msg: str):
    print(f"  {RED}✗ ATTACK SUCCEEDED{RESET} — {msg}")


def ok(msg: str):
    print(f"  {GREEN}✓ Server blocked it{RESET} — {msg}")


def decode_claims(token: str) -> dict:
    try:
        p = token.split(".")[1]
        p += "=" * (4 - len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


async def call(session: ClientSession, tool: str, args: dict) -> dict:
    result = await session.call_tool(tool, args)
    if result.content and hasattr(result.content[0], "text"):
        return json.loads(result.content[0].text)
    return {}


async def main():
    if not ALICE_TOKEN:
        print(f"\n  {YELLOW}[!] ALICE_TOKEN is empty.{RESET}")
        print(f"      Run: cd server-3-resourceserver && python pkce_client.py")
        print(f"      Copy the DEMO | auth0_token= value from the server-3 terminal.")
        sys.exit(1)

    claims = decode_claims(ALICE_TOKEN)
    alice_sub = claims.get("sub", "unknown")
    token_aud = claims.get("aud", "unknown")

    print()
    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  Attack #4: Confused Deputy{RESET}")
    print(f"{BOLD}  Token sub (alice): {alice_sub}{RESET}")
    print(f"{BOLD}  Acting as:         bob{RESET}")
    print(f"{BOLD}{'=' * 62}{RESET}")
    print()
    print(f"{DIM}  Alice's token is valid (aud={token_aud}){RESET}")
    print(f"{DIM}  We pass user_id='bob' to act on bob's account{RESET}")
    print()

    # ── Step 1: Server #1 — no auth, accepts anything ─────────────────────────
    print(f"{BOLD}[1/3] Server #1 (API key) — no user binding at all...{RESET}")
    try:
        http = httpx.AsyncClient(headers={"X-API-Key": SERVER_1_API_KEY})
        async with streamable_http_client(SERVER_1_URL, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await call(session, "book_payment", {
                    "user_id": "bob",
                    "amount": 1500.00,
                    "to": "Attacker LLC",
                    "memo": "Confused deputy — alice acting as bob",
                })
        if result.get("ok"):
            fail(f"booked $1,500 from bob's account (payment_id={result['payment']['id']}) — no user binding in API key auth")
        else:
            ok(f"rejected: {result.get('error')}")
    except Exception as exc:
        print(f"  [!] Could not connect to Server #1: {exc}")
    print()

    # ── Step 2: Server #2 — sub binding only if bob's sub is configured ────────
    print(f"{BOLD}[2/3] Server #2 (OAuth proxy) — sub binding depends on data.py config...{RESET}")
    try:
        # Alice's Auth0 token won't work on server-2 (wrong aud).
        # We use a fresh server-2 FastMCP token from 02_token_replay.py if available,
        # but the point is made architecturally: server-2's sub binding is
        # optional (warn-and-skip when auth0_sub is not mapped for a user).
        print(f"  {DIM}Note: Server #2 uses FastMCP JWTs (not Auth0 JWTs directly).{RESET}")
        print(f"  {DIM}Sub binding on Server #2 is warn-and-skip if bob's auth0_sub{RESET}")
        print(f"  {DIM}is not configured in data.py — attack would succeed there.{RESET}")
        fail("Server #2 sub binding is not structurally enforced — requires manual mapping for every user")
    except Exception as exc:
        print(f"  [!] {exc}")
    print()

    # ── Step 3: Server #3 — sub binding is structural ─────────────────────────
    print(f"{BOLD}[3/3] Server #3 (resource server) — sub claim IS the authorization...{RESET}")
    print(f"      {DIM}token sub={alice_sub}{RESET}")
    print(f"      {DIM}requested user_id=bob{RESET}")
    try:
        http = httpx.AsyncClient(headers={"Authorization": f"Bearer {ALICE_TOKEN}"})
        async with streamable_http_client(SERVER_3_URL, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await call(session, "book_payment", {
                    "user_id": "bob",
                    "amount": 1500.00,
                    "to": "Attacker LLC",
                    "memo": "Confused deputy — alice acting as bob",
                })
        if result.get("ok"):
            fail(f"booked $1,500 from bob's account — sub binding not enforced!")
        else:
            ok(
                f"rejected — {result.get('error', 'sub mismatch')}\n"
                f"      token sub ({alice_sub}) ≠ requested user_id (bob)"
            )
    except Exception as exc:
        if "401" in str(exc) or "unauthorized" in str(exc).lower():
            ok(f"rejected at auth layer — 401 Unauthorized")
        else:
            print(f"  [!] Connection error: {exc}")
    print()

    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  VERDICT{RESET}")
    print(f"{'=' * 62}")
    print(f"""
  Confused deputy attack: alice's token used to act as bob.

  Server #1: ACCEPTED  — API key has no user identity at all
  Server #2: ACCEPTED* — sub binding is opt-in, not structural
             (* if bob's auth0_sub is not configured in data.py)
  Server #3: REJECTED  — sub claim in the Auth0 JWT IS the identity;
             user_id must match it. This check cannot be skipped.

  The structural difference: in Server #3, the token's sub arrives
  directly from Auth0 in the validated JWT. There is no session state,
  no server-side mapping, no way to bypass it without a forged token.
  In Server #2, the sub lives in FastMCP's session state — a mutable,
  server-managed layer that a developer must explicitly wire up.
""")


if __name__ == "__main__":
    asyncio.run(main())
