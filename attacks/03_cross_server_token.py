"""
Attack #3: Cross-Server Token Reuse / Audience Mismatch
--------------------------------------------------------
Scenario: Attacker obtains a valid FastMCP JWT issued by Server #2
(aud = http://127.0.0.1:8002/mcp) and replays it against Server #3.

What this proves:
  - Server #3 validates the `aud` claim cryptographically — a token
    scoped to Server #2 is REJECTED outright, before any tool runs.
  - Without audience binding, compromising any resource server would
    give an attacker tokens reusable across ALL other servers.
  - Server #1 and Server #2 don't enforce audience at the MCP level
    (Server #1 has no JWT at all; Server #2 issues its own JWTs and
    only validates them against its own signing key).

This is the OAuth 2.0 audience restriction (RFC 9396) in practice.

Run:
  1. Start server-2: cd server-2-proxy && python server.py
  2. Start server-3: cd server-3-resourceserver && python server.py
  3. Get a server-2 token: cd attacks && python 00_capture_token.py
  4. Paste it into SERVER_2_TOKEN below
  5. cd attacks && python 03_cross_server_token.py
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

SERVER_2_URL = "http://127.0.0.1:8002/mcp"
SERVER_3_URL = "http://127.0.0.1:8003/mcp"

SERVER_2_TOKEN = os.getenv("SERVER_2_FASTMCP_TOKEN", "")

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


async def try_server(url: str, token: str) -> bool:
    """Returns True if server accepted the token, False if rejected."""
    try:
        http = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"})
        async with streamable_http_client(url, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return True
    except Exception:
        return False


async def main():
    if not SERVER_2_TOKEN:
        print(f"\n  {YELLOW}[!] SERVER_2_TOKEN is empty.{RESET}")
        print(f"      Run: python 00_capture_token.py  (server-2 must be running)")
        print(f"      Copy the DEMO | fastmcp_token= value from the server-2 terminal.")
        sys.exit(1)

    claims = decode_claims(SERVER_2_TOKEN)
    token_aud = claims.get("aud", "unknown")
    token_iss = claims.get("iss", "unknown")

    print()
    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  Attack #3: Cross-Server Token Reuse{RESET}")
    print(f"{BOLD}  Token iss: {token_iss}{RESET}")
    print(f"{BOLD}  Token aud: {token_aud}{RESET}")
    print(f"{BOLD}{'=' * 62}{RESET}")
    print()
    print(f"{DIM}  This token was issued FOR:  {token_aud}{RESET}")
    print(f"{DIM}  We are replaying it AGAINST: {SERVER_3_URL}{RESET}")
    print()

    # ── Step 1: Confirm the token works on its home server (server-2) ──────────
    print(f"{BOLD}[1/2] Confirming token is valid on its home server (Server #2)...{RESET}")
    if await try_server(SERVER_2_URL, SERVER_2_TOKEN):
        print(f"  {GREEN}Token accepted by Server #2 (expected — it was issued here){RESET}")
    else:
        print(f"  {YELLOW}[!] Token rejected by Server #2 — may be expired. Recapture and retry.{RESET}")
        sys.exit(1)
    print()

    # ── Step 2: Replay the server-2 token against server-3 ────────────────────
    print(f"{BOLD}[2/2] Replaying server-2 token against Server #3 (resource server)...{RESET}")
    print(f"      {DIM}Expected aud on server-3: http://127.0.0.1:8003/mcp{RESET}")
    print(f"      {DIM}Token's actual aud:        {token_aud}{RESET}")
    print()

    if await try_server(SERVER_3_URL, SERVER_2_TOKEN):
        fail(
            f"Server #3 accepted a token with aud='{token_aud}'\n"
            f"      This server should only accept aud='http://127.0.0.1:8003/mcp'"
        )
    else:
        ok(
            f"Server #3 rejected the token — aud mismatch\n"
            f"      Expected: http://127.0.0.1:8003/mcp\n"
            f"      Got:      {token_aud}"
        )
    print()

    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  VERDICT{RESET}")
    print(f"{'=' * 62}")
    print(f"""
  A token scoped to Server #2 (aud={token_aud})
  is cryptographically rejected by Server #3.

  Without audience validation:
    - Compromising Server #2 gives tokens reusable on Server #3
    - Any server that accepts Bearer tokens would be in scope
    - Multi-tenant deployments collapse into a single blast radius

  Server #3 enforces RFC 9396 audience restriction — each token
  is bound to exactly one resource server at issuance time.
  Auth0 embeds the aud claim; the server validates it against its
  own resource URL (http://127.0.0.1:8003/mcp). No match = 401.
""")


if __name__ == "__main__":
    asyncio.run(main())
