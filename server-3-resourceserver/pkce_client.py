"""
Token capture helper for Server #3.

Triggers a PKCE + DCR flow against Server #3. The server's DemoBearerCapture
middleware intercepts the Auth0 JWT and writes it to tokens.env automatically.
Also prints the token's sub claim so you can paste it into data.py.

Auth0 prerequisite: connection must be domain-level and the Server 3 API
must allow third-party apps (User-delegated Access → Allow).

Run (with Server #3 running):
    cd server-3-resourceserver/
    python pkce_client.py
    OR: make capture-tokens  (runs this after 00_capture_token.py)
"""

import asyncio
import base64
import json
import sys
from pathlib import Path

from fastmcp import Client

SERVER_URL = "http://127.0.0.1:8003/mcp"
TOKENS_ENV = Path(__file__).parent.parent / "tokens.env"


def _decode_claims(token: str) -> dict:
    try:
        p = token.split(".")[1]
        p += "=" * (4 - len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


async def main():
    print(f"\nConnecting to {SERVER_URL} (Auth0 PKCE + DCR flow)...")
    print("A browser window will open for Auth0 login.\n")

    try:
        async with Client(SERVER_URL, auth="oauth") as client:
            result = await client.call_tool("list_payments", {"user_id": "alice"})
            print(f"Tool call succeeded: {result.data.get('user_id')} — {len(result.data.get('payments', []))} payments\n")
    except Exception as exc:
        print(f"[!] Connection failed: {exc}")
        print(f"    Is Server #3 running?  make server3")
        sys.exit(1)

    # Token is written to tokens.env by the server's DemoBearerCapture middleware
    if TOKENS_ENV.exists():
        content = TOKENS_ENV.read_text()
        token = ""
        for line in content.splitlines():
            if line.startswith("ALICE_AUTH0_TOKEN="):
                token = line.split("=", 1)[1]
                break

        if token:
            claims = _decode_claims(token)
            print(f"✓ ALICE_AUTH0_TOKEN written to tokens.env")
            print(f"  sub : {claims.get('sub', '?')}  ← paste into server-3-resourceserver/data.py")
            print(f"  aud : {claims.get('aud', '?')}")
            print(f"  exp : lifetime {claims.get('exp',0) - claims.get('iat',0)}s")
        else:
            print(f"[!] Token not found in tokens.env — check server-3 logs for DEMO | auth0_token=")
    else:
        print(f"[!] tokens.env not found — check server-3 logs for DEMO | auth0_token=")


if __name__ == "__main__":
    asyncio.run(main())
