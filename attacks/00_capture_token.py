"""
Token capture helper for Server #2.

Triggers an OAuth flow against Server #2. The server's DemoBearerCapture
middleware intercepts the Bearer token and writes it to tokens.env automatically.

Run (with Server #2 running):
    cd attacks/
    python 00_capture_token.py
    OR: make capture-tokens  (also runs pkce_client.py for server-3)
"""

import asyncio
import sys
from pathlib import Path

from fastmcp import Client

SERVER_URL = "http://127.0.0.1:8002/mcp"
TOKENS_ENV = Path(__file__).parent.parent / "tokens.env"


async def main():
    print(f"\nConnecting to {SERVER_URL} (OAuth flow)...")
    print("A browser window will open for Auth0 login.\n")

    try:
        async with Client(SERVER_URL, auth="oauth") as client:
            result = await client.call_tool("list_payments", {"user_id": "alice"})
            print(f"Tool call succeeded: {result.data.get('user_id')} — {len(result.data.get('payments', []))} payments\n")
    except Exception as exc:
        print(f"[!] Connection failed: {exc}")
        print(f"    Is Server #2 running?  make server2")
        sys.exit(1)

    # Token is written to tokens.env by the server's DemoBearerCapture middleware
    if TOKENS_ENV.exists():
        content = TOKENS_ENV.read_text()
        if "SERVER_2_FASTMCP_TOKEN=" in content:
            print(f"✓ SERVER_2_FASTMCP_TOKEN written to tokens.env")
        else:
            print(f"[!] Token not found in tokens.env — check server-2 logs for DEMO | fastmcp_token=")
    else:
        print(f"[!] tokens.env not found — check server-2 logs for DEMO | fastmcp_token=")


if __name__ == "__main__":
    asyncio.run(main())
