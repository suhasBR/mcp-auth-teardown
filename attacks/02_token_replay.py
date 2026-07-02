"""
Attack #2: Access Token Replay (Server #2 — FastMCP Auth Proxy)
----------------------------------------------------------------
Scenario: An attacker intercepts or exfiltrates an access token issued
to a legitimate agent session (e.g., from logs, memory dumps, or a
compromised agent host). They replay it directly against Server #2.

What this proves / disproves (fill in after running):
  - Does the server reject replayed tokens after the session ends?
  - Can a token obtained for Agent A be used by Agent B?
  - What's the actual window of exposure?

TODO: Fill in this script after Server #2 is implemented.
      You (the author) write the token validation logic in server-2;
      this attack script can then be completed to test it.

Expected output format:
  ✗ ATTACK SUCCEEDED — replayed token accepted (N seconds after issue)
  ✓ Server blocked it — token rejected (reason: ...)
"""

# TODO: Implement after server-2-proxy is complete.
# Suggested structure:
#
# 1. Obtain a valid token from the Auth0 proxy flow (capture from server-2 logs)
# 2. Wait for the "legitimate" session to end
# 3. Replay the raw token against server-2's MCP endpoint
# 4. Compare rejection behavior vs server-3's resource-server model

print("Attack #2 is stubbed — implement after server-2-proxy is complete.")
print("See docstring for the attack scenario and expected output format.")
