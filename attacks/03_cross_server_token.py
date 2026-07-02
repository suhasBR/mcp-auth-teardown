"""
Attack #3: Cross-Server Token Reuse / Audience Mismatch (Server #3)
--------------------------------------------------------------------
Scenario: An attacker obtains a valid access token issued for Server #2
(the proxy) and attempts to use it against Server #3 (the resource server).
This tests whether Server #3 validates the `aud` (audience) claim.

This is the classic confused-deputy vector in multi-resource OAuth deployments:
a token scoped to resource A should be cryptographically rejected by resource B.

What this proves:
  - Server #2 (proxy) tokens should NOT work against Server #3
  - Server #3's JWT validation must check `aud` — not just `iss` and `exp`
  - Without audience validation, compromise of any resource server = compromise of all

TODO: Implement after both server-2 and server-3 are complete.

Expected output format:
  ✗ Server #2 token accepted by Server #3 (audience not validated)
  OR
  ✓ Server #3 rejected cross-server token — aud mismatch: expected 'api://payment-agent-v3', got 'api://payment-agent-v2'
"""

# TODO: Implement after server-2-proxy and server-3-resourceserver are complete.
# Key things to validate in this script:
#
# 1. Get a token from the Auth0 M2M flow scoped to Server #2's API identifier
# 2. Present that token to Server #3's /mcp endpoint
# 3. Assert rejection and capture the exact error (should reference `aud`)
# 4. Compare audit log entries from Server #3 for the rejected request

print("Attack #3 is stubbed — implement after both server-2 and server-3 are complete.")
print("See docstring for the attack scenario (audience mismatch / cross-server token reuse).")
