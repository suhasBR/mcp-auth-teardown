"""
Attack #4: Confused Deputy — Agent Acts for the Wrong User (Server #3)
-----------------------------------------------------------------------
Scenario: Agent is granted a token on behalf of User A (alice) via PKCE.
The attacker (or a misconfigured agent) changes the `user_id` parameter
in the tool call to User B (bob). Does Server #3 catch this?

This is the agentic-AI variant of the confused deputy problem:
the server must verify that the token's `sub` claim matches the
user_id being acted upon — otherwise the agent can pivot to any user.

This attack also maps to OWASP Agentic Top 10:
  - A2: Insufficient Authorization (agent acting beyond delegated scope)
  - A4: Data Exfiltration (reading another user's payment data)

What this proves:
  - Server #3's tools must bind the user_id parameter to the token's `sub`
  - Accepting a user_id from the caller without verifying it against the
    token is the same mistake as trusting user input for authorization

TODO: Implement after server-3-resourceserver is complete.
      The `book_payment` tool in server-3 should reject calls where
      user_id != token.sub (you write that validation logic).

Expected output format:
  ✗ Server #3 accepted payment for 'bob' with alice's token (sub mismatch not checked)
  OR
  ✓ Server #3 rejected request — sub mismatch: token issued for 'alice', requested user 'bob'
"""

# TODO: Implement after server-3-resourceserver is complete.
# Suggested flow:
#
# 1. Complete PKCE flow as alice — obtain alice's access token
# 2. Call book_payment with user_id="bob" using alice's token
# 3. Assert that Server #3 rejects based on sub != user_id
# 4. Show that Server #1 and Server #2 would have accepted this

print("Attack #4 is stubbed — implement after server-3-resourceserver is complete.")
print("See docstring for the confused deputy scenario (sub vs user_id mismatch).")
