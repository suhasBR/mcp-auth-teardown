# Threat Model Notes

Three patterns, three threat models. This file tracks the security reasoning
that underpins the blog post.

---

## Server #1 — Static API Key

**What an attacker needs:** The key. That's it.

**How keys leak:**
- Committed to git (`.env` without `.gitignore`)
- Printed in application logs
- Passed in a URL query string (appears in access logs, browser history, Referer headers)
- Shared in a Slack message, screenshot, or email

**Blast radius after compromise:**
- Full access to ALL tools, ALL users
- No expiry — access persists until manual rotation
- No user binding — attacker can impersonate any user_id
- Audit log is useless: shows "key was used" but not by whom or on whose behalf

**Controls available:**
- Key rotation (reactive, manual, error-prone)
- IP allowlisting (reduces surface, doesn't eliminate it)
- Rate limiting (slows brute force, doesn't stop replay)

**When to use:** Local development, internal tooling with no user data, throwaway demos.
**Never use for:** Anything that touches real user data or takes irreversible actions.

---

## Server #2 — FastMCP Auth Proxy

**Improvement over #1:** Credential is time-limited (access token expiry), scoped to specific APIs.

**Residual risks:**
- MCP server holds a long-lived M2M client secret — if the server is compromised,
  attacker can issue new tokens indefinitely until the client is rotated
- Token is issued to the *server identity*, not to a *user* — no delegation chain
- Audit log shows "server accessed API" — no user attribution without extra instrumentation
- Token replay window: from issue until expiry (typically 1h) — meaningful attack window

**Controls available:**
- Short token TTL (reduces replay window)
- Scope limitation (minimize what the M2M client is authorized for)
- Refresh token rotation with reuse detection (Auth0 feature)
- Client secret rotation

**When to use:** Agentic workflows where the agent acts with its own identity,
not on behalf of a specific human user. Background jobs, automated reports.
**Avoid for:** User-delegated actions where you need to know WHICH user approved this.

---

## Server #3 — Resource Server + Token Exchange

**Improvement over #2:**
- MCP server holds NO credentials — it only validates tokens, never issues them
- Token has user identity (`sub`) — every action is attributed to a specific human
- RFC 8693 token exchange creates a minimal-scope, short-lived downstream token
  scoped to exactly the downstream API — not reusable for anything else
- Full delegation chain in audit log: `user → agent → MCP server → downstream API`

**What this looks like in a security review:**
- Compromise of MCP server: attacker gets tokens they can validate but cannot issue
- Compromise of downstream token: it's scoped to one API, short-lived, not reusable
- User revokes consent: all derived tokens become invalid (if implemented with refresh tokens)

**Controls present:**
- Audience (`aud`) validation — token for Server #3 rejected by any other service
- Scope enforcement — `payments:read` token cannot `payments:write`
- Subject binding — `sub` in token must match `user_id` in tool call (prevents confused deputy)
- Token exchange minimizes downstream blast radius

---

## OWASP Agentic Top 10 Mapping (draft — full post to follow)

| Attack script | OWASP Agentic Risk | Mitigation in Server #3 |
|---------------|-------------------|-------------------------|
| #1 Leaked key replay | A1: Unbounded Agent Actions | Scoped, expiring tokens |
| #2 Token replay | A3: Unsafe Third-Party Integration | Short TTL + audience binding |
| #3 Cross-server token | A5: Improper Output Handling | `aud` claim validation |
| #4 Confused deputy | A2: Insufficient Authorization | `sub` ↔ `user_id` binding in tools |
