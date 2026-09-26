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
- Subject binding — `sub` in token must match `user_id` in tool call (prevents authenticated-user impersonation — see note below on why this is not the spec's "Confused Deputy Problem")
- Token exchange minimizes downstream blast radius

---

## OWASP Agentic Top 10 Mapping (draft — full post to follow)

| Attack script | OWASP Agentic Risk | Mitigation in Server #3 |
|---------------|-------------------|-------------------------|
| #1 Leaked key replay | A1: Unbounded Agent Actions | Scoped, expiring tokens |
| #2 Token replay | A3: Unsafe Third-Party Integration | Short TTL + audience binding |
| #3 Cross-server token | A2: Insufficient Authorization (audience-scoped tokens rejected outside their intended resource) | `aud` claim validation |
| #4 User impersonation | A2: Insufficient Authorization | `sub` ↔ `user_id` binding in tools |

---

## Naming note: "Confused Deputy" vs. Attack #4

The MCP spec's [Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices#confused-deputy-problem)
document defines "Confused Deputy Problem" precisely — it is **not**
a generic term for "one user acting as another." It requires a specific
architecture:

1. An **MCP proxy server** holding a **static client ID** toward a
   third-party authorization server,
2. that allows MCP clients to **dynamically register** their own
   `client_id`/`redirect_uri`,
3. combined with a **consent cookie** at the third-party AS that causes
   it to skip re-consent for a previously-approved static client.

An attacker exploits this by registering a malicious `redirect_uri`,
sending a victim a crafted authorization link, and relying on the
victim's existing upstream consent cookie to skip consent — so the
authorization code gets redirected to the attacker's client instead of
the legitimate one.

Attack #4 in this repo (`04_user_impersonation.py`) is a **different**
vulnerability class: broken object-level authorization. A validly
authenticated caller (alice, holding her own legitimate token) supplies
a *different* subject (`user_id="bob"`) as a tool argument, and the
server must reject it because the caller's identity doesn't match the
identity being acted on. This is closer to IDOR than to the OAuth
confused-deputy attack, even though both fall under the general
"agent authorized for X does Y instead" umbrella and are often
conflated informally.

**Can the real confused-deputy attack even be demonstrated against
Server #3 in this repo?** No — and not because Server #3 has a control
that blocks it. Server #3 never satisfies precondition (1): it holds
zero Auth0 credentials and never acts as an OAuth client with a static
`client_id` toward Auth0. The MCP client talks to Auth0 directly via
`RemoteAuthProvider`'s discovery metadata. The vulnerable architecture
simply isn't present, so the attack has no surface to land on — a
stronger and more accurate claim than "Server #3 blocks it."

Server #2 (`server-2-proxy/`) *is* architecturally the right shape to
host this attack — `Auth0Provider` is exactly the OAuth-proxy pattern
the spec's confused-deputy section describes. However, FastMCP's
`OAuthProxy` defaults to `require_authorization_consent=True` and binds
consent to a signed, browser-session cookie specifically to defeat this
attack, even when the upstream IdP would otherwise skip its own consent
screen for a returning app. Server #2 in this repo does not override
that default, so demonstrating the real attack here would require
explicitly setting `require_authorization_consent=False` — i.e.,
simulating a team that disabled the consent screen for local-dev
convenience and shipped it that way. That's a legitimate, realistic
scenario, but it is a materially bigger build than attacks #1–4 (which
are single-shot token replays): it requires simulating a victim
browser's cookie jar across two separate OAuth transactions, not just
replaying a captured token. Not currently implemented in this repo.
