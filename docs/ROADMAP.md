# Build Roadmap & Division of Labor

This file is the source of truth for what's left and who writes what.
It exists so work can continue on a different machine (and with a different
AI assistant) without losing the plan.

## The hard rule (do not break)

**Suhas writes all auth/security logic by hand** — it must be interview-defensible.
The AI assistant writes boilerplate/scaffolding only, and may *review* the auth code.

Test for each chunk: "Will someone ask me about this in an interview?"
- Yes → Suhas writes it (leave a clearly-marked stub with the function contract).
- No → assistant writes it.

**Never let the assistant write:** JWT signature validation, JWKS fetching, the
`client_credentials` request, PKCE verifier/challenge, the RFC 8693 token-exchange
call, `sub`↔`user_id` binding checks, or the attack scripts' core logic.

## Status legend
- ✅ done  · 🟡 scaffold exists, logic pending · ⬜ not started

---

## Current state

| Component | Status | Notes |
|---|---|---|
| `server-1-apikey/` | ✅ | Runs, tested, attack #1 verified |
| `attacks/01_leaked_key_replay.py` | ✅ | Working, blog-ready output |
| `server-2-proxy/` | ⬜ | README only |
| `server-3-resourceserver/` | ⬜ | README only |
| `attacks/02_token_replay.py` | 🟡 | print-stub only |
| `attacks/03_cross_server_token.py` | 🟡 | print-stub only |
| `attacks/04_confused_deputy.py` | 🟡 | print-stub only |
| `setup/provision_auth0.py` | ⬜ | not started |
| README video + blog post | ⬜ | placeholders in README |

---

## Environment note (laptop switch)

- The Auth0 tenant lives on the **office laptop**. Configure `.env` there.
- `.env` is gitignored — **never commit tenant secrets**. Only `.env.example` is tracked.
- Workflow: push from here → pull on office laptop → fill `.env` from the real tenant → run.

---

## Phase 2 — Server #2 (FastMCP auth-proxy)

**Goal:** MCP server acts as an OAuth client. It holds a confidential M2M
credential and fetches an access token from Auth0 (`client_credentials`),
then uses/forwards it. This is the "convenient but the server holds the secret,
and the audit log loses the user" pattern.

### Assistant scaffolds (boilerplate)
- [ ] `data.py` — copy of `server-1-apikey/data.py` (or shared import)
- [ ] `requirements.txt` — `fastmcp`, `uvicorn`, `httpx`, `python-jose[cryptography]` (or `pyjwt[crypto]`), `python-dotenv`
- [ ] `.env.example` — the `AUTH0_*` vars for v2 (domain, client id/secret, audience)
- [ ] `server.py` **skeleton** — same 3 tools (`list_payments`, `book_payment`,
      `cancel_payment`), the audit-logging format matching server-1, and a
      middleware mount point. Leave the token-validation body as a stub calling
      into `auth.py`.

### Suhas writes by hand (`auth.py` — interview-defensible)
- [ ] `get_m2m_token()` — POST to `https://{AUTH0_DOMAIN}/oauth/token` with
      `grant_type=client_credentials`, `audience=AUTH0_AUDIENCE_V2`. Decide:
      fetch-per-request vs cache-until-expiry (recommend cache with a small
      safety margin — more realistic, and you can speak to it).
- [ ] `validate_token(token)` — fetch JWKS from
      `https://{AUTH0_DOMAIN}/.well-known/jwks.json`, verify signature, `iss`,
      `aud`, `exp`. This is the middleware's core.
- [ ] Wire validation into the FastMCP request path.

### Design decision to pin down (yours)
FastMCP ships an `OAuthProxy` construct for bridging IdPs. Decide whether
server-2 uses that construct or a hand-rolled middleware + `get_m2m_token()`.
Either is fine for the blog — just be able to explain *why*. Document the choice
in `server-2-proxy/README.md`.

### Definition of done
- [ ] Server starts, rejects requests with no/invalid token (401)
- [ ] Server accepts a valid Auth0 token and runs the tool
- [ ] Audit log shows the token was used but **cannot** attribute to a human user
      (this gap is the point — call it out in a log comment)

---

## Phase 3 — Attack #2 (token replay) against Server #2

**Suhas writes** (`attacks/02_token_replay.py`). Contract:
1. Obtain a valid token (capture from the proxy flow / server-2 logs).
2. Replay the raw token directly against server-2's `/mcp` endpoint after the
   "legitimate" session ends.
3. Print ✗/✓ in the same format as attack #1, with the exposure window in seconds.

Assistant may scaffold the MCP-client connection boilerplate (copy the
`streamablehttp_client` + `ClientSession` harness from attack #1) — but the
token-capture and replay assertion are yours.

---

## Phase 4 — Server #3 (resource server + RFC 8693)

**Goal:** MCP server holds **no** credentials. It only validates incoming JWTs
(issued to a real user via PKCE) and, when calling downstream, exchanges the
token via RFC 8693 for a narrower, audience-scoped downstream token. Every
action is attributed to a human `sub`.

### Assistant scaffolds (boilerplate)
- [ ] `data.py` — copy/shared
- [ ] `requirements.txt`
- [ ] `.env.example` — `AUTH0_AUDIENCE_V3`, `AUTH0_CLIENT_ID_PKCE`, (no secret on the server)
- [ ] `server.py` **skeleton** — 3 tools + audit logging that includes `sub`,
      `user_id`, and a `token_exchange=` field; validation + binding bodies stubbed
- [ ] `token_exchange.py` **skeleton** — function signature + docstring only
- [ ] A tiny PKCE test-client scaffold (or a doc stub) so you can get a real
      user token to test with

### Suhas writes by hand (interview-defensible)
- [ ] `auth.py` — JWT validation (`iss`/`aud`/`exp`/`scope`) for `AUTH0_AUDIENCE_V3`
- [ ] **`sub` ↔ `user_id` binding check** inside each tool (the confused-deputy fix)
- [ ] `token_exchange.py` — RFC 8693 call: POST to `/oauth/token` with
      `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
      `subject_token`, `subject_token_type`, target `audience`/`scope`
- [ ] The PKCE flow (verifier/challenge, code exchange) — either in a test client
      or documented as the agent host's responsibility (clarify the boundary in README)

### Auth0 tenant setup needed (do on office laptop)
- API `api://payment-agent-v3` with scopes `payments:read|write|cancel`
- A **public** client for PKCE (`AUTH0_CLIENT_ID_PKCE`)
- Token exchange enabled (Enterprise feature, or an Auth0 Action workaround —
  note which you used; it's a good blog detail)

### Definition of done
- [ ] Rejects tokens with wrong `aud` (sets up attack #3)
- [ ] Rejects `book_payment(user_id="bob")` when token `sub` = alice (attack #4)
- [ ] Downstream call uses an exchanged, narrower token
- [ ] Audit log shows full chain: `sub` → agent → server → downstream

---

## Phase 5 — Attacks #3 & #4 (the ones that actually prove the thesis)

**Suhas writes.** These are the differentiators — most posts never show them.

- [ ] `attacks/03_cross_server_token.py` — get a server-2-audience token, present
      it to server-3, assert rejection citing `aud` mismatch.
- [ ] `attacks/04_confused_deputy.py` — complete PKCE as alice, call
      `book_payment(user_id="bob")` with alice's token, assert rejection citing
      `sub` != `user_id`. Show servers #1/#2 would have accepted it.

---

## Phase 6 — Provisioning + polish (deferrable)

- [ ] `setup/provision_auth0.py` — assistant scaffolds Management API CRUD to
      create the two APIs, scopes, M2M app, and PKCE app; writes IDs back to `.env`.
      You supply Management API creds and review.
- [ ] Record the 3–5 min README video (all servers + all attacks)
- [ ] Write the ~1500-word blog post — lead with the proxy-vs-resource-server tension
- [ ] (Optional / follow-up) OWASP Agentic Top 10 mapping — draft already in `docs/threat-model.md`

---

## Suggested order for the office-laptop session

1. Assistant scaffolds Server #2 (Phase 2 boilerplate) → you write `auth.py`
2. Configure Auth0 v2 resources → test server-2 end to end
3. You write Attack #2 → verify
4. Assistant scaffolds Server #3 (Phase 4 boilerplate) → you write `auth.py` +
   `token_exchange.py` + PKCE
5. Configure Auth0 v3 resources → test server-3
6. You write Attacks #3 & #4 → verify (this is the payoff moment)
7. Provisioning script, video, blog post
