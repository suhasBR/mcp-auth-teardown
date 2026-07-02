# MCP Authorization Teardown

**Three ways to authorize an AI agent calling an MCP server — from insecure to enterprise-ready.**

A runnable reference repo with working attack scripts that prove the differences. Auth0 throughout.

> **[VIDEO PLACEHOLDER]** — 3-5 min walkthrough of all three servers + attacks running. Embed here after recording.

---

## The design tension this repo is actually about

FastMCP's popular **auth-proxy pattern** vs Auth0's recommended **"MCP server as pure OAuth resource server"** pattern.

They have different threat models, different blast radii, and different answers from an enterprise security review. This repo shows the difference concretely — not just in diagrams, but in runnable attack scripts.

---

## Narrative arc

| Server | Auth pattern | One-line verdict |
|--------|-------------|-----------------|
| `server-1-apikey/` | Static hardcoded API key | One leak = unlimited impersonation of any user, forever |
| `server-2-proxy/` | FastMCP auth-proxy (M2M) | Server holds the credential; audit log loses the user |
| `server-3-resourceserver/` | Auth0 resource server + PKCE + RFC 8693 | No credentials on the server; every action attributed to a human |

## Use case

An AI payment agent that can **book and cancel payments on behalf of users**. Dummy users: alice, bob, charlie. No real money.

The tools are intentionally high-stakes: `book_payment`, `cancel_payment`, `list_payments`. Authorization matters when an agent can move money.

---

## Quickstart — Server #1 + Attack #1 (zero Auth0 setup)

```bash
# Terminal 1 — start Server #1
cd server-1-apikey
pip install -r requirements.txt
cp .env.example .env
python server.py
# → Server #1 (API key) starting on http://127.0.0.1:8001

# Terminal 2 — run the leaked-key attack
cd attacks
pip install -r requirements.txt
python 01_leaked_key_replay.py
```

Expected output:
```
==============================================================
  Attack #1: Leaked API Key Replay
==============================================================

[1/3] Attacker reads alice's payment history using leaked key...
  ✗ ATTACK SUCCEEDED — server returned 2 payments for user 'alice' — data exposed

[2/3] Attacker books a fraudulent payment ON BEHALF OF alice...
  ✗ ATTACK SUCCEEDED — booked $9,999.00 from alice's account → 'Attacker LLC'

[3/3] Attacker now acts as a DIFFERENT user (bob)...
  ✗ ATTACK SUCCEEDED — booked $500.00 from bob's account using the same key
```

---

## Auth0 setup (for Server #2 and #3)

```bash
cp .env.example .env
# Fill in AUTH0_DOMAIN, AUTH0_MGMT_CLIENT_ID, AUTH0_MGMT_CLIENT_SECRET

cd setup
pip install auth0-python python-dotenv
python provision_auth0.py   # creates Auth0 apps/APIs, writes IDs back to .env
```

Then follow the individual server READMEs.

---

## Repo structure

```
/
├── README.md
├── .env.example                   # All env vars, with comments
├── server-1-apikey/               # Static API key — zero external deps
│   ├── server.py
│   ├── data.py                    # Dummy payment data (alice, bob, charlie)
│   ├── requirements.txt
│   └── .env.example
├── server-2-proxy/                # FastMCP auth-proxy with Auth0 M2M
│   └── README.md                  # (implementation: author)
├── server-3-resourceserver/       # Auth0 resource server + PKCE + RFC 8693
│   └── README.md                  # (implementation: author)
├── attacks/                       # Misbehaving clients — the blog post's evidence
│   ├── 01_leaked_key_replay.py    # ← Working now
│   ├── 02_token_replay.py         # Stub — after server-2
│   ├── 03_cross_server_token.py   # Stub — after server-3 (audience mismatch)
│   ├── 04_confused_deputy.py      # Stub — after server-3 (sub vs user_id)
│   ├── requirements.txt
│   └── README.md
├── setup/                         # Auth0 provisioning
│   └── README.md
└── docs/
    └── threat-model.md            # Threat model + OWASP Agentic Top 10 mapping
```

---

## Audit log comparison

**Server #1 (API key):**
```
AUDIT | action=book_payment | user_id=alice | amount=9999.00 | to='Attacker LLC' | auth=api_key
```
*Who authorized this? Unknown. Which agent? Unknown. On whose behalf? Self-reported by the caller.*

**Server #3 (resource server + token exchange):**
```
AUDIT | action=book_payment | sub=auth0|alice123 | user_id=alice | amount=250.00 | to='Landlord Corp.' | agent_session=sess_abc | token_exchange=downstream_pay_api | auth=jwt
```
*User identity from the signed token. Agent session tracked. Downstream call scoped and attributed.*

---

## Threat model summary

See `docs/threat-model.md` for the full breakdown. Short version:

- **Server #1 blast radius:** unlimited (one key = all users, all tools, forever)
- **Server #2 blast radius:** bounded by M2M scope, but MCP server holds a secret that can issue tokens
- **Server #3 blast radius:** minimal — server holds no credentials, tokens are scoped, attributed, and short-lived

---

## Related reading

- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Auth0 docs — Calling APIs](https://auth0.com/docs/get-started/apis)
- [FastMCP — Authentication](https://gofastmcp.com/servers/auth)
- [OWASP Agentic AI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
