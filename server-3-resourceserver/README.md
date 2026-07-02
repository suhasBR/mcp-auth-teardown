# server-3-resourceserver/

**Auth0-recommended resource-server model** — the one enterprises should ship.

## What makes this different from server-2

The MCP server is a **pure OAuth resource server**. It does not hold any
Auth0 client credentials. It only validates incoming JWTs (issued by Auth0)
and enforces claims. Token issuance is entirely the agent host's problem.

This separates concerns correctly:
- **Agent host** → runs PKCE flow, holds refresh token, manages consent
- **MCP server** → validates tokens, enforces scopes and sub binding, logs

## The RFC 8693 layer (token exchange / on-behalf-of)

When the AI agent needs to call a downstream API (e.g., a payment processor),
it cannot forward its own token — the downstream API has a different audience.
RFC 8693 token exchange solves this cleanly:

1. Agent presents its access token (aud = MCP server)  
2. MCP server exchanges it at Auth0 for a scoped downstream token (aud = payment API)
3. Downstream call is made with the narrower token
4. Audit log shows the full delegation chain: user → agent → MCP server → downstream

This is what enterprise security reviews approve.

## TODO (author writes)

- JWT validation middleware (verify `iss`, `aud`, `exp`, `scope`)
- `sub` ↔ `user_id` binding check in each tool (prevents confused-deputy)
- RFC 8693 token exchange call to Auth0 (on-behalf-of flow)
- The PKCE client (or doc that the agent host runs it — clarify the boundary)

## Auth0 resources needed

- API: `api://payment-agent-v3`
- Scopes: `payments:read`, `payments:write`, `payments:cancel`
- Token exchange enabled on the Auth0 tenant (Enterprise feature or Actions workaround)

## Files to create

```
server-3-resourceserver/
├── server.py          # FastMCP server — no Auth0 creds held here (YOU wire)
├── auth.py            # JWT validation + sub binding (YOU write — interview-defensible)
├── token_exchange.py  # RFC 8693 on-behalf-of flow (YOU write)
├── data.py            # Symlink or copy from server-1-apikey/data.py
├── requirements.txt
└── .env.example
```
