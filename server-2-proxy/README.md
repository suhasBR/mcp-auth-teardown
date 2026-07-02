# server-2-proxy/

**FastMCP auth-proxy approach** — convenient and popular, with caveats named precisely.

## What this server does

Acts as an OAuth 2.0 client on behalf of the AI agent. The MCP server itself
fetches tokens from Auth0 using a confidential M2M client credential, then
forwards them (or uses them directly) when calling downstream services.

## The design tension (this is the centerpiece of the blog post)

FastMCP's auth-proxy pattern is popular because it's easy: the MCP server
handles Auth0 interaction so the agent host doesn't have to. But this means:

1. The MCP server holds a long-lived client secret (M2M credential)
2. The token is issued to the *server*, not to the *user* — there is no
   delegated identity in the standard PKCE sense
3. If the MCP server is compromised, the attacker inherits a token with
   broad scopes and no user binding
4. Audit logs show "server called API" — not "alice asked agent to call API"

## TODO (author writes)

This is where **you** implement:
- Auth0 M2M client credential flow (`client_credentials` grant)
- Token validation middleware (JWT verification against Auth0 JWKS)
- The FastMCP auth-proxy pattern (server fetches token, attaches to outbound calls)

FastMCP has built-in OAuth support — wire it to your Auth0 tenant.

## Files to create

```
server-2-proxy/
├── server.py          # FastMCP server + Auth0 auth-proxy wiring (YOU write)
├── auth.py            # Auth0 token validation (YOU write — interview-defensible)
├── data.py            # Symlink or copy from server-1-apikey/data.py
├── requirements.txt
└── .env.example
```

## Auth0 resources needed

- Application: Machine-to-Machine (server-2-proxy)
- API: `api://payment-agent-v2` (or your preferred identifier)
- Scopes: `payments:read`, `payments:write`, `payments:cancel`

Run `setup/provision_auth0.py` to create these (after you implement it).
