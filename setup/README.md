# setup/

Auth0 provisioning scripts — run these once to create the resources needed for
Server #2 and Server #3. Server #1 needs nothing here.

## What gets provisioned

| Resource | Used by | Notes |
|----------|---------|-------|
| M2M Application: `mcp-payment-agent-proxy` | Server #2 | Holds client secret for auth-proxy pattern |
| API: `api://payment-agent-v2` | Server #2 | Identifier + scopes for the proxy server |
| API: `api://payment-agent-v3` | Server #3 | Identifier + scopes for the resource server |
| Regular Web App: `mcp-payment-agent-pkce` | Server #3 client | PKCE client for the agent host |

## Scopes provisioned on both APIs

- `payments:read` — list payments for a user
- `payments:write` — book a new payment
- `payments:cancel` — cancel a pending payment

## TODO (author writes or reviews)

`provision_auth0.py` — Python script using the Auth0 Management API to create
all of the above. Use `AUTH0_DOMAIN`, `AUTH0_MGMT_CLIENT_ID`, and
`AUTH0_MGMT_CLIENT_SECRET` from your `.env`.

Alternatively: Terraform using the `auth0` provider (cleaner for repeatability).

## Quickstart (once script is implemented)

```bash
cd setup
pip install auth0-python python-dotenv
cp ../.env.example ../.env
# Fill in AUTH0_DOMAIN, AUTH0_MGMT_CLIENT_ID, AUTH0_MGMT_CLIENT_SECRET
python provision_auth0.py
```

The script should print the generated client IDs and API identifiers,
then write them into `../.env` automatically.
