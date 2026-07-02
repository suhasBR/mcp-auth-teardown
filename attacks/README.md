# attacks/

Runnable misbehaving clients that prove the security differences between the three servers.
Each script prints legible pass/fail output designed to be quoted directly in the blog post.

## Attack matrix

| Script | Target | Technique | Status |
|--------|--------|-----------|--------|
| `01_leaked_key_replay.py` | Server #1 | Replay a leaked static API key | **Ready** |
| `02_token_replay.py` | Server #2 | Replay an intercepted access token | Stub — implement after server-2 |
| `03_cross_server_token.py` | Server #3 | Use server-2 token against server-3 (audience mismatch) | Stub — implement after server-3 |
| `04_confused_deputy.py` | Server #3 | Alice's token used to act as bob (sub vs user_id mismatch) | Stub — implement after server-3 |

## Quickstart (Attack #1)

```bash
# Terminal 1 — start server-1
cd server-1-apikey
pip install -r requirements.txt
cp .env.example .env
python server.py

# Terminal 2 — run the attack
cd attacks
pip install -r requirements.txt
python 01_leaked_key_replay.py
```

## Output format

Each script prints ✗ (attack succeeded) or ✓ (server blocked it) with a one-line explanation.
The goal: evidence you can paste into the blog post without editing.

## OWASP Agentic Top 10 mapping

Attack #3 and #4 map directly to the OWASP Agentic Top 10 (see `docs/threat-model.md`).
Full mapping will be added as a follow-up post.
