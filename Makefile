.PHONY: install server1 server2 server3 capture-tokens demo clean-tokens help

help:
	@echo ""
	@echo "  MCP Auth Teardown — Demo Commands"
	@echo "  ─────────────────────────────────"
	@echo "  make install          Install dependencies for all servers and attacks"
	@echo ""
	@echo "  Open 3 terminals and run one per terminal:"
	@echo "  make server1          Start Server #1 (API key, port 8001)"
	@echo "  make server2          Start Server #2 (OAuth proxy, port 8002)"
	@echo "  make server3          Start Server #3 (resource server, port 8003)"
	@echo ""
	@echo "  With all servers running:"
	@echo "  make capture-tokens   Run OAuth flows to capture tokens (opens browser x2)"
	@echo "  make demo             Run all 4 attacks in sequence"
	@echo ""
	@echo "  make clean-tokens     Delete tokens.env (forces re-capture)"
	@echo ""

install:
	pip install -r server-1-apikey/requirements.txt
	pip install -r server-2-proxy/requirements.txt
	pip install -r server-3-resourceserver/requirements.txt
	pip install -r attacks/requirements.txt

server1:
	cd server-1-apikey && python3 server.py

server2:
	cd server-2-proxy && python3 server.py

server3:
	cd server-3-resourceserver && python3 server.py

capture-tokens:
	@echo ""
	@echo "Step 1/2 — Server #2 OAuth flow (browser will open, log in with Auth0)"
	@echo "           Token saved to tokens.env when complete."
	@echo ""
	cd attacks && python3 00_capture_token.py
	@echo ""
	@echo "Step 2/2 — Server #3 PKCE flow (browser will open again)"
	@echo "           Token saved to tokens.env when complete."
	@echo ""
	cd server-3-resourceserver && python3 pkce_client.py
	@echo ""
	@echo "✓ tokens.env populated. Run: make demo"
	@echo ""

demo:
	python3 run_attacks.py

clean-tokens:
	rm -f tokens.env
	@echo "tokens.env deleted. Run: make capture-tokens to re-capture."
