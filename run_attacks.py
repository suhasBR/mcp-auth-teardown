#!/usr/bin/env python3
"""
Demo orchestrator — runs all 4 attacks in sequence and prints a summary.

Before running:
  Terminal 1:  make server1
  Terminal 2:  make server2
  Terminal 3:  make server3
  Then:        make capture-tokens   (browser opens twice — log in both times)
  Then:        make demo             (or: python run_attacks.py)
"""

import subprocess
import sys
from pathlib import Path

BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"
RED   = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"

TOKENS_ENV = Path("tokens.env")


def check_tokens():
    if not TOKENS_ENV.exists():
        print(f"\n  {YELLOW}[!] tokens.env not found.{RESET}")
        print(f"      Run: make capture-tokens\n")
        sys.exit(1)
    content = TOKENS_ENV.read_text()
    missing = []
    for key in ("SERVER_2_FASTMCP_TOKEN", "ALICE_AUTH0_TOKEN"):
        val = ""
        for line in content.splitlines():
            if line.startswith(f"{key}="):
                val = line.split("=", 1)[1].strip()
        if not val:
            missing.append(key)
    if missing:
        print(f"\n  {YELLOW}[!] Missing tokens in tokens.env: {', '.join(missing)}{RESET}")
        print(f"      Run: make capture-tokens\n")
        sys.exit(1)


def divider(title: str):
    print()
    print(f"{BOLD}{'─' * 62}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─' * 62}{RESET}")
    print()


def run(script: str):
    subprocess.run([sys.executable, script], check=False)


def summary():
    print()
    print(f"{BOLD}{'=' * 62}{RESET}")
    print(f"{BOLD}  SUMMARY — What Each Server Blocks{RESET}")
    print(f"{'=' * 62}{RESET}")
    print(f"""
               Attack #1    Attack #2    Attack #3    Attack #4
               Key Replay   Tkn Replay   Cross-Aud    Conf.Dep.
               ───────────  ───────────  ───────────  ───────────
Server #1      {RED}✗ BREACH{RESET}    {RED}✗ BREACH{RESET}      N/A         {RED}✗ BREACH{RESET}
 (API Key)

Server #2         N/A       {RED}✗ BREACH{RESET}      N/A         {RED}✗ BREACH{RESET}
 (Proxy)

Server #3         N/A          N/A       {GREEN}✓ BLOCK{RESET}     {GREEN}✓ BLOCK{RESET}
 (Resource)
""")
    print(f"{BOLD}The progression:{RESET}")
    print(f"  #1 → #2  Tokens expire (finite window) but proxy holds the secret")
    print(f"  #2 → #3  Audience binding + structural sub binding close both gaps")
    print()


def main():
    check_tokens()

    divider("Attack #1 — Leaked API Key Replay  |  Target: Server #1")
    run("attacks/01_leaked_key_replay.py")

    divider("Attack #2 — Token Replay + Confused Deputy  |  Target: Server #2")
    run("attacks/02_token_replay.py")

    divider("Attack #3 — Cross-Server Token (Aud Mismatch)  |  Target: Server #3")
    run("attacks/03_cross_server_token.py")

    divider("Attack #4 — Confused Deputy  |  All Servers")
    run("attacks/04_confused_deputy.py")

    summary()


if __name__ == "__main__":
    main()
