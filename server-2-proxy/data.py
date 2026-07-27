"""Dummy payment data — no real money, no real accounts."""
import uuid
from copy import deepcopy
from datetime import datetime, timezone

USERS: dict[str, dict] = {
    # auth0_sub: paste each user's Auth0 subject claim here.
    # Find it by decoding any Auth0 JWT for that user, or from the Auth0 dashboard
    # (Users → select user → user_id field). Format: "auth0|<hex>".
    # Leave blank ("") to disable sub binding for that user during development.
    "alice":   {"name": "Alice Chen",    "account": "ACC-001", "balance": 5000.00,  "auth0_sub": "auth0|69babdf573424c2fb4e7eb58"},
    "bob":     {"name": "Bob Ramos",     "account": "ACC-002", "balance": 3200.50,  "auth0_sub": "auth0|bob_placeholder"},
    "charlie": {"name": "Charlie Kim",   "account": "ACC-003", "balance": 12000.00, "auth0_sub": ""},
}

PAYMENTS: list[dict] = [
    {
        "id": "pay-001",
        "user_id": "alice",
        "amount": 150.00,
        "to": "Netflix Inc.",
        "memo": "Monthly subscription",
        "status": "completed",
        "created_at": "2026-06-01T10:00:00Z",
    },
    {
        "id": "pay-002",
        "user_id": "bob",
        "amount": 500.00,
        "to": "Landlord Corp.",
        "memo": "June rent",
        "status": "pending",
        "created_at": "2026-06-15T09:00:00Z",
    },
    {
        "id": "pay-003",
        "user_id": "alice",
        "amount": 75.00,
        "to": "Spotify AB",
        "memo": "Annual plan",
        "status": "pending",
        "created_at": "2026-06-18T14:30:00Z",
    },
]


def add_payment(user_id: str, amount: float, to: str, memo: str) -> dict:
    payment = {
        "id": f"pay-{uuid.uuid4().hex[:6]}",
        "user_id": user_id,
        "amount": round(amount, 2),
        "to": to,
        "memo": memo,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    PAYMENTS.append(payment)
    USERS[user_id]["balance"] = round(USERS[user_id]["balance"] - amount, 2)
    return deepcopy(payment)


def cancel_payment_by_id(payment_id: str) -> dict:
    for p in PAYMENTS:
        if p["id"] == payment_id:
            if p["status"] != "pending":
                return {"ok": False, "error": f"Payment {payment_id!r} is '{p['status']}' — only 'pending' payments can be cancelled"}
            p["status"] = "cancelled"
            USERS[p["user_id"]]["balance"] = round(USERS[p["user_id"]]["balance"] + p["amount"], 2)
            return {"ok": True, "payment_id": payment_id, "status": "cancelled", "refunded": p["amount"]}
    return {"ok": False, "error": f"Payment {payment_id!r} not found"}
