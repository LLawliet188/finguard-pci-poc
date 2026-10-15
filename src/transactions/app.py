"""FinGuard transaction API - PoC handler.

Handles two routes behind API Gateway (Cognito-authorised):
  POST /transactions        create a payment instruction (idempotent)
  GET  /transactions/{id}   read back a transaction owned by the caller

PCI DSS scope reduction: the primary account number (PAN) is never stored.
It is replaced by a keyed HMAC token computed inside AWS KMS (GenerateMac),
so the HMAC key material never leaves the KMS HSMs. Only the BIN (first six)
and the last four digits are kept for display, as PCI DSS Req. 3.4.1 allows.
"""
import base64
import json
import logging
import os
import re
import time
import uuid
from decimal import Decimal

import boto3
from botocore.config import Config

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

_CFG = Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=2, read_timeout=3)
KMS = boto3.client("kms", config=_CFG)
TABLE = boto3.resource("dynamodb", config=_CFG).Table(os.environ["TABLE_NAME"])
HMAC_KEY_ID = os.environ["HMAC_KEY_ID"]
REVIEW_THRESHOLD = int(os.environ.get("REVIEW_THRESHOLD_MINOR", "500000"))  # 5,000.00

CURRENCIES = {"EUR", "USD", "GBP", "CHF", "PLN", "SEK"}
IBAN_RE = re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$")


def _resp(status, body, extra_headers=None):
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
    }
    if extra_headers:
        headers.update(extra_headers)
    return {"statusCode": status, "headers": headers, "body": json.dumps(body, default=str)}


def luhn_ok(pan: str) -> bool:
    total, alt = 0, False
    for ch in reversed(pan):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def tokenise(pan: str) -> str:
    """Deterministic, non-reversible token: HMAC-SHA256 computed by KMS."""
    mac = KMS.generate_mac(KeyId=HMAC_KEY_ID, MacAlgorithm="HMAC_SHA_256", Message=pan.encode())
    return "tok_" + base64.urlsafe_b64encode(mac["Mac"]).decode().rstrip("=")[:43]


def _caller(event):
    claims = (event.get("requestContext", {}).get("authorizer") or {}).get("claims") or {}
    return claims.get("sub"), claims.get("cognito:username")


def create_transaction(event):
    sub, username = _caller(event)
    if not sub:
        return _resp(401, {"error": "unauthenticated"})
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    idem = headers.get("idempotency-key", "")
    if not re.fullmatch(r"[A-Za-z0-9\-]{16,64}", idem):
        return _resp(400, {"error": "Idempotency-Key header (16-64 chars) is required"})
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _resp(400, {"error": "body must be JSON"})

    pan = str(body.get("card_number", "")).replace(" ", "")
    amount = body.get("amount_minor")
    currency = str(body.get("currency", "")).upper()
    iban = str(body.get("beneficiary_iban", "")).replace(" ", "").upper()

    if not (pan.isdigit() and 13 <= len(pan) <= 19 and luhn_ok(pan)):
        return _resp(422, {"error": "card_number failed validation"})
    if not isinstance(amount, int) or not (1 <= amount <= 10_000_000):
        return _resp(422, {"error": "amount_minor must be an integer between 1 and 10,000,000"})
    if currency not in CURRENCIES:
        return _resp(422, {"error": "unsupported currency"})
    if not IBAN_RE.match(iban):
        return _resp(422, {"error": "beneficiary_iban is not a valid IBAN format"})

    txn_id = str(uuid.uuid4())
    now = int(time.time())
    status = "PENDING_REVIEW" if amount >= REVIEW_THRESHOLD else "AUTHORISED"
    item = {
        "pk": f"USER#{sub}",
        "sk": f"TXN#{txn_id}",
        "txn_id": txn_id,
        "idempotency_key": idem,
        "pan_token": tokenise(pan),
        "pan_display": f"{pan[:6]}{'*' * (len(pan) - 10)}{pan[-4:]}",
        "amount_minor": Decimal(amount),
        "currency": currency,
        "beneficiary_iban_masked": iban[:4] + "*" * (len(iban) - 8) + iban[-4:],
        "status": status,
        "created_at": Decimal(now),
        "created_by": username,
    }
    # Idempotency: a guard item keyed on the client key makes retries safe.
    # (the resource-level client serialises native Python types itself)
    try:
        TABLE.meta.client.transact_write_items(
            TransactItems=[
                {"Put": {"TableName": TABLE.name,
                         "Item": {"pk": f"IDEM#{sub}#{idem}", "sk": "IDEM",
                                  "txn_id": txn_id, "expires_at": Decimal(now + 86400)},
                         "ConditionExpression": "attribute_not_exists(pk)"}},
                {"Put": {"TableName": TABLE.name, "Item": item,
                         "ConditionExpression": "attribute_not_exists(pk)"}},
            ]
        )
    except TABLE.meta.client.exceptions.TransactionCanceledException:
        prev = TABLE.get_item(Key={"pk": f"IDEM#{sub}#{idem}", "sk": "IDEM"}, ConsistentRead=True).get("Item")
        if prev:
            original = TABLE.get_item(Key={"pk": f"USER#{sub}", "sk": f"TXN#{prev['txn_id']}"}).get("Item")
            return _resp(200, _public(original), {"Idempotent-Replay": "true"})
        raise
    LOG.info(json.dumps({"event": "txn_created", "txn_id": txn_id, "status": status,
                         "amount_minor": amount, "currency": currency}))  # no PAN in logs
    return _resp(201, _public(item))


def get_transaction(event):
    sub, _ = _caller(event)
    if not sub:
        return _resp(401, {"error": "unauthenticated"})
    txn_id = (event.get("pathParameters") or {}).get("id", "")
    try:
        uuid.UUID(txn_id)
    except ValueError:
        return _resp(400, {"error": "invalid id"})
    item = TABLE.get_item(Key={"pk": f"USER#{sub}", "sk": f"TXN#{txn_id}"}).get("Item")
    if not item:
        return _resp(404, {"error": "not found"})  # also hides other users' records
    return _resp(200, _public(item))


def _public(item):
    keep = ("txn_id", "status", "amount_minor", "currency", "pan_display",
            "beneficiary_iban_masked", "created_at")
    return {k: (int(v) if isinstance(v, Decimal) else v) for k, v in item.items() if k in keep}


def handler(event, context):
    route = (event.get("httpMethod"), event.get("resource"))
    try:
        if route == ("POST", "/transactions"):
            return create_transaction(event)
        if route == ("GET", "/transactions/{id}"):
            return get_transaction(event)
        return _resp(404, {"error": "route not found"})
    except Exception:  # noqa: BLE001 - never leak internals to the client
        LOG.exception("unhandled error")
        return _resp(500, {"error": "internal error", "request_id": getattr(context, "aws_request_id", None)})
