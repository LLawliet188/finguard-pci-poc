"""Unit tests for the transaction handler (DynamoDB mocked with moto, KMS stubbed)."""
import importlib
import json
import os
import sys
import uuid

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "transactions"))
os.environ.update(AWS_DEFAULT_REGION="eu-central-1", TABLE_NAME="finguard-transactions",
                  HMAC_KEY_ID="alias/finguard-pan-token", AWS_ACCESS_KEY_ID="x", AWS_SECRET_ACCESS_KEY="x")

VISA_TEST = "4111111111111111"


@pytest.fixture()
def app():
    with mock_aws():
        boto3.client("dynamodb").create_table(
            TableName="finguard-transactions", BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}])
        mod = importlib.reload(importlib.import_module("app"))
        mod.KMS.generate_mac = lambda **kw: {"Mac": b"\x01" * 32}
        yield mod


def _event(body, idem=None, method="POST", resource="/transactions", path=None, sub="user-1"):
    return {"httpMethod": method, "resource": resource, "pathParameters": path,
            "headers": {"Idempotency-Key": idem or uuid.uuid4().hex},
            "body": json.dumps(body),
            "requestContext": {"authorizer": {"claims": {"sub": sub, "cognito:username": "alice"}}}}


GOOD = {"card_number": VISA_TEST, "amount_minor": 12_550, "currency": "EUR", "beneficiary_iban": "DE89370400440532013000"}


def test_luhn(app):
    assert app.luhn_ok(VISA_TEST) and not app.luhn_ok("4111111111111112")


def test_create_masks_and_never_stores_pan(app):
    r = app.handler(_event(GOOD), None)
    assert r["statusCode"] == 201
    body = json.loads(r["body"])
    assert body["pan_display"] == "411111******1111" and body["status"] == "AUTHORISED"
    raw = json.dumps(app.TABLE.scan()["Items"], default=str)
    assert VISA_TEST not in raw and "tok_" in raw


def test_idempotent_replay_returns_same_transaction(app):
    key = uuid.uuid4().hex
    first = json.loads(app.handler(_event(GOOD, idem=key), None)["body"])
    second = app.handler(_event(GOOD, idem=key), None)
    assert second["statusCode"] == 200 and second["headers"]["Idempotent-Replay"] == "true"
    assert json.loads(second["body"])["txn_id"] == first["txn_id"]


def test_high_value_goes_to_review(app):
    r = app.handler(_event({**GOOD, "amount_minor": 750_000}), None)
    assert json.loads(r["body"])["status"] == "PENDING_REVIEW"


@pytest.mark.parametrize("patch,code", [({"card_number": "4111111111111112"}, 422),
                                        ({"currency": "XYZ"}, 422),
                                        ({"amount_minor": 0}, 422),
                                        ({"beneficiary_iban": "NOT-AN-IBAN"}, 422)])
def test_validation(app, patch, code):
    assert app.handler(_event({**GOOD, **patch}), None)["statusCode"] == code


def test_missing_idempotency_key(app):
    ev = _event(GOOD)
    ev["headers"] = {}
    assert app.handler(ev, None)["statusCode"] == 400


def test_tenant_isolation(app):
    created = json.loads(app.handler(_event(GOOD, sub="alice"), None)["body"])
    ev = _event({}, method="GET", resource="/transactions/{id}", path={"id": created["txn_id"]}, sub="mallory")
    assert app.handler(ev, None)["statusCode"] == 404
    ev = _event({}, method="GET", resource="/transactions/{id}", path={"id": created["txn_id"]}, sub="alice")
    assert app.handler(ev, None)["statusCode"] == 200
