#!/usr/bin/env python3
"""End-to-end verification of the deployed FinGuard PoC (run in AWS CloudShell).

1. Creates a test customer in Cognito and enrols a TOTP authenticator (MFA ON).
2. Signs in with password + one-time code and obtains an ID token.
3. Exercises the API: happy path, idempotent replay, validation, tenant isolation,
   missing token, WAF SQL-injection block.
4. Proves at the data layer that no PAN is stored (scan of the table).
Only the Python standard library and boto3 are used (both present in CloudShell).
"""
import base64, hashlib, hmac, json, os, struct, sys, time, urllib.request, urllib.error, uuid
import boto3

STACK = os.environ.get("APP_STACK", "finguard-app")
cfn = boto3.client("cloudformation")
out = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=STACK)["Stacks"][0]["Outputs"]}
API, POOL, CLIENT, TABLE = out["ApiUrl"], out["UserPoolId"], out["UserPoolClientId"], out["TableName"]
idp = boto3.client("cognito-idp")
PASSWORD = "Fg!" + uuid.uuid4().hex[:12] + "Aa9#"
TEST_PAN = "4111111111111111"          # public Visa test number - never a real card


def totp(secret_b32, step=30, digits=6, t=None):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = int((t or time.time()) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def wait_for_fresh_window():
    # avoid reusing a code that Cognito has already accepted in this 30 s window
    time.sleep(31 - (time.time() % 30))


def make_user(name):
    try:
        idp.admin_delete_user(UserPoolId=POOL, Username=name)
    except idp.exceptions.UserNotFoundException:
        pass
    idp.admin_create_user(UserPoolId=POOL, Username=name, MessageAction="SUPPRESS")
    idp.admin_set_user_password(UserPoolId=POOL, Username=name, Password=PASSWORD, Permanent=True)
    r = idp.initiate_auth(ClientId=CLIENT, AuthFlow="USER_PASSWORD_AUTH",
                          AuthParameters={"USERNAME": name, "PASSWORD": PASSWORD})
    assert r["ChallengeName"] == "MFA_SETUP", r.get("ChallengeName")
    assoc = idp.associate_software_token(Session=r["Session"])
    secret = assoc["SecretCode"]
    v = idp.verify_software_token(Session=assoc["Session"], UserCode=totp(secret), FriendlyDeviceName="ci-authenticator")
    assert v["Status"] == "SUCCESS"
    r = idp.respond_to_auth_challenge(ClientId=CLIENT, ChallengeName="MFA_SETUP", Session=v["Session"],
                                      ChallengeResponses={"USERNAME": name})
    return secret


def login(name, secret):
    wait_for_fresh_window()
    r = idp.initiate_auth(ClientId=CLIENT, AuthFlow="USER_PASSWORD_AUTH",
                          AuthParameters={"USERNAME": name, "PASSWORD": PASSWORD})
    assert r["ChallengeName"] == "SOFTWARE_TOKEN_MFA", "MFA was not enforced!"
    r = idp.respond_to_auth_challenge(ClientId=CLIENT, ChallengeName="SOFTWARE_TOKEN_MFA", Session=r["Session"],
                                      ChallengeResponses={"USERNAME": name, "SOFTWARE_TOKEN_MFA_CODE": totp(secret)})
    return r["AuthenticationResult"]["IdToken"]


def call(method, path, token=None, body=None, idem=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", token)
    if idem:
        req.add_header("Idempotency-Key", idem)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}"), dict(r.headers), (time.perf_counter() - t0) * 1000
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = {"raw": raw[:120].decode(errors="replace")}
        return e.code, data, dict(e.headers), (time.perf_counter() - t0) * 1000


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")


if __name__ == "__main__":
    print(f"API: {API}\n")
    s_alice, s_mallory = make_user("alice.tester"), make_user("mallory.tester")
    check("MFA enrolment (TOTP) completed for test users", True)
    tok_a = login("alice.tester", s_alice)
    check("Sign-in requires password + TOTP (SOFTWARE_TOKEN_MFA challenge)", bool(tok_a))

    good = {"card_number": TEST_PAN, "amount_minor": 12550, "currency": "EUR", "beneficiary_iban": "DE89370400440532013000"}
    st, _, _, ms = call("POST", "/transactions", None, good, uuid.uuid4().hex)
    check("Request without token rejected", st == 401, f"-> {st}")

    key = uuid.uuid4().hex
    st, body, _, ms = call("POST", "/transactions", tok_a, good, key)
    check("Create payment (201, PAN masked)", st == 201 and body.get("pan_display") == "411111******1111", f"-> {st} {body} {ms:.0f} ms")
    txn = body.get("txn_id")

    st, body2, hdr, _ = call("POST", "/transactions", tok_a, good, key)
    check("Idempotent replay returns same txn", st == 200 and body2.get("txn_id") == txn, f"-> {st} replay={hdr.get('Idempotent-Replay')}")

    st, body, _, _ = call("POST", "/transactions", tok_a, {**good, "amount_minor": 750000}, uuid.uuid4().hex)
    check("High-value payment routed to PENDING_REVIEW", body.get("status") == "PENDING_REVIEW", f"-> {body.get('status')}")

    st, body, _, _ = call("POST", "/transactions", tok_a, {**good, "card_number": "4111111111111112"}, uuid.uuid4().hex)
    check("Invalid card (Luhn) rejected", st == 422, f"-> {st}")
    st, body, _, _ = call("POST", "/transactions", tok_a, {**good, "cvv": "123"}, uuid.uuid4().hex)
    check("Unexpected field (CVV) rejected by API Gateway schema", st == 400, f"-> {st} {body}")

    st, body, _, _ = call("GET", f"/transactions/{txn}", tok_a)
    check("Owner can read own transaction", st == 200 and body.get("txn_id") == txn, f"-> {st}")
    tok_m = login("mallory.tester", s_mallory)
    st, body, _, _ = call("GET", f"/transactions/{txn}", tok_m)
    check("Other customer cannot read it (tenant isolation)", st == 404, f"-> {st}")

    st, body, _, _ = call("GET", f"/transactions/{txn}?filter=1%27%20OR%20%271%27%3D%271%27%20--", tok_a)
    check("SQL-injection probe blocked by AWS WAF", st == 403, f"-> {st}")

    items = boto3.resource("dynamodb").Table(TABLE).scan()["Items"]
    raw = json.dumps(items, default=str)
    check("No PAN stored at rest (table scan)", TEST_PAN not in raw and "tok_" in raw, f"-> {len(items)} items scanned")

    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    sys.exit(0 if passed == len(RESULTS) else 1)
