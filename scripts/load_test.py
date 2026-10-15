#!/usr/bin/env python3
"""Transaction-surge test for the FinGuard PoC (run in CloudShell after e2e_test.py).

Phase A  steady  : 10 workers, 300 payment requests  -> baseline latency
Phase B  surge   : 60 workers, 400 payment requests  -> scaling + API throttling
Phase C  flood   : unauthenticated GET flood         -> WAF rate-based block
Results are printed and written to load_results.json for the report.
"""
import json, statistics, time, uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import e2e_test as e

GOOD = {"card_number": e.TEST_PAN, "amount_minor": 4999, "currency": "EUR", "beneficiary_iban": "DE89370400440532013000"}


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))] if values else None


def run(name, workers, n, fn):
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        res = list(pool.map(lambda _: fn(), range(n)))
    dur = time.time() - t0
    codes = Counter(r[0] for r in res)
    ok_lat = [r[3] for r in res if r[0] in (200, 201)]
    summary = {"phase": name, "workers": workers, "requests": n, "duration_s": round(dur, 1),
               "throughput_rps": round(n / dur, 1), "status_codes": dict(codes),
               "p50_ms": round(pct(ok_lat, 50) or 0), "p95_ms": round(pct(ok_lat, 95) or 0),
               "p99_ms": round(pct(ok_lat, 99) or 0), "mean_ms": round(statistics.mean(ok_lat)) if ok_lat else None}
    print(json.dumps(summary))
    return summary


if __name__ == "__main__":
    secret = e.make_user("load.tester")
    token = e.login("load.tester", secret)
    pay = lambda: e.call("POST", "/transactions", token, GOOD, uuid.uuid4().hex)
    results = [run("A-steady", 10, 300, pay)]
    time.sleep(5)
    results.append(run("B-surge", 60, 400, pay))
    time.sleep(5)
    probe = lambda: e.call("GET", "/transactions/00000000-0000-0000-0000-000000000000")
    flood = []
    for wave in range(6):                 # WAF evaluates rate rules with a short delay
        flood.append(run(f"C-flood-wave{wave + 1}", 40, 250, probe))
        if flood[-1]["status_codes"].get(403):
            break
        time.sleep(10)
    results += flood
    json.dump(results, open("load_results.json", "w"), indent=2)
    print("\nwritten load_results.json")
