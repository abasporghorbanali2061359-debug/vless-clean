import base64
import socket
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCE = "https://raw.githubusercontent.com/mehrtat/vless-collector/main/sub.txt"
BAD_TRUE = {"1", "true", "yes", "on"}
CONNECT_TIMEOUT = 2.5
MAX_WORKERS = 60
TESTS = 3
MIN_SUCCESSES = 3
PAUSE = 0.25

def decode_subscription(raw):
    raw = raw.strip()
    if raw.startswith("vless://"):
        return raw
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
    except Exception:
        return raw

def unsafe(uri):
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query, keep_blank_values=True)
        q = {k.lower(): [v.lower() for v in vals] for k, vals in q.items()}
        return (any(v in BAD_TRUE for v in q.get("allowinsecure", []))
                or any(v in BAD_TRUE for v in q.get("insecure", []))
                or any(v == "unsafe" for v in q.get("fp", [])))
    except Exception:
        return True

def endpoint(uri):
    p = urllib.parse.urlsplit(uri)
    if not p.hostname or not p.port:
        raise ValueError("missing host/port")
    return p.hostname, p.port

def stable(uri):
    try:
        host, port = endpoint(uri)
        ok = 0
        latencies = []
        for n in range(TESTS):
            start = time.monotonic()
            try:
                with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
                    ok += 1
                    latencies.append((time.monotonic() - start) * 1000)
            except Exception:
                pass
            if n + 1 < TESTS:
                time.sleep(PAUSE)
        if ok >= MIN_SUCCESSES:
            return True, sum(latencies) / len(latencies)
    except Exception:
        pass
    return False, 999999.0

raw = urllib.request.urlopen(SOURCE, timeout=30).read().decode("utf-8", "replace")
lines = [x.strip() for x in decode_subscription(raw).splitlines() if x.strip()]
safe = [x for x in lines if x.startswith("vless://") and not unsafe(x)]

# Remove exact duplicate configurations while preserving source order.
safe = list(dict.fromkeys(safe))

results = []
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
    jobs = {pool.submit(stable, uri): uri for uri in safe}
    for job in as_completed(jobs):
        uri = jobs[job]
        try:
            good, latency = job.result()
            if good:
                results.append((latency, uri))
        except Exception:
            pass

# Put consistently reachable, lower TCP-connect-latency endpoints first.
results.sort(key=lambda x: x[0])
clean = [uri for _, uri in results]

payload = base64.b64encode(("\n".join(clean) + ("\n" if clean else "")).encode()).decode()
with open("sub.txt", "w", encoding="utf-8") as f:
    f.write(payload + "\n")

print(f"source={len(lines)} safe_unique={len(safe)} stable_3_of_3={len(clean)} removed={len(lines)-len(clean)}")
