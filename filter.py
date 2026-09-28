import base64
import socket
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCE = "https://raw.githubusercontent.com/mehrtat/vless-collector/main/sub.txt"
BAD_TRUE = {"1", "true", "yes", "on"}
CONNECT_TIMEOUT = 2.5
MAX_WORKERS = 80

def decode_subscription(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("vless://"):
        return raw
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
    except Exception:
        return raw

def unsafe(uri: str) -> bool:
    try:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query, keep_blank_values=True)
        q = {k.lower(): [v.lower() for v in vals] for k, vals in q.items()}
        return (
            any(v in BAD_TRUE for v in q.get("allowinsecure", []))
            or any(v in BAD_TRUE for v in q.get("insecure", []))
            or any(v == "unsafe" for v in q.get("fp", []))
        )
    except Exception:
        return True

def endpoint(uri: str):
    p = urllib.parse.urlsplit(uri)
    if not p.hostname or not p.port:
        raise ValueError("missing host/port")
    return p.hostname, p.port

def reachable(uri: str) -> bool:
    try:
        host, port = endpoint(uri)
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except Exception:
        return False

raw = urllib.request.urlopen(SOURCE, timeout=30).read().decode("utf-8", "replace")
lines = [x.strip() for x in decode_subscription(raw).splitlines() if x.strip()]
safe = [x for x in lines if x.startswith("vless://") and not unsafe(x)]

alive = set()
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
    jobs = {pool.submit(reachable, uri): uri for uri in safe}
    for job in as_completed(jobs):
        uri = jobs[job]
        try:
            if job.result():
                alive.add(uri)
        except Exception:
            pass

clean = [x for x in safe if x in alive]
payload = base64.b64encode(("\n".join(clean) + ("\n" if clean else "")).encode()).decode()
with open("sub.txt", "w", encoding="utf-8") as f:
    f.write(payload + "\n")

print(f"source={len(lines)} safe={len(safe)} tcp_reachable={len(clean)} removed={len(lines)-len(clean)}")
