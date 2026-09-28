import base64
import urllib.parse
import urllib.request

SOURCE = "https://raw.githubusercontent.com/mehrtat/vless-collector/main/sub.txt"
BAD_TRUE = {"1", "true", "yes", "on"}

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
        if any(v in BAD_TRUE for v in q.get("allowinsecure", [])):
            return True
        if any(v in BAD_TRUE for v in q.get("insecure", [])):
            return True
        if any(v == "unsafe" for v in q.get("fp", [])):
            return True
        return False
    except Exception:
        return True

raw = urllib.request.urlopen(SOURCE, timeout=30).read().decode("utf-8", "replace")
lines = [x.strip() for x in decode_subscription(raw).splitlines() if x.strip()]
clean = [x for x in lines if x.startswith("vless://") and not unsafe(x)]
payload = base64.b64encode(("\n".join(clean) + "\n").encode()).decode()
with open("sub.txt", "w", encoding="utf-8") as f:
    f.write(payload + "\n")
print(f"kept={len(clean)} removed={len(lines)-len(clean)} total={len(lines)}")
