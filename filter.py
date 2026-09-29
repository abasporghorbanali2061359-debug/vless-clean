import base64
import json
import os
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from collections import defaultdict

SOURCE = SOURCE = "https://sub.vlessfo.ru/vlessforu/working_configs.txt"

BAD_TRUE = {"1", "true", "yes", "on"}

MAX_OUTPUT = 30
MAX_PER_HOST = 2
TIMEOUT = 7
XRAY = "xray"
TEST_URL = "https://www.gstatic.com/generate_204"


def decode_subscription(raw):
    raw = raw.strip()

    if raw.startswith("vless://"):
        return raw

    try:
        return base64.b64decode(
            raw + "=" * (-len(raw) % 4)
        ).decode("utf-8")
    except Exception:
        return raw


def unsafe(uri):
    try:
        q = urllib.parse.parse_qs(
            urllib.parse.urlsplit(uri).query,
            keep_blank_values=True
        )

        q = {
            k.lower(): [v.lower() for v in values]
            for k, values in q.items()
        }

        return (
            any(v in BAD_TRUE for v in q.get("allowinsecure", []))
            or any(v in BAD_TRUE for v in q.get("insecure", []))
            or any(v == "unsafe" for v in q.get("fp", []))
        )

    except Exception:
        return True


def one(q, key, default=""):
    return q.get(key, [default])[0]


def make_config(uri, socks_port):
    p = urllib.parse.urlsplit(uri)

    if not p.hostname or not p.port or not p.username:
        raise ValueError("Invalid VLESS URI")

    q = urllib.parse.parse_qs(
        p.query,
        keep_blank_values=True
    )

    network = one(q, "type", "tcp")
    security = one(q, "security", "none")

    stream = {
        "network": network,
        "security": security
    }

    if network == "ws":
        stream["wsSettings"] = {
            "path": urllib.parse.unquote(
                one(q, "path", "/")
            ),
            "headers": {
                "Host": one(
                    q,
                    "host",
                    one(q, "sni", "")
                )
            }
        }

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": one(
                q,
                "serviceName",
                one(q, "service_name", "")
            )
        }

    if security == "tls":
        stream["tlsSettings"] = {
            "serverName": one(
                q,
                "sni",
                p.hostname
            ),
            "fingerprint": one(
                q,
                "fp",
                "chrome"
            ),
            "allowInsecure": False
        }

    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": one(
                q,
                "sni",
                p.hostname
            ),
            "fingerprint": one(
                q,
                "fp",
                "chrome"
            ),
            "publicKey": one(q, "pbk"),
            "shortId": one(q, "sid"),
            "spiderX": urllib.parse.unquote(
                one(q, "spx", "/")
            )
        }

    user = {
        "id": p.username,
        "encryption": one(
            q,
            "encryption",
            "none"
        )
    }

    flow = one(q, "flow")

    if flow:
        user["flow"] = flow

    return {
        "log": {
            "loglevel": "none"
        },

        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                }
            }
        ],

        "outbounds": [
            {
                "protocol": "vless",

                "settings": {
                    "vnext": [
                        {
                            "address": p.hostname,
                            "port": p.port,
                            "users": [user]
                        }
                    ]
                },

                "streamSettings": stream
            }
        ]
    }


def test_vless(uri, index):
    socks_port = 20000 + (index % 30000)

    process = None
    config_path = None

    try:
        config = make_config(
            uri,
            socks_port
        )

        fd, config_path = tempfile.mkstemp(
            suffix=".json"
        )

        with os.fdopen(fd, "w") as f:
            json.dump(config, f)

        process = subprocess.Popen(
            [
                XRAY,
                "run",
                "-c",
                config_path
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(0.6)

        start = time.monotonic()

        result = subprocess.run(
            [
                "curl",
                "-fsS",
                "--max-time",
                str(TIMEOUT),

                "--socks5-hostname",
                f"127.0.0.1:{socks_port}",

                "-o",
                "/dev/null",

                "-w",
                "%{http_code}",

                TEST_URL
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT + 2
        )

        latency = (
            time.monotonic() - start
        ) * 1000

        if (
            result.returncode == 0
            and result.stdout.strip()
            in {"200", "204"}
        ):
            return True, latency

    except Exception:
        pass

    finally:
        if process:
            process.terminate()

            try:
                process.wait(timeout=1)
            except Exception:
                process.kill()

        if config_path:
            try:
                os.remove(config_path)
            except OSError:
                pass

    return False, 999999


raw = urllib.request.urlopen(
    SOURCE,
    timeout=30
).read().decode(
    "utf-8",
    "replace"
)


lines = [
    line.strip()
    for line
    in decode_subscription(raw).splitlines()
    if line.strip()
]


safe = [
    line
    for line in lines
    if line.startswith("vless://")
    and not unsafe(line)
]


safe = list(
    dict.fromkeys(safe)
)


print(
    f"source={len(lines)} "
    f"safe_unique={len(safe)}"
)


working = []


for index, uri in enumerate(safe):

    good, latency = test_vless(
        uri,
        index
    )

    if good:

        host = (
            urllib.parse.urlsplit(uri)
            .hostname
            or ""
        ).lower()

        working.append(
            (
                latency,
                host,
                uri
            )
        )

        print(
            f"PASS "
            f"{len(working)} "
            f"host={host} "
            f"latency={latency:.0f}ms"
        )


print(
    f"total_real_working="
    f"{len(working)}"
)


working.sort(
    key=lambda item: item[0]
)


selected = []

host_count = defaultdict(int)


for latency, host, uri in working:

    if host_count[host] >= MAX_PER_HOST:
        continue

    selected.append(
        (
            latency,
            uri
        )
    )

    host_count[host] += 1

    if len(selected) >= MAX_OUTPUT:
        break


if len(selected) < MAX_OUTPUT:

    already = {
        uri
        for _, uri in selected
    }

    for latency, host, uri in working:

        if uri in already:
            continue

        selected.append(
            (
                latency,
                uri
            )
        )

        already.add(uri)

        if len(selected) >= MAX_OUTPUT:
            break


clean = [
    uri
    for latency, uri
    in selected[:MAX_OUTPUT]
]


plain = "\n".join(clean)

if clean:
    plain += "\n"


payload = base64.b64encode(
    plain.encode("utf-8")
).decode("ascii")


with open(
    "sub.txt",
    "w",
    encoding="utf-8"
) as output:

    output.write(payload)
    output.write("\n")


print(
    f"selected="
    f"{len(clean)} "
    f"unique_hosts="
    f"{len(set(urllib.parse.urlsplit(x).hostname for x in clean))}"
    )
