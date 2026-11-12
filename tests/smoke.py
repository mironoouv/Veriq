"""Check the local stack through the web service's same-origin API proxy."""

import json
import os
from urllib.request import urlopen

port = int(os.environ.get("VERIQ_WEB_PORT", "5173"))
base = f"http://127.0.0.1:{port}"

with urlopen(base, timeout=10) as response:
    if b"<title>Veriq</title>" not in response.read():
        raise RuntimeError("Veriq web entry point is missing")

for probe in ("live", "ready"):
    with urlopen(f"{base}/api/v1/health/{probe}", timeout=10) as response:
        if json.load(response) != {"status": "ok"}:
            raise RuntimeError(f"Unexpected {probe} response")

print("Veriq web entry point, API liveness and PostgreSQL readiness are healthy.")
