# SPDX-License-Identifier: Apache-2.0
"""UI-02.2 screenshot helper: local headless Chromium + raw CDP.

Captures full-page screenshots of the console in both themes into
services/console/static/preview/. Run with the project venv python
(needs websocket-client which is installed there)."""

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import websocket

PREVIEW = pathlib.Path(__file__).resolve().parents[1] / "static" / "preview"
PORT = 9223
# Console origin to shoot; keep production on 3412, scratch shots on 3414
CONSOLE_URL = os.environ.get("RAUCLE_CONSOLE_URL", "http://127.0.0.1:3412")


class CDP:
    def __init__(self, url, ws_base):
        self.ws = websocket.create_connection(url, timeout=60, suppress_origin=True)
        self.base = ws_base
        self.mid = 0

    def send(self, method, **params):
        self.mid += 1
        payload = {"id": self.mid, "method": method, "params": params}
        self.ws.send(json.dumps(payload))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})


def new_page(http, url):
    req = urllib.request.Request(f"{http}/json/new?{url}", method="PUT")
    r = urllib.request.urlopen(req, timeout=10)
    return json.loads(r.read())


def shot(http, out_path, theme):
    tab = new_page(http, CONSOLE_URL + "/")
    page_ws = tab["webSocketDebuggerUrl"]
    conn = CDP(page_ws, http)

    # fixed light-theme desktop viewport, then fit-to-content below
    conn.send(
        "Emulation.setDeviceMetricsOverride",
        width=1440,
        height=900,
        deviceScaleFactor=2,
        mobile=False,
    )
    conn.send("Page.enable")
    conn.send("Page.navigate", url=CONSOLE_URL + "/")
    time.sleep(1.0)

    # wait for boot: data-bs-theme set and overview populated
    for _ in range(40):
        expr = "window.overview !== undefined"
        v = conn.send("Runtime.evaluate", expression=expr, returnByValue=True)
        if v.get("result", {}).get("result", {}).get("value"):
            break
        time.sleep(0.5)
    time.sleep(1.5)

    if theme == "dark":
        conn.send("Runtime.evaluate", expression="localStorage.setItem('rc-theme','dark')")
        conn.send("Page.reload")
        time.sleep(2.5)

    height = (
        conn.send(
            "Runtime.evaluate",
            expression="document.documentElement.scrollHeight",
            returnByValue=True,
        )
        .get("result", {})
        .get("result", {})
        .get("value", 2000)
        + 4
    )
    conn.send(
        "Emulation.setDeviceMetricsOverride",
        width=1440,
        height=int(height),
        deviceScaleFactor=2,
        mobile=False,
    )
    conn.send("Page.navigate", url=CONSOLE_URL + "/")
    time.sleep(2.5)
    height = (
        conn.send(
            "Runtime.evaluate",
            expression="document.documentElement.scrollHeight",
            returnByValue=True,
        )
        .get("result", {})
        .get("result", {})
        .get("value", 2000)
        + 80
    )
    conn.send(
        "Emulation.setDeviceMetricsOverride",
        width=1440,
        height=int(height),
        deviceScaleFactor=2,
        mobile=False,
    )
    time.sleep(0.8)
    r = conn.send("Page.captureScreenshot", format="png")
    out_path.write_bytes(base64.b64decode(r["data"]))
    print(out_path, out_path.stat().st_size)


def main():
    http = f"http://127.0.0.1:{PORT}"
    tmp = tempfile.mkdtemp(prefix="console-shots-")
    proc = subprocess.Popen(
        [
            "chromium",
            "--headless=new",
            "--no-first-run",
            f"--user-data-dir={tmp}",
            f"--remote-debugging-port={PORT}",
            "--remote-allow-origins=*",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(http + "/json/version", timeout=2).read()
                break
            except Exception:
                time.sleep(0.3)
        else:
            raise RuntimeError("chrome CDP never came up")
        shot(http, PREVIEW / "console.png", "light")
        shot(http, PREVIEW / "console-dark.png", "dark")
    finally:
        proc.terminate()
        time.sleep(0.5)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
