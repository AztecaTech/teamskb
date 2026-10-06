import base64
import http.client
import json
import select
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(len(body)).encode())

    def log_message(self, *_):
        pass


def serve():
    servers = [ThreadingHTTPServer(("0.0.0.0", port), Handler) for port in (8080, 3978)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


def post(port, body):
    request = urllib.request.Request(f"https://localhost:{port}/api/ask", data=body, method="POST")
    try:
        with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=8) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def probe(port):
    status, body = post(port, b"hello")
    if status != 200 or body != b"5":
        raise SystemExit(f"small request did not reach the upstream: status={status}, body={body!r}")

    image = base64.b64encode(b"x" * (1 << 20)).decode()
    activity = json.dumps({"attachments": [{"content": image}]}).encode()
    status, body = post(port, activity)
    if status != 200 or body != str(len(activity)).encode():
        raise SystemExit(f"1 MiB base64 image activity did not pass: status={status}, body={body!r}")

    status, _ = post(port, b"x" * ((2 << 20) + 1))
    if status != 413:
        raise SystemExit(f"request over 2 MiB returned HTTP {status}, expected 413")

    connection = http.client.HTTPSConnection(
        "localhost", port, context=ssl._create_unverified_context(), timeout=15
    )
    connection.putrequest("POST", "/api/ask")
    connection.putheader("Content-Length", "100")
    connection.endheaders()
    started = time.monotonic()
    connection.send(b"x")
    status = None
    deadline = started + 12
    while time.monotonic() < deadline:
        readable, _, _ = select.select([connection.sock], [], [], 0.25)
        if readable:
            try:
                response = connection.getresponse()
                response.read()
                status = response.status
            except (OSError, http.client.HTTPException):
                status = 0
            break
    elapsed = time.monotonic() - started
    connection.close()
    if status is None or status == 200 or elapsed >= 11.5:
        raise SystemExit(f"slow upload was not aborted by the 10-second idle deadline: status={status}, elapsed={elapsed:.1f}s")
    print(f"Caddy upload checks passed: normal and 1 MiB base64-image requests, HTTP 413 above 2 MiB, slow upload aborted in {elapsed:.1f}s.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        serve()
    elif len(sys.argv) == 2:
        probe(int(sys.argv[1]))
    else:
        raise SystemExit("usage: caddy-request-probe.py <port>|serve")
