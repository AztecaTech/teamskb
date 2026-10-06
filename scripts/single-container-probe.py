"""Synthetic deployment probe, mounted only by the validation script."""
import base64
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

with open("/run/iqkb-supervisor/pids.json") as handle:
    pids = json.load(handle)
if sys.argv[1:] == ["crash-app"]:
    os.kill(pids[2], signal.SIGKILL)
    raise SystemExit(0)

if sys.argv[1:] in (["seed"], ["verify"]):
    marker_probe = '''
import sqlite3, sys
with sqlite3.connect('/var/lib/iqkb/config.sqlite', timeout=5) as db:
    if sys.argv[1] == 'seed':
        db.execute("INSERT INTO settings(key,value) VALUES('deployment_probe',?)", (b'synthetic-persistent-marker',))
    else:
        assert db.execute("SELECT value FROM settings WHERE key='deployment_probe'").fetchone()[0] == b'synthetic-persistent-marker'
'''
    subprocess.run([sys.executable, "-c", marker_probe, sys.argv[1]], user=65532,
                   group=65532, extra_groups=[], env={"PATH": "/usr/local/bin:/usr/bin:/bin"}, check=True)

secrets = {"MODEL_API_KEY", "APP_CLIENT_SECRET", "BOT_CLIENT_SECRET",
           "APP_ENCRYPTION_KEY", "BRIDGE_HMAC_KEY", "MSAL_CACHE_KEY_HEX", "BOOTSTRAP_SECRET"}
for pid, uid, allowed in zip(pids, (65534, 65532, 65532, 65533),
                             (set(), {"APP_CLIENT_SECRET", "BOT_CLIENT_SECRET", "MSAL_CACHE_KEY_HEX"},
                              {"MODEL_API_KEY", "APP_ENCRYPTION_KEY", "BRIDGE_HMAC_KEY", "BOOTSTRAP_SECRET"}, set())):
    # Inspect as the same UID; do not add SYS_PTRACE just for this test.
    inspect_env = '''
import json, sys
with open('/proc/' + sys.argv[1] + '/environ', 'rb') as handle:
    env = dict(part.split(b'=', 1) for part in handle.read().split(b'\\0') if b'=' in part)
if b'MODEL_API_KEY' in env:
    assert env[b'MODEL_API_KEY'] == b'dummy-model-$-only'
    assert env[b'POSTGRES_DSN'].startswith(b'postgres://')
print(json.dumps([name.decode() for name in env]))
'''
    names = json.loads(subprocess.check_output([sys.executable, "-c", inspect_env, str(pid)],
                       user=uid, group=uid, extra_groups=[], env={"PATH": "/usr/local/bin:/usr/bin:/bin"}))
    assert secrets.intersection(names) == allowed
    with open(f"/proc/{pid}/status") as handle:
        status = dict(line.split(":", 1) for line in handle if ":" in line)
    assert int(status["Uid"].split()[0]) == uid
    assert int(status["NoNewPrivs"].strip()) == 1
    assert int(status["CapEff"].strip(), 16) == 0

response = urllib.request.urlopen("http://127.0.0.1:8088/health/ready", timeout=2)
assert response.status == 200
assert response.headers["X-Content-Type-Options"] == "nosniff"
assert "frame-ancestors" in response.headers["Content-Security-Policy"]
container_address = socket.gethostbyname(socket.gethostname())
for port in (8080, 3978):
    try:
        with socket.create_connection((container_address, port), timeout=1):
            raise AssertionError("internal service accepted a non-loopback connection")
    except ConnectionRefusedError:
        pass
try:
    urllib.request.urlopen("http://127.0.0.1:8088/api/session", timeout=2)
    raise AssertionError("anonymous session accepted")
except urllib.error.HTTPError as error:
    assert error.code == 401
# The proxy must route the Teams callback to the gateway, which rejects no JWT.
unsigned_activity = (b'{"type":"message","id":"probe","timestamp":"2026-01-01T00:00:00Z",'
                    b'"serviceUrl":"https://smba.trafficmanager.net/teams/","channelId":"msteams",'
                    b'"from":{"id":"probe-user"},"recipient":{"id":"probe-bot"},'
                    b'"conversation":{"id":"probe-conversation","conversationType":"personal"},"text":"probe"}')
for attempt in range(20):
    request = urllib.request.Request("http://127.0.0.1:8088/api/messages", data=unsigned_activity,
                                     headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(request, timeout=3)
        raise AssertionError("unsigned Teams activity accepted")
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        if error.code in (401, 403):
            break
        if error.code != 404 or attempt == 19:
            raise AssertionError(f"Teams callback route returned {error.code}: {body[:512]}") from error
    time.sleep(0.25)


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(2)
        self.sock.connect("/run/parser/parser.sock")


connection = UnixConnection("localhost")
connection.request("POST", "/v1/parse", json.dumps({"filename": "dummy.txt",
                   "contentBase64": base64.b64encode(b"Synthetic retention: seven years.").decode()}),
                   {"Content-Type": "application/json"})
parsed = connection.getresponse()
assert parsed.status == 200
assert "seven years" in json.loads(parsed.read())["text"]
connection.close()
sandbox_probe = '''
import os, runpy, socket
runpy.run_path('/opt/iqkb/parser-sandbox.py')['restrict']()
for family in (socket.AF_INET, socket.AF_INET6):
    try:
        socket.socket(family)
        raise AssertionError('network socket permitted')
    except PermissionError:
        pass
with socket.socket(socket.AF_UNIX):
    pass
try:
    os.open('/var/lib/iqkb/config.sqlite', os.O_RDONLY)
    raise AssertionError('parser read app database')
except PermissionError:
    pass
'''
subprocess.run([sys.executable, "-c", sandbox_probe], user=65534, group=65534,
               extra_groups=[], env={"PATH": "/usr/local/bin:/usr/bin:/bin"}, check=True)
print("Single-container probe passed: UID/capability/environment separation, proxy headers, anonymous rejection, Teams routing, parser extraction, network denial, and database isolation.")
