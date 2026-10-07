"""Manage four processes; a failed service exits the container for Compose restart."""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request

APP_UID, PROXY_UID, PARSER_UID = 65532, 65533, 65534
BASE = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
PIDS = "/run/iqkb-supervisor/pids.json"


def health():
    with open(PIDS) as handle:
        for pid in json.load(handle):
            os.kill(pid, 0)
    with urllib.request.urlopen("http://127.0.0.1:8088/health/ready", timeout=1) as response:
        if response.status != 200:
            raise RuntimeError("app not ready")
    with socket.create_connection(("127.0.0.1", 3978), timeout=1):
        pass
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(1)
        client.connect("/run/parser/parser.sock")


def environment(names, **fixed):
    return BASE | {name: os.environ[name] for name in names.split() if name in os.environ} | fixed


def main():
    bot_enabled = os.environ.get("BOT_ENABLED", "false").strip().lower() == "true"
    print("Startup mode: " + ("bot + tab" if bot_enabled else "tab-only"), flush=True)
    required = "PUBLIC_ORIGIN TENANT_ID ADMIN_OBJECT_ID APP_CLIENT_ID APP_CLIENT_SECRET BOOTSTRAP_SECRET MODEL_API_KEY APP_ENCRYPTION_KEY BRIDGE_HMAC_KEY MSAL_CACHE_KEY_HEX"
    if bot_enabled:
        required += " BOT_CLIENT_ID TEAMS_APP_ID BOT_CLIENT_SECRET"
    missing = [name for name in required.split() if not os.environ.get(name, "").strip()]
    if missing:
        raise RuntimeError("missing environment variables: " + ", ".join(missing))
    for name in ("APP_ENCRYPTION_KEY", "BRIDGE_HMAC_KEY", "MSAL_CACHE_KEY_HEX"):
        value = os.environ[name]
        if len(value) != 64 or any(char not in "0123456789abcdefABCDEF" for char in value):
            raise RuntimeError(name + " must be 64 hexadecimal characters")
    if len({os.environ[name].lower() for name in ("APP_ENCRYPTION_KEY", "BRIDGE_HMAC_KEY", "MSAL_CACHE_KEY_HEX")}) != 3:
        raise RuntimeError("encryption/HMAC keys must be distinct")
    for path, uid, gid, mode in (("/var/lib/iqkb", APP_UID, APP_UID, 0o700),
                                 ("/var/lib/iqkb-msal", APP_UID, APP_UID, 0o700),
                                 ("/run/iqkb", APP_UID, APP_UID, 0o700),
                                 ("/run/parser", PARSER_UID, APP_UID, 0o750),
                                 ("/run/iqkb-supervisor", 0, 0, 0o700)):
        os.makedirs(path, exist_ok=True)
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    processes = []

    def start(command, uid, env):
        process = subprocess.Popen(command, user=uid, group=uid, extra_groups=[],
                                   env=env, start_new_session=True)
        processes.append(process)
        return process

    def stopping(_number, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    try:
        start(["python", "/opt/iqkb/parser-sandbox.py"], PARSER_UID,
              BASE | {"PARSER_SOCKET": "/run/parser/parser.sock"})
        for _ in range(100):
            if processes[0].poll() is not None:
                raise RuntimeError("parser exited during startup")
            if os.path.exists("/run/parser/parser.sock"):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("parser socket startup timed out")
        os.chown("/run/parser/parser.sock", PARSER_UID, APP_UID)
        os.chmod("/run/parser/parser.sock", 0o660)
        start(["node", "/opt/iqkb/gateway/dist/server.js"], APP_UID,
              environment("BOT_ENABLED TENANT_ID APP_CLIENT_ID BOT_CLIENT_ID TEAMS_APP_ID PUBLIC_ORIGIN APP_CLIENT_SECRET BOT_CLIENT_SECRET MSAL_CACHE_KEY_HEX OAUTH_CONNECTION_NAME",
                          BOT_ENABLED="true" if bot_enabled else "false",
                          NODE_ENV="production", PORT="3978", HTTP_LISTEN_HOST="127.0.0.1", OBO_SOCKET="/run/iqkb/obo.sock"))
        start(["iqkb"], APP_UID,
              environment("PUBLIC_ORIGIN TENANT_ID ADMIN_OBJECT_ID APP_CLIENT_ID APP_ENCRYPTION_KEY BRIDGE_HMAC_KEY BOOTSTRAP_SECRET MODEL_API_KEY POSTGRES_DSN POSTGRES_CONNECTION_MODE MODEL_MONTHLY_ATTEMPT_LIMIT AUDIT_RETENTION_DAYS",
                          HTTP_LISTEN_ADDR="127.0.0.1:8080", SQLITE_PATH="/var/lib/iqkb/config.sqlite",
                          BRIDGE_SOCKET="/run/iqkb/bridge.sock", OBO_SOCKET="/run/iqkb/obo.sock", PARSER_SOCKET="/run/parser/parser.sock"))
        start(["caddy", "run", "--config", "/opt/iqkb/Caddyfile", "--adapter", "caddyfile"], PROXY_UID, BASE)
        with open(PIDS, "w") as handle:
            json.dump([process.pid for process in processes], handle)
        print("Started parser, Teams gateway, Go app and proxy; port 8088.", flush=True)
        while True:
            if any(process.poll() is not None for process in processes):
                raise RuntimeError("a service exited; restarting the container")
            time.sleep(0.25)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + 12
        for process in processes:
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["health"]:
            health()
        else:
            main()
    except Exception as error:
        # Errors contain names/status only, never configuration values.
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(1)
