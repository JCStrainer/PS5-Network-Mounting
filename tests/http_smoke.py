#!/usr/bin/env python3
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18081"

def request(path, method="GET", body=None, headers=None):
    data = None
    h = {}
    if headers:
        h.update(headers)
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            data = body.encode()
            h.setdefault("Content-Type", "application/json")
        elif isinstance(body, bytes):
            data = body
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers=h,
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()

env = os.environ.copy()
env["PS5NM_PORT"] = "18081"
env["PS5NM_BIND"] = "127.0.0.1"
proc = subprocess.Popen(["/tmp/ps5nm-host"], env=env)

try:
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError(f"host server exited early with {proc.returncode}")
        try:
            status_code, raw = request("/api/v1/status")
            if status_code == 200:
                break
        except (OSError, TimeoutError):
            time.sleep(0.1)
    else:
        raise RuntimeError("HTTP server did not start")

    status = json.loads(raw)
    assert status["mounted"] is False
    assert status["mountpoint"] == "/hostapp"

    # HTML page delivery
    code, page = request("/?cache=1")
    page = page.decode()
    assert code == 200 and "PS5 Network Mounting" in page
    assert 'value="nfs"' in page and 'value="smb"' in page
    assert 'value="ftp"' not in page.lower() and 'value="sftp"' not in page.lower()

    # CORS OPTIONS preflight
    code, _ = request("/api/v1/mount", "OPTIONS")
    assert code == 204

    # Mount validation
    code, raw = request("/api/v1/mount", "POST", {
        "protocol": "nfs", "host": "127.0.0.1", "port": 2049,
        "remote_path": "/mnt/dataPool/games", "mountpoint": "/unsafe",
    })
    assert code == 400 and json.loads(raw)["error"] == "unsafe_mountpoint"

    # Substring key trap in JSON parser
    code, raw = request("/api/v1/mount", "POST", {
        "note": "my favorite protocol is nfs",
        "protocol": "smb", "host": "127.0.0.1", "port": 445,
        "remote_path": "games", "mountpoint": "/hostapp",
    })
    assert code == 500
    assert "no PS5 FUSE/NFS/SMB adapters linked" in json.loads(raw)["message"]

    # Malformed JSON body
    code, raw = request("/api/v1/mount", "POST", '{"protocol": "nfs", "unclosed": ')
    assert code == 400 and json.loads(raw)["error"] == "invalid_json"

    # Trailing garbage after valid JSON
    code, raw = request("/api/v1/mount", "POST", '{"protocol": "nfs"} trailing_garbage')
    assert code == 400 and json.loads(raw)["error"] == "invalid_json"

    # CSRF check: foreign Origin without X-Requested-With
    code, raw = request("/api/v1/unmount", "POST", {"mountpoint": "/hostapp"}, headers={
        "Origin": "http://evil-attacker.com",
        "Host": "127.0.0.1:18081"
    })
    assert code == 403 and json.loads(raw)["error"] == "forbidden_origin"

    # CSRF check: foreign Origin WITH X-Requested-With
    code, raw = request("/api/v1/unmount", "POST", {"mountpoint": "/hostapp"}, headers={
        "Origin": "http://evil-attacker.com",
        "Host": "127.0.0.1:18081",
        "X-Requested-With": "PS5NM"
    })
    assert code == 409 and json.loads(raw)["error"] == "unmount_failed"

    # Standard unmount request
    code, raw = request("/api/v1/unmount", "POST", {"mountpoint": "/hostapp"})
    assert code == 409 and json.loads(raw)["error"] == "unmount_failed"

    print("HTTP smoke tests passed (host build with JSON parser and security checks).")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
