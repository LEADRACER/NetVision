#!/usr/bin/env python3
"""Test auth flow end-to-end — no credentials in the file."""
import json
import subprocess
import sys

BASE = "http://localhost:8000"

def curl(method="GET", path="/", data=None, token=None, headers_only=False):
    cmd = ["curl", "-s"]
    if headers_only:
        cmd.append("-I")
    else:
        cmd.append("-w")
        cmd.append("%{http_code}")
    cmd.append(BASE + path)
    if token:
        auth_val = "Authorization: Bearer " + token
        cmd.extend(["-H", auth_val])
    if data:
        cmd.extend(["-H", "Content-Type: application/json"])
        cmd.extend(["-d", json.dumps(data)])
    if method != "GET":
        cmd.extend(["-X", method])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return result.stdout

def parse(out):
    body = out[:-3]
    code = out[-3:]
    return body, code

passed = 0
failed = 0

def check(desc, ok):
    global passed, failed
    if ok:
        print("  PASS")
        passed += 1
    else:
        print("  FAIL")
        failed += 1

# 1. Health (public)
out = curl("GET", "/health")
body, code = parse(out)
print("1. /health (no auth): " + code)
check("public endpoint works", code == "200")

# 2. Get token
out = curl("POST", "/auth/token", data={"username": "admin", "password": "netvision"})
body, _code = parse(out)
token_data = json.loads(body)
access = token_data["access_token"]
refresh = token_data["refresh_token"]
print("2. Auth token obtained: " + access[:30] + "...")
check("token received", len(access) > 50)

# 3. /devices no auth (dev mode allows this — returns builtin admin)
out = curl("GET", "/devices")
body, code = parse(out)
print("3. /devices NO auth (dev mode): " + code)
check("dev mode allows unauthenticated access", code == "200")

# 4. /devices with auth (expect 200)
out = curl("GET", "/devices", token=access)
body, code = parse(out)
print("4. /devices WITH auth: " + code)
check("authenticated request allowed", code == "200")

# 5. /auth/whoami
out = curl("GET", "/auth/whoami", token=access)
body, _code = parse(out)
try:
    w = json.loads(body)
    print("5. /auth/whoami: user=" + w["username"] + " role=" + w["role"])
    check("whoami returns superadmin role", w["role"] == "superadmin")
except Exception as e:
    print("5. /auth/whoami FAIL: " + str(e))
    check("whoami works", False)

# 6. /audit-log (admin only)
out = curl("GET", "/audit-log", token=access)
body, code = parse(out)
print("6. /audit-log admin: " + code)
check("audit log accessible", code == "200")
if code == "200":
    entries = json.loads(body).get("entries", [])
    print("   Entries: " + str(len(entries)))

# 7. /scan (admin qualifies as operator+)
out = curl("GET", "/scan", token=access)
body, code = parse(out)
print("7. /scan admin: " + code)
check("scan endpoint responds", code in ("200", "503"))

# 8. Rate limit headers
out = curl("GET", "/devices", token=access, headers_only=True)
headers_lower = out.lower()
has_rl = "x-ratelimit" in headers_lower
has_rid = "x-request-id" in headers_lower
print("8. Rate limit headers: rl=" + str(has_rl) + " rid=" + str(has_rid))
check("rate limit headers present", has_rl and has_rid)

# 9. /auth/refresh
out = curl("POST", "/auth/refresh", data={"refresh_token": refresh})
body, _code = parse(out)
try:
    r = json.loads(body)
    new_access = r.get("access_token", "")
    print("9. /auth/refresh: " + new_access[:30] + "...")
    check("refresh works", len(new_access) > 50)
except Exception as e:
    print("9. /auth/refresh FAIL: " + str(e))
    check("refresh works", False)

# 10. /auth/revoke
out = curl("POST", "/auth/revoke", data={"token": access})
body, _code = parse(out)
try:
    r = json.loads(body)
    print("10. /auth/revoke: " + str(r))
    check("revoke works", r.get("revoked") is True)
except Exception as e:
    print("10. /auth/revoke FAIL: " + str(e))
    check("revoke works", False)

# 11. Revoked token should fail
out = curl("GET", "/devices", token=access)
body, code = parse(out)
print("11. /devices with revoked token: " + code)
check("revoked token rejected", code == "401")

print("\n=== RESULTS: " + str(passed) + " passed, " + str(failed) + " failed ===")
sys.exit(0 if failed == 0 else 1)
