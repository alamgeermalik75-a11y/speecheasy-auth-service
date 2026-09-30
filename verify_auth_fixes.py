import urllib.request
import urllib.error
import json

def test_call(name, url, method='POST', body=None, headers=None):
    h = headers or {}
    h['Content-Type'] = 'application/json'
    data = json.dumps(body).encode('utf-8') if body is not None else b'{}'
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode('utf-8')
            print(f"[PASS] {name}: HTTP {resp.status} - {content[:80]}")
    except urllib.error.HTTPError as e:
        err = e.read().decode('utf-8')
        print(f"[FAIL] {name}: HTTP {e.code} - {err[:120]}")

if __name__ == '__main__':
    AUTH_BASE = "https://speecheasy-auth-service-production.up.railway.app"
    SPEECH_BASE = "https://speecheasy-speech-backend-production.up.railway.app"
    print("=== TESTING LOGOUT & FORGOT PASSWORD ENDPOINTS ON LIVE RAILWAY ===")
    test_call('Logout Auth Service with empty body', f'{AUTH_BASE}/api/v1/auth/logout', body={})
    test_call('Logout Auth Service with refresh_token', f'{AUTH_BASE}/api/v1/auth/logout', body={'refresh_token': 'abc123token'})
    test_call('Logout Speech Backend universal', f'{SPEECH_BASE}/api/v1/auth/logout', body={})
    test_call('Forgot Password (email)', f'{AUTH_BASE}/api/v1/auth/forgot-password', body={'email': 'alamgeermalik75@gmail.com'})

    req_html = urllib.request.Request(f'{AUTH_BASE}/api/v1/auth/reset-password-link?token=123456')
    try:
        with urllib.request.urlopen(req_html) as resp:
            print(f"[PASS] Reset Password Link Web Page: HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"[INFO] Reset Password Link Web Page: HTTP {e.code}")
