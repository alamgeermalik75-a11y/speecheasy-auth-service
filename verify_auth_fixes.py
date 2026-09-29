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
    print("=== TESTING LOGOUT & FORGOT PASSWORD ENDPOINTS ===")
    test_call('Logout 8001 with empty body', 'http://127.0.0.1:8001/api/v1/auth/logout', body={})
    test_call('Logout 8001 with refresh_token', 'http://127.0.0.1:8001/api/v1/auth/logout', body={'refresh_token': 'abc123token'})
    test_call('Logout 8000 universal', 'http://127.0.0.1:8000/api/v1/auth/logout', body={})
    test_call('Forgot Password (email)', 'http://127.0.0.1:8001/api/v1/auth/forgot-password', body={'email': 'alamgeermalik75@gmail.com'})

    req_html = urllib.request.Request('http://127.0.0.1:8001/api/v1/auth/reset-password-link?token=123456')
    with urllib.request.urlopen(req_html) as resp:
        print(f"[PASS] Reset Password Link Web Page: HTTP {resp.status}")
