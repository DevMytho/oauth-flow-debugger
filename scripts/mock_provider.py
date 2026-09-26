"""Mock OAuth provider for end-to-end smoke testing.

  GET  /authorize  → 302 back to redirect_uri with code + echoed state
  POST /token      → JSON token response (opaque access token + HS256 id_token)

Logs every request to stdout so the test can verify the full chain:
auth URL → redirect capture → state check → code exchange.
"""

import base64
import hashlib
import hmac
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

PORT = 9099
_seen_nonce = {"value": None}


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def make_jwt(payload: dict) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url(json.dumps(payload).encode())
    sig = b64url(hmac.new(b"mock-client-secret", header + b"." + body, hashlib.sha256).digest())
    return (header + b"." + body + b"." + sig).decode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("MOCK", self.address_string(), fmt % args, flush=True)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/authorize":
            state = query.get("state", [""])[0]
            redirect = query.get("redirect_uri", [""])[0]
            _seen_nonce["value"] = query.get("nonce", [None])[0]
            sep = "&" if "?" in redirect else "?"
            location = redirect + sep + urlencode(
                {"code": "mock-auth-code-123", "state": state}
            )
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""
        if url.path == "/token":
            print("MOCK TOKEN REQUEST:", body, flush=True)
            now = int(time.time())
            id_token = make_jwt(
                {
                    "iss": "http://localhost:9099",
                    "sub": "user-42",
                    "aud": "demo-client",
                    "exp": now + 3600,
                    "iat": now,
                    "nonce": _seen_nonce["value"],
                    "email": "dev@example.com",
                    "name": "Mock User",
                }
            )
            payload = {
                "access_token": "mock-access-token-abc123",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "mock-refresh-token-xyz",
                "id_token": id_token,
                "scope": "openid profile email",
            }
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    print(f"mock provider listening on http://localhost:{PORT}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
