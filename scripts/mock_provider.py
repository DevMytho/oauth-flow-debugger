"""Mock OAuth / OIDC provider for end-to-end smoke testing and screenshots.

  GET  /.well-known/openid-configuration -> discovery doc (jwks_uri included)
  GET  /jwks                             -> RSA-2048 public key (JWKS)
  GET  /authorize                         -> 302 back to redirect_uri with code + echoed state
  POST /token                             -> JSON token response (opaque access token +
                                            RS256-signed id_token bound to the nonce seen
                                            at /authorize)

The app under test discovers the JWKS from the expected issuer, matches by
`kid`, and verifies the ID token signature — so the full chain
auth URL -> redirect capture -> state check -> code exchange -> JWKS
verification is exercised without any real provider.

Logs every request to stdout so a test can verify the chain.

Requires the `cryptography` package (present in most dev environments).
"""

import base64
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes

PORT = 9099
KID = "mock-key-1"
ISSUER = f"http://127.0.0.1:{PORT}"

_seen_nonce = {"value": None}

# RSA-2048 keypair, generated once per process.
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def jwks() -> dict:
    pub = _public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": b64url(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")).decode(),
                "e": b64url(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")).decode(),
            }
        ]
    }


def make_jwt(payload: dict) -> str:
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": KID}).encode())
    body = b64url(json.dumps(payload).encode())
    signing_input = header + b"." + body
    sig = b64url(
        _private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    )
    return (signing_input + b"." + sig).decode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("MOCK", self.address_string(), fmt % args, flush=True)

    def _json(self, payload: dict, status: int = 200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/.well-known/openid-configuration":
            self._json(
                {
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/jwks",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "client_credentials"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }
            )
            return
        if url.path == "/jwks":
            self._json(jwks())
            return
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
            form = dict(
                k.split("=", 1) for k in body.split("&") if "=" in k
            ) if body else {}
            from urllib.parse import unquote

            form = {k: unquote(v) for k, v in form.items()}
            now = int(time.time())
            id_token = make_jwt(
                {
                    "iss": ISSUER,
                    "sub": "user-42",
                    "aud": form.get("client_id", "demo-client"),
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
            self._json(payload)
            return
        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    print(f"mock provider listening on {ISSUER} (RS256 + JWKS)", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
