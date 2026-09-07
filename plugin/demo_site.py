"""Small local HTTPS login fixture for browser-cookie reuse tests."""

from __future__ import annotations

import http.server
import ipaddress
import datetime
import os
import secrets
import shutil
import ssl
import tempfile
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


AUTHENTICATED_MARKER = "Demo account verified"
_USERNAME = "demo"
_PASSWORD = "demo-pass"
_MAX_BODY = 8 * 1024


class _Handler(http.server.BaseHTTPRequestHandler):
    server: "_DemoHTTPServer"

    def log_message(self, *_args: object) -> None:
        pass

    def _send(
        self,
        status: int,
        body: str,
        *,
        cookie: str | None = None,
        location: str | None = None,
    ) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/account":
            token = self.headers.get("Cookie", "").removeprefix("demo_session=").split(";", 1)[0]
            if token in self.server.sessions:
                self._send(200, f"<h1>{AUTHENTICATED_MARKER}</h1>")
            else:
                self._send(401, "<h1>Not authenticated</h1>")
            return
        if self.path in ("/", "/login"):
            self._send(
                200,
                '<form method="post" action="/login">'
                '<input name="username" type="text">'
                '<input name="password" type="password">'
                '<button type="submit">Log in</button></form>',
            )
            return
        self._send(404, "Not found")

    def do_POST(self) -> None:
        if self.path != "/login":
            self._send(404, "Not found")
            return
        length = self.headers.get("Content-Length")
        try:
            size = int(length or "-1")
        except ValueError:
            size = -1
        if size < 0 or size > _MAX_BODY:
            self._send(413, "Request too large")
            return
        raw = self.rfile.read(size)
        values = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        if values.get("username") != [_USERNAME] or values.get("password") != [_PASSWORD]:
            self._send(401, "Invalid credentials")
            return
        token = secrets.token_urlsafe(32)
        self.server.sessions.add(token)
        self._send(
            303,
            "Logged in",
            cookie=f"demo_session={token}; HttpOnly; Secure; Path=/",
            location="/account",
        )


class _DemoHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int]):
        super().__init__(address, _Handler)
        self.sessions: set[str] = set()


def _make_certificate(directory: str) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(key_path).write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )
    return cert_path, key_path


@dataclass
class DemoSite:
    login_url: str
    account_url: str
    origin: str
    _server: _DemoHTTPServer
    _thread: threading.Thread
    _tempdir: str

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)
        shutil.rmtree(self._tempdir, ignore_errors=True)


def start_demo() -> DemoSite:
    tempdir = tempfile.mkdtemp(prefix="demo-site-")
    try:
        cert_path, key_path = _make_certificate(tempdir)
        server = _DemoHTTPServer(("127.0.0.1", 0))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, name="demo-site", daemon=True)
        thread.start()
        origin = f"https://127.0.0.1:{server.server_port}"
        return DemoSite(origin + "/login", origin + "/account", origin, server, thread, tempdir)
    except Exception:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise
