import http.cookiejar
import ssl
import urllib.error
import urllib.parse
import urllib.request

from plugin.demo_site import AUTHENTICATED_MARKER, start_demo


def test_demo_login_cookie_reuse_and_safe_failures():
    site = start_demo()
    try:
        context = ssl._create_unverified_context()
        jar = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPRedirectHandler(),
        )

        def request(method, url, data=None):
            return client.open(urllib.request.Request(url, data=data, method=method))

        try:
            request("GET", site.account_url)
        except urllib.error.HTTPError as error:
            assert error.code == 401
            assert error.read() == b"<h1>Not authenticated</h1>"

        oversized = b"x" * (8 * 1024 + 1)
        try:
            request("POST", site.login_url, oversized)
        except urllib.error.HTTPError as error:
            assert error.code == 413
            assert error.read() == b"Request too large"

        bad = urllib.parse.urlencode({"username": "wrong", "password": "bad"}).encode()
        try:
            request("POST", site.login_url, bad)
        except urllib.error.HTTPError as error:
            assert error.code == 401
            assert error.read() == b"Invalid credentials"
        assert len(jar) == 0

        good = urllib.parse.urlencode({"username": "demo", "password": "demo-pass"}).encode()
        response = request("POST", site.login_url, good)
        assert response.status == 200
        assert len(jar) == 1
        assert "demo" not in response.read().decode()

        account = request("GET", site.account_url).read().decode()
        assert AUTHENTICATED_MARKER in account
        assert "demo-pass" not in account
    finally:
        site.close()
