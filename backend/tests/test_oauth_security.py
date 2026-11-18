import ast
import asyncio
import html
import os
import secrets
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit, parse_qs

SOURCE = Path(__file__).resolve().parents[1] / "main.py"
class HTTPError(Exception):
    def __init__(self, status_code, detail=""):
        self.status_code = status_code
        self.detail = detail
class App:
    def get(self, path):
        return lambda f: f
class Redirect:
    def __init__(self, url):
        self.url = url

def load_functions():
    wanted = {"parse_allowed_origins", "parse_bool_env", "is_admin", "login", "consume_oauth_state", "oauth_callback"}
    tree = ast.parse(SOURCE.read_text())
    ns = {"html": html, "os": os, "secrets": secrets, "time": time, "urlencode": urlencode,
          "urlsplit": urlsplit, "HTTPException": HTTPError, "Request": object,
          "RedirectResponse": Redirect, "app": App(), "ALLOWED_USERS": ["allowed"],
          "DISCORD_API": "https://discord.com/api", "config": {"discord": {"client_id": "test", "redirect_uri": "https://admin.example.invalid/auth/callback"}}}
    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in wanted]
    exec(compile(ast.Module(body=funcs, type_ignores=[]), str(SOURCE), "exec"), ns)
    return ns

class OAuthSecurityTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_functions()
    def request(self, state="token", age=0):
        return SimpleNamespace(session={"discord_oauth_state": state, "discord_oauth_issued_at": time.time() - age})
    def test_state_is_consumed_and_not_reusable(self):
        r = self.request(); self.ns["consume_oauth_state"](r, "token")
        self.assertEqual(r.session, {})
        with self.assertRaises(HTTPError): self.ns["consume_oauth_state"](r, "token")
    def test_bad_expired_future_and_non_ascii_states_are_rejected(self):
        for state, age, supplied in [("token", 0, "wrong"), ("token", 601, "token"), ("token", -60, "token"), ("token", 0, "é"), ("token", 0, "")]:
            with self.subTest(state=supplied, age=age), self.assertRaises(HTTPError) as raised:
                self.ns["consume_oauth_state"](self.request(state, age), supplied)
            self.assertEqual(raised.exception.status_code, 400)
    def test_login_rotates_state_and_encodes_the_redirect(self):
        r = SimpleNamespace(session={}); a = self.ns["login"](r); first = r.session["discord_oauth_state"]
        b = self.ns["login"](r); second = r.session["discord_oauth_state"]
        self.assertNotEqual(first, second)
        self.assertEqual(parse_qs(urlsplit(b.url).query)["state"], [second])
        self.assertEqual(parse_qs(urlsplit(a.url).query)["redirect_uri"], ["https://admin.example.invalid/auth/callback"])
    def test_wildcard_and_non_origin_cors_entries_are_rejected(self):
        for raw in ["*", "https://*.example.invalid", "https://example.invalid/path", "https://user:pass@example.invalid", "https://example.invalid?q=1"]:
            with self.subTest(raw=raw), self.assertRaises(RuntimeError): self.ns["parse_allowed_origins"](raw)
        self.assertEqual(self.ns["parse_allowed_origins"](""), [])
        self.assertEqual(self.ns["parse_allowed_origins"]("https://example.invalid,https://example.invalid/"), ["https://example.invalid"])
    def test_invalid_state_prevents_provider_exchange(self):
        calls = []
        async def exchange(*args): calls.append(args)
        self.ns["auth_callback"] = exchange
        with self.assertRaises(HTTPError): asyncio.run(self.ns["oauth_callback"]("code", self.request(), "wrong"))
        self.assertEqual(calls, [])
    def test_unlisted_account_is_cleared_at_http_boundary(self):
        async def exchange(code, request): request.session["user"] = {"id": "unlisted"}; return "response"
        self.ns["auth_callback"] = exchange
        r = self.request()
        with self.assertRaises(HTTPError) as raised: asyncio.run(self.ns["oauth_callback"]("code", r, "token"))
        self.assertEqual(raised.exception.status_code, 403); self.assertEqual(r.session, {})
    def test_authorized_callback_returns_the_exchange_result(self):
        async def exchange(code, request): request.session["user"] = {"id": "allowed"}; return "response"
        self.ns["auth_callback"] = exchange
        self.assertEqual(asyncio.run(self.ns["oauth_callback"]("code", self.request(), "token")), "response")
    def test_security_functions_are_not_duplicated(self):
        names = [n.name for n in ast.parse(SOURCE.read_text()).body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.assertEqual(len(names), len(set(names)))
    def test_exchange_helper_is_not_registered_as_the_http_route(self):
        tree = ast.parse(SOURCE.read_text())
        helper = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "auth_callback")
        wrapper = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "oauth_callback")
        self.assertEqual(helper.decorator_list, []); self.assertTrue(wrapper.decorator_list)

if __name__ == "__main__": unittest.main()
