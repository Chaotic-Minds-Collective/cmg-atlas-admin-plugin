import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request


BACKEND = Path(__file__).resolve().parents[1]


class AdminCookieAndHtmlSecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in ('main.py', 'config.yaml'):
            shutil.copyfile(BACKEND / name, self.root / name)

    def load(self, values):
        (self.root / '.env').write_text('')
        spec = importlib.util.spec_from_file_location(
            'admin_cookie_security_test_app', self.root / 'main.py'
        )
        module = importlib.util.module_from_spec(spec)
        a2s = ModuleType('valve.source.a2s')
        a2s.NoResponseError = type('NoResponseError', (Exception,), {})
        a2s.ServerQuerier = None
        with patch.dict(os.environ, values, clear=True), patch.dict(
            sys.modules, {'valve.source.a2s': a2s}
        ):
            spec.loader.exec_module(module)
        return module

    def test_session_cookie_is_secure_by_default_and_can_be_disabled_for_local_http(self):
        cases = (
            ({}, True),
            ({'SESSION_COOKIE_SECURE': 'false'}, False),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                values = {
                    'SESSION_SECRET': 's' * 32,
                    'DISCORD_CLIENT_SECRET': 'synthetic-value',
                    **overrides,
                }
                module = self.load(values)
                middleware = next(
                    item for item in module.app.user_middleware
                    if item.cls is SessionMiddleware
                )
                self.assertIs(middleware.options['https_only'], expected)

    def test_home_escapes_html_in_discord_username(self):
        module = self.load({
            'SESSION_SECRET': 's' * 32,
            'DISCORD_CLIENT_SECRET': 'synthetic-value',
        })
        module.ALLOWED_USERS = ['test-admin-id']
        request = Request({
            'type': 'http',
            'session': {
                'user': {
                    'id': 'test-admin-id',
                    'username': '<img src=x onerror=alert(1)>',
                },
            },
        })

        response = module.home(request)
        body = response.body.decode('utf-8')

        self.assertIn('&lt;img', body)
        self.assertNotIn('<img', body)


if __name__ == '__main__':
    unittest.main()
