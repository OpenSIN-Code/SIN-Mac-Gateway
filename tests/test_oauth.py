import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from starlette.testclient import TestClient

from sin_mac_gateway.app import create_app
from sin_mac_gateway.oauth import SQLiteOAuthProvider
from test_app import fake_backend

PUBLIC = 'https://sin-mac-gateway.delqhi.com'
CALLBACK = 'https://claude.ai/api/mcp/auth_callback'


def _pkce(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')


def test_oauth_discovery_auth_code_refresh_and_protected_mcp(tmp_path: Path):
    app = create_app(
        [fake_backend(tmp_path)],
        public_base_url=PUBLIC,
        client_id='claude-test',
        client_secret='test-secret-please-change',
        oauth_db=str(tmp_path / 'oauth.sqlite3'),
    )
    with TestClient(app, base_url=PUBLIC) as client:
        metadata = client.get('/.well-known/oauth-authorization-server')
        assert metadata.status_code == 200
        assert metadata.json()['authorization_endpoint'] == PUBLIC + '/authorize'

        unauthenticated = client.post(
            '/mcp',
            headers={'Accept': 'application/json, text/event-stream'},
            json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}},
        )
        assert unauthenticated.status_code == 401
        assert 'resource_metadata=' in unauthenticated.headers['www-authenticate']

        verifier = 'v' * 64
        authorize = client.get(
            '/authorize',
            params={
                'response_type': 'code',
                'client_id': 'claude-test',
                'redirect_uri': CALLBACK,
                'scope': 'mac',
                'state': 'state-1',
                'code_challenge': _pkce(verifier),
                'code_challenge_method': 'S256',
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302, authorize.text
        parsed = urlparse(authorize.headers['location'])
        assert parsed.scheme + '://' + parsed.netloc + parsed.path == CALLBACK
        code = parse_qs(parsed.query)['code'][0]

        token = client.post(
            '/token',
            data={
                'grant_type': 'authorization_code',
                'client_id': 'claude-test',
                'client_secret': 'test-secret-please-change',
                'code': code,
                'redirect_uri': CALLBACK,
                'code_verifier': verifier,
            },
        )
        assert token.status_code == 200, token.text
        tokens = token.json()
        assert tokens['access_token']
        assert tokens['refresh_token']

        initialized = client.post(
            '/mcp',
            headers={
                'Authorization': 'Bearer ' + tokens['access_token'],
                'Accept': 'application/json, text/event-stream',
                'Content-Type': 'application/json',
            },
            json={
                'jsonrpc': '2.0',
                'id': 2,
                'method': 'initialize',
                'params': {
                    'protocolVersion': '2025-11-25',
                    'capabilities': {},
                    'clientInfo': {'name': 'Claude', 'version': 'test'},
                },
            },
        )
        assert initialized.status_code == 200, initialized.text

        refreshed = client.post(
            '/token',
            data={
                'grant_type': 'refresh_token',
                'client_id': 'claude-test',
                'client_secret': 'test-secret-please-change',
                'refresh_token': tokens['refresh_token'],
                'scope': 'mac',
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()['access_token'] != tokens['access_token']


def test_oauth_connection_context_closes_connection(tmp_path: Path):
    provider = SQLiteOAuthProvider(
        db_path=str(tmp_path / "provider.sqlite3"),
        client_id="claude-test",
        client_secret="test-secret-please-change",
    )
    connection = provider._connect()
    assert hasattr(connection, "__enter__")
    with connection as db:
        db.execute("SELECT 1")
    # A closed sqlite connection rejects further use; this guards the
    # descriptor-leak fix behind the provider's real connection path.
    try:
        db.execute("SELECT 1")
    except Exception as exc:
        assert "closed" in str(exc).lower()
    else:
        raise AssertionError("OAuth connection remained open after context exit")
