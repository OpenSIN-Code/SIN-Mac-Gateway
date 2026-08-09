from pathlib import Path

from starlette.testclient import TestClient

from sin_mac_gateway.app import create_app
from test_app import fake_backend

HEADERS = {
    'Accept': 'application/json, text/event-stream',
    'Content-Type': 'application/json',
}


def test_official_streamable_http_initialize_list_and_call(tmp_path: Path):
    with TestClient(create_app([fake_backend(tmp_path)]), base_url='http://localhost') as client:
        init = client.post(
            '/mcp',
            headers=HEADERS,
            json={
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'initialize',
                'params': {
                    'protocolVersion': '2025-11-25',
                    'capabilities': {},
                    'clientInfo': {'name': 'test', 'version': '1'},
                },
            },
        )
        assert init.status_code == 200, init.text
        assert init.json()['result']['serverInfo']['name'] == 'SIN Mac Gateway'

        tools = client.post(
            '/mcp',
            headers=HEADERS,
            json={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
        )
        assert tools.status_code == 200, tools.text
        assert tools.json()['result']['tools'][0]['name'] == 'fs__echo'

        called = client.post(
            '/mcp',
            headers=HEADERS,
            json={
                'jsonrpc': '2.0',
                'id': 3,
                'method': 'tools/call',
                'params': {'name': 'fs__echo', 'arguments': {'text': 'SIN_OK'}},
            },
        )
        assert called.status_code == 200, called.text
        assert called.json()['result']['content'][0]['text'] == 'SIN_OK'
