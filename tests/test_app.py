from pathlib import Path

from starlette.testclient import TestClient

from sin_mac_gateway.app import _guard_command, _guard_filesystem, _redact_text, create_app


def fake_backend(tmp_path: Path) -> str:
    backend = tmp_path / "backend.py"
    backend.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " m=json.loads(line)\n"
        " if 'id' not in m: continue\n"
        " method=m.get('method')\n"
        " if method=='initialize': result={'protocolVersion':'2025-11-25','capabilities':{'tools':{}},'serverInfo':{'name':'fake','version':'1'}}\n"
        " elif method=='tools/list': result={'tools':[{'name':'fs__echo','description':'Echo','inputSchema':{'type':'object','properties':{'text':{'type':'string'}},'required':['text']}}]}\n"
        " elif method=='tools/call': result={'content':[{'type':'text','text':m['params']['arguments'].get('text','ok')}],'isError':False}\n"
        " else: result={}\n"
        " print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':result}),flush=True)\n"
    )
    backend.chmod(0o700)
    return str(backend)


def test_health_and_ready(tmp_path: Path):
    with TestClient(create_app([fake_backend(tmp_path)])) as client:
        assert client.get('/healthz').text == 'live'
        ready = client.get('/readyz')
        assert ready.status_code == 200
        assert ready.json()['tools'] == 1
        assert ready.json()['auth'] is False


def test_command_guard_blocks_keychain_reads():
    reason = _guard_command({'argv': ['security', 'find-generic-password', '-s', 'secret']})
    assert reason and 'security find-generic-password' in reason


def test_high_confidence_secret_redaction():
    assert 'gho_' not in _redact_text('token gho_abcdefghijklmnopqrstuvwxyz123456')


def test_filesystem_guard_blocks_private_key_paths():
    reason = _guard_filesystem({"path": str(Path.home() / ".ssh/id_ed25519")})
    assert reason and "blocked sensitive" in reason
