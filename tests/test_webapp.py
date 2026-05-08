"""
Integration tests for the FastAPI web UI.

Uses FastAPI's TestClient (backed by httpx) against real EVTX fixtures
— no mocks of the parser or ingest pipeline.
"""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from webapp import app  # noqa: E402

CLIENT = TestClient(app)

_FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'evtx'
_SMALL_EVTX  = _FIXTURE_DIR / 'Defense Evasion' / 'DE_1102_security_log_cleared.evtx'


def _upload(path: Path):
    with open(path, 'rb') as fh:
        return CLIENT.post('/api/upload', files={'file': (path.name, fh, 'application/octet-stream')})


# ── happy path ─────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not _SMALL_EVTX.exists(), reason='EVTX fixture not downloaded')
def test_upload_returns_200():
    assert _upload(_SMALL_EVTX).status_code == 200


@pytest.mark.skipif(not _SMALL_EVTX.exists(), reason='EVTX fixture not downloaded')
def test_response_top_level_keys():
    data = _upload(_SMALL_EVTX).json()
    assert data['status'] == 'success'
    assert 'cy' in data
    assert 'metadata' in data
    assert 'report_markdown' in data


@pytest.mark.skipif(not _SMALL_EVTX.exists(), reason='EVTX fixture not downloaded')
def test_cy_has_nodes_and_edges():
    cy = _upload(_SMALL_EVTX).json()['cy']
    assert isinstance(cy['nodes'], list)
    assert isinstance(cy['edges'], list)


@pytest.mark.skipif(not _SMALL_EVTX.exists(), reason='EVTX fixture not downloaded')
def test_chain_nodes_have_required_fields():
    cy = _upload(_SMALL_EVTX).json()['cy']
    chains = [n for n in cy['nodes'] if n['data'].get('type') == 'chain']
    assert chains, 'Expected at least one chain node'
    for node in chains:
        d = node['data']
        assert d['id'].startswith('chain_')
        assert 'chain_type' in d
        assert 'severity' in d
        assert 'color' in d
        assert 'event_count' in d


@pytest.mark.skipif(not _SMALL_EVTX.exists(), reason='EVTX fixture not downloaded')
def test_event_nodes_have_parent_and_start_hidden():
    cy = _upload(_SMALL_EVTX).json()['cy']
    events = [n for n in cy['nodes'] if n['data'].get('type') == 'event']
    for node in events:
        assert 'parent' in node['data'], 'Event node missing parent'
        assert node['data']['id'].startswith('event_')
        assert 'hidden' in node.get('classes', ''), 'Event node must start hidden'


@pytest.mark.skipif(not _SMALL_EVTX.exists(), reason='EVTX fixture not downloaded')
def test_metadata_shape():
    meta = _upload(_SMALL_EVTX).json()['metadata']
    assert meta['file_name'] == _SMALL_EVTX.name
    assert isinstance(meta['event_count'], int)
    assert isinstance(meta['chain_count'], int)
    assert set(meta['severity_distribution']) >= {'critical', 'high', 'medium', 'low', 'info'}


@pytest.mark.skipif(not _SMALL_EVTX.exists(), reason='EVTX fixture not downloaded')
def test_report_markdown_is_nonempty_string():
    md = _upload(_SMALL_EVTX).json()['report_markdown']
    assert isinstance(md, str) and len(md) > 0


# ── error cases ────────────────────────────────────────────────────────────────

def test_non_evtx_extension_rejected():
    res = CLIENT.post('/api/upload', files={'file': ('evil.txt', b'data', 'text/plain')})
    assert res.status_code == 400
    assert 'evtx' in res.json()['detail'].lower()


def test_bad_magic_bytes_rejected():
    res = CLIENT.post('/api/upload', files={'file': ('fake.evtx', b'\x00\x00\x00\x00', 'application/octet-stream')})
    assert res.status_code == 400
    assert 'magic' in res.json()['detail'].lower()


def test_index_serves_html():
    res = CLIENT.get('/')
    assert res.status_code == 200
    assert 'text/html' in res.headers['content-type']
    assert 'Cyber Incident Storyteller' in res.text
