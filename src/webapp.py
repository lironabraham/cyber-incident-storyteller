"""
Cyber Incident Storyteller — localhost web UI.

Usage:
    pip install fastapi uvicorn[standard] python-multipart
    python src/webapp.py
    # then open http://localhost:8000
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

sys.path.insert(0, str(Path(__file__).parent))

from api_schema import build_analysis_response
from hunter import build_attack_chains
from ingest import ingest

app = FastAPI(title='Cyber Incident Storyteller')

_TEMPLATES  = Path(__file__).parent.parent / 'templates'
_EVTX_MAGIC = b'ElfFile\x00'
_MAX_BYTES   = 500 * 1024 * 1024  # 500 MB


@app.get('/', response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((_TEMPLATES / 'index.html').read_text(encoding='utf-8'))


@app.post('/api/upload')
async def upload(file: UploadFile) -> JSONResponse:
    name = file.filename or 'upload.evtx'
    if not name.lower().endswith('.evtx'):
        raise HTTPException(400, 'Only .evtx files are accepted.')

    data = await file.read()
    if len(data) > _MAX_BYTES:
        raise HTTPException(413, 'File exceeds the 500 MB limit.')
    if not data.startswith(_EVTX_MAGIC):
        raise HTTPException(400, 'Not a valid EVTX file (bad magic bytes).')

    with tempfile.TemporaryDirectory() as tmp:
        evtx_path     = Path(tmp) / name
        processed_dir = Path(tmp) / 'processed'
        evtx_path.write_bytes(data)

        try:
            events = ingest(evtx_path, fmt='evtx', processed_dir=processed_dir)
            chains = build_attack_chains(events)
        except Exception as exc:
            raise HTTPException(422, f'Analysis failed: {exc}') from exc

    return JSONResponse(build_analysis_response(chains, events, name))


if __name__ == '__main__':
    uvicorn.run('webapp:app', host='127.0.0.1', port=8000, reload=True)
