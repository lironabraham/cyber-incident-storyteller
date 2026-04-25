"""
Download EVTX attack sample fixtures from sbousseaden/EVTX-ATTACK-SAMPLES.

Run once before executing the real-sample integration tests:

    py tests/download_evtx_fixtures.py

Files are saved to tests/fixtures/evtx/ and gitignored (binary blobs).
Already-downloaded files are skipped.
"""

import sys
import urllib.error
import urllib.request
from pathlib import Path

_RAW_BASE = (
    'https://raw.githubusercontent.com/sbousseaden/'
    'EVTX-ATTACK-SAMPLES/master/'
)

_FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'evtx'

_SAMPLES = [
    'Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx',
    'Credential Access/kerberos_pwd_spray_4771.evtx',
    'Execution/temp_scheduled_task_4698_4699.evtx',
    'Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx',
    (
        'Privilege Escalation/'
        'PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.evtx'
    ),
    'Lateral Movement/LM_Remote_Service02_7045.evtx',
    'Persistence/Network_Service_Guest_added_to_admins_4732.evtx',
]


def download_all() -> None:
    _FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    ok = skipped = failed = 0

    for repo_path in _SAMPLES:
        local = _FIXTURE_DIR / Path(repo_path).name
        if local.exists():
            print(f'  skip  {local.name}')
            skipped += 1
            continue

        url = _RAW_BASE + urllib.request.quote(repo_path, safe='/')
        print(f'  fetch {local.name} ... ', end='', flush=True)
        try:
            urllib.request.urlretrieve(url, local)
            size_kb = local.stat().st_size // 1024
            print(f'ok ({size_kb} KB)')
            ok += 1
        except urllib.error.URLError as exc:
            local.unlink(missing_ok=True)
            print(f'FAILED: {exc}')
            failed += 1

    print(f'\n{ok} downloaded, {skipped} already cached, {failed} failed.')
    if failed:
        sys.exit(1)


if __name__ == '__main__':
    download_all()
