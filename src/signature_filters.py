"""
Signature-based noise filters for forensic analysis.

Contains DLL names that are high-signal when loaded from unexpected processes.
Used by sysmon_evtx.py to filter EventID 7 (Image Loaded) noise.
"""

# DLL basenames that are high-signal when loaded from an unexpected process.
# Used by sysmon_evtx.py to filter EventID 7 (Image Loaded) noise.
SUSPICIOUS_DLLS: frozenset[str] = frozenset({
    # AMSI bypass targets
    'amsi.dll',
    # Credential dumping (Mimikatz targets)
    'cryptdll.dll', 'samsrv.dll', 'lsasrv.dll', 'wdigest.dll', 'kerberos.dll',
    # NTLM credential material
    'ntlm.dll', 'msv1_0.dll',
    # SAM access
    'samlib.dll',
})
