"""
ais-storyteller — Autonomous Incident Storyteller

Public SDK surface:
    from ais import ingest, build_attack_chains, generate_report
    from ais import StandardEvent, AttackChain
"""

__version__ = "0.1.0"

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from ingest import ingest, verify_integrity
from hunter import build_attack_chains, AttackChain
from reporter import generate_report
from schema import StandardEvent, SourceActor, TargetSystem, MitreTechnique

__all__ = [
    "ingest",
    "verify_integrity",
    "build_attack_chains",
    "AttackChain",
    "generate_report",
    "StandardEvent",
    "SourceActor",
    "TargetSystem",
    "MitreTechnique",
]
