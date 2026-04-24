"""Subprocess-based CLI tests for src/storyteller.py.

Uses real synthetic log fixtures from conftest.py — no mocks, per CLAUDE.md convention.
"""

import subprocess
import sys
from pathlib import Path

import pytest

STORYTELLER = Path(__file__).parent.parent / 'src' / 'storyteller.py'


def _run(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(STORYTELLER), *args],
        capture_output=True,
        text=True,
        **kwargs,
    )


class TestAnalyzeCommand:
    def test_happy_path_auth_log(self, sample_log, tmp_path):
        report_path = tmp_path / 'report.md'
        result = _run('analyze', str(sample_log), '--fmt', 'auth_log',
                      '--output', str(report_path),
                      '--processed-dir', str(tmp_path / 'processed'))
        assert result.returncode == 0
        assert report_path.exists()
        assert '# Cyber Incident Report' in report_path.read_text(encoding='utf-8')

    def test_report_contains_forensic_integrity_section(self, brute_force_log, tmp_path):
        report_path = tmp_path / 'report.md'
        _run('analyze', str(brute_force_log), '--fmt', 'auth_log',
             '--output', str(report_path),
             '--processed-dir', str(tmp_path / 'processed'))
        content = report_path.read_text(encoding='utf-8')
        assert '## Forensic Integrity' in content

    def test_default_fmt_is_auth_log(self, sample_log, tmp_path):
        report_path = tmp_path / 'report.md'
        result = _run('analyze', str(sample_log),
                      '--output', str(report_path),
                      '--processed-dir', str(tmp_path / 'processed'))
        assert result.returncode == 0

    def test_unknown_format_exits_nonzero(self, sample_log, tmp_path):
        result = _run('analyze', str(sample_log), '--fmt', 'bad_format',
                      '--output', str(tmp_path / 'report.md'),
                      '--processed-dir', str(tmp_path / 'processed'))
        assert result.returncode != 0

    def test_missing_file_exits_nonzero(self, tmp_path):
        result = _run('analyze', str(tmp_path / 'nonexistent.log'),
                      '--fmt', 'auth_log',
                      '--output', str(tmp_path / 'report.md'),
                      '--processed-dir', str(tmp_path / 'processed'))
        assert result.returncode != 0

    def test_stdout_reports_event_and_chain_counts(self, brute_force_log, tmp_path):
        report_path = tmp_path / 'report.md'
        result = _run('analyze', str(brute_force_log), '--fmt', 'auth_log',
                      '--output', str(report_path),
                      '--processed-dir', str(tmp_path / 'processed'))
        assert 'events' in result.stdout
        assert 'chain' in result.stdout


class TestVerifyCommand:
    def test_verify_after_analyze_returns_zero(self, brute_force_log, tmp_path):
        processed_dir = tmp_path / 'processed'
        _run('analyze', str(brute_force_log), '--fmt', 'auth_log',
             '--output', str(tmp_path / 'report.md'),
             '--processed-dir', str(processed_dir))
        result = _run('verify', str(brute_force_log),
                      '--processed-dir', str(processed_dir))
        assert result.returncode == 0
        assert 'OK' in result.stdout

    def test_verify_without_prior_ingest_returns_two(self, sample_log, tmp_path):
        result = _run('verify', str(sample_log),
                      '--processed-dir', str(tmp_path / 'never_ingested'))
        assert result.returncode == 2
