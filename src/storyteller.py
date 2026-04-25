"""
Turns a parsed log DataFrame into a human-readable incident narrative.

Public API
----------
analyze(df, log_path)       -> IncidentReport
generate_narrative(report)  -> str
report(df, log_path)        -> str   (convenience: analyze + generate_narrative)
"""

import argparse
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

# Self-bootstrap import path when run as a script (mirrors ingest.py pattern)
sys.path.insert(0, str(Path(__file__).parent))

SUPPORTED_FORMATS = ('auth_log', 'syslog', 'audit_log', 'web_access', 'sysmon_linux', 'evtx')


@dataclass
class ThreatActor:
    ip: str
    failed_attempts: int
    successful_logins: int
    targeted_users: list
    first_seen: pd.Timestamp
    last_seen: pd.Timestamp

    @property
    def is_successful(self) -> bool:
        return self.successful_logins > 0

    @property
    def is_brute_force(self) -> bool:
        return self.failed_attempts >= 5


@dataclass
class IncidentReport:
    log_path: str
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    total_events: int
    threat_actors: list
    affected_users: list
    event_counts: dict
    recommendations: list


# ── Internal helpers ───────────────────────────────────────────────────────────

_SUCCESS_TYPES = {'Accepted Password', 'Accepted Publickey'}


def _find_threat_actors(df: pd.DataFrame) -> list:
    ip_events = df[df['source_ip'].notna()]
    if ip_events.empty:
        return []

    actors = []
    for ip, group in ip_events.groupby('source_ip'):
        failed = int((group['event_type'] == 'Failed Login').sum())
        successful = int(group['event_type'].isin(_SUCCESS_TYPES).sum())
        if failed == 0 and successful == 0:
            continue
        users = group['user'].dropna().unique().tolist()
        actors.append(ThreatActor(
            ip=ip,
            failed_attempts=failed,
            successful_logins=successful,
            targeted_users=users,
            first_seen=group['timestamp'].min(),
            last_seen=group['timestamp'].max(),
        ))

    actors.sort(key=lambda a: (-a.successful_logins, -a.failed_attempts))
    return actors


def _generate_recommendations(df: pd.DataFrame, actors: list) -> list:
    recs = []

    brute_force = [a for a in actors if a.is_brute_force]
    if brute_force:
        ips = ', '.join(a.ip for a in brute_force[:3])
        extra = f' and {len(brute_force) - 3} more' if len(brute_force) > 3 else ''
        recs.append(
            f"Block {len(brute_force)} IP(s) exhibiting brute-force behavior: {ips}{extra}."
        )

    compromised = [a for a in actors if a.is_successful and a.failed_attempts > 0]
    if compromised:
        recs.append(
            "Audit accounts with successful logins after failed attempts — "
            "possible credential-stuffing success."
        )

    failed_total = df['event_type'].value_counts().get('Failed Login', 0)
    if failed_total > 50:
        recs.append(
            "Enable fail2ban or equivalent rate-limiting to throttle repeated login failures."
        )

    root_attacks = df[(df['event_type'] == 'Failed Login') & (df['user'] == 'root')]
    if not root_attacks.empty:
        recs.append("Disable root SSH login (set PermitRootLogin no in sshd_config).")

    if not recs:
        recs.append("No immediate threats detected. Continue routine monitoring.")

    return recs


# ── Public API ─────────────────────────────────────────────────────────────────

def analyze(df: pd.DataFrame, log_path: str = 'auth.log') -> IncidentReport:
    """Analyze a parsed log DataFrame and return a structured IncidentReport."""
    if df.empty:
        return IncidentReport(
            log_path=log_path,
            start_time=pd.NaT,
            end_time=pd.NaT,
            total_events=0,
            threat_actors=[],
            affected_users=[],
            event_counts={},
            recommendations=['No events to analyze.'],
        )

    actors = _find_threat_actors(df)
    affected_users = df['user'].dropna().unique().tolist()
    event_counts = df['event_type'].value_counts().to_dict()
    recommendations = _generate_recommendations(df, actors)

    return IncidentReport(
        log_path=log_path,
        start_time=df['timestamp'].min(),
        end_time=df['timestamp'].max(),
        total_events=len(df),
        threat_actors=actors,
        affected_users=affected_users,
        event_counts=event_counts,
        recommendations=recommendations,
    )


def generate_narrative(inc: IncidentReport) -> str:
    """Render an IncidentReport as a human-readable text narrative."""
    W = 70
    sep = '-' * W
    dbl = '=' * W

    lines = [
        dbl,
        'CYBER INCIDENT REPORT',
        dbl,
        f'Log file : {inc.log_path}',
    ]

    if pd.isna(inc.start_time):
        lines += ['', 'No events found in log.', dbl]
        return '\n'.join(lines)

    lines += [
        f'Period   : {inc.start_time}  ->  {inc.end_time}',
        f'Events   : {inc.total_events} total',
        '',
    ]

    # ── Executive summary ──────────────────────────────────────────────────────
    lines += [sep, 'EXECUTIVE SUMMARY', sep]

    failed = inc.event_counts.get('Failed Login', 0)
    accepted = sum(inc.event_counts.get(t, 0) for t in _SUCCESS_TYPES)
    parts = []
    if failed:
        parts.append(f'{failed} failed login attempt(s)')
    if accepted:
        parts.append(f'{accepted} successful authentication(s)')
    if inc.threat_actors:
        parts.append(f'{len(inc.threat_actors)} distinct external IP(s)')
    if parts:
        lines.append('Observed: ' + '; '.join(parts) + '.')

    compromised = [a for a in inc.threat_actors if a.is_successful]
    if compromised:
        lines.append(
            f'\n*** ALERT: {len(compromised)} IP(s) achieved a SUCCESSFUL LOGIN '
            f'after failed attempts. ***'
        )
    lines.append('')

    # ── Event breakdown ────────────────────────────────────────────────────────
    if inc.event_counts:
        lines += [sep, 'EVENT BREAKDOWN', sep]
        for etype, count in sorted(inc.event_counts.items(), key=lambda x: -x[1]):
            lines.append(f'  {etype:<28} {count:>5}')
        lines.append('')

    # ── Threat actors ──────────────────────────────────────────────────────────
    if inc.threat_actors:
        lines += [sep, 'THREAT ACTORS', sep]
        for actor in inc.threat_actors[:10]:
            status = 'COMPROMISED' if actor.is_successful else 'blocked'
            users_str = ', '.join(actor.targeted_users) if actor.targeted_users else 'unknown'
            lines += [
                f'  IP: {actor.ip}',
                f'    Status      : {status}',
                f'    Failed      : {actor.failed_attempts}',
                f'    Successful  : {actor.successful_logins}',
                f'    Users       : {users_str}',
                f'    Active      : {actor.first_seen}  ->  {actor.last_seen}',
                '',
            ]
        if len(inc.threat_actors) > 10:
            lines.append(f'  ... and {len(inc.threat_actors) - 10} more IP(s)')
            lines.append('')

    # ── Affected users ─────────────────────────────────────────────────────────
    if inc.affected_users:
        lines += [sep, 'AFFECTED USERS', sep]
        user_list = inc.affected_users[:20]
        lines.append('  ' + ', '.join(user_list))
        if len(inc.affected_users) > 20:
            lines.append(f'  ... and {len(inc.affected_users) - 20} more')
        lines.append('')

    # ── Recommendations ────────────────────────────────────────────────────────
    lines += [sep, 'RECOMMENDATIONS', sep]
    for i, rec in enumerate(inc.recommendations, 1):
        wrapped = textwrap.fill(rec, width=W - 5, subsequent_indent='     ')
        lines.append(f'  {i}. {wrapped}')
    lines += ['', dbl]

    return '\n'.join(lines)


def report(df: pd.DataFrame, log_path: str = 'auth.log') -> str:
    """Convenience: analyze df and return the formatted narrative string."""
    return generate_narrative(analyze(df, log_path))


# ── CLI ────────────────────────────────────────────────────────────────────────

def _cmd_analyze(args: argparse.Namespace) -> int:
    from ingest import ingest
    from hunter import build_attack_chains
    from reporter import generate_report

    log_path = Path(args.log_path).resolve()
    output_path = Path(args.output)
    processed_dir = Path(args.processed_dir)

    try:
        events = ingest(log_path, fmt=args.fmt, processed_dir=processed_dir)
    except FileNotFoundError:
        print(f"Error: log file not found: {log_path}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    chains = build_attack_chains(events, threshold=args.threshold)
    generate_report(chains, events, output_path=output_path)
    print(f"Analyzed {len(events)} events, {len(chains)} attack chain(s). Report: {output_path}")
    return 0


def _cmd_demo(_args: argparse.Namespace) -> int:
    import tempfile
    from ingest import ingest
    from hunter import build_attack_chains
    from reporter import generate_report
    from generate_lab import generate_lab

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        log_path = generate_lab(output_path=tmp_path / 'demo_attack.log')
        processed_dir = tmp_path / 'processed'
        report_path = tmp_path / 'demo_report.md'

        print('Generating synthetic multi-stage attack log...')
        events = ingest(log_path, fmt='auth_log', processed_dir=processed_dir)
        print(f'Ingested {len(events)} events. Hunting attack chains...')
        chains = build_attack_chains(events)
        print(f'Found {len(chains)} attack chain(s). Building report...')
        generate_report(chains, events, output_path=report_path)
        report_text = report_path.read_text(encoding='utf-8')

    print('\n' + '=' * 70)
    print(report_text)
    print('=' * 70)
    print(f'\nDemo complete. {len(chains)} chain(s), {len(events)} events analyzed.')
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from ingest import verify_integrity

    log_path = Path(args.log_path).resolve()
    processed_dir = Path(args.processed_dir)

    if verify_integrity(log_path, processed_dir=processed_dir):
        print(f"OK: SHA-256 match for {log_path.name}")
        return 0
    print(f"FAIL: hash mismatch or no hash file for {log_path.name}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    """
    Entry point for the Cyber Incident Storyteller CLI.

    Exit codes: 0 success, 1 user/parse error, 2 integrity verification failure.
    """
    p = argparse.ArgumentParser(
        prog='storyteller',
        description='Cyber Incident Storyteller — DFIR log analysis and report generation',
    )
    sub = p.add_subparsers(dest='command', metavar='command')
    sub.required = True

    p_analyze = sub.add_parser('analyze', help='Ingest a log and generate an incident report')
    p_analyze.add_argument('log_path', help='Path to the log file to analyze')
    p_analyze.add_argument('--fmt', default='auth_log', choices=SUPPORTED_FORMATS,
                           help='Log format (default: auth_log)')
    p_analyze.add_argument('--output', default='reports/incident.md',
                           help='Output report path (default: reports/incident.md)')
    p_analyze.add_argument('--processed-dir', default='data/processed',
                           help='Directory for processed cache and SHA-256 hashes')
    p_analyze.add_argument('--threshold', type=int, default=5,
                           help='Min failed logins to flag an IP as attacker (default: 5)')

    p_verify = sub.add_parser('verify', help='Verify forensic integrity of an ingested log')
    p_verify.add_argument('log_path', help='Path to the log file to verify')
    p_verify.add_argument('--processed-dir', default='data/processed',
                          help='Directory containing SHA-256 hash files')

    sub.add_parser('demo', help='Run a self-contained demo: generate synthetic logs, hunt chains, print report')

    args = p.parse_args(argv)
    if args.command == 'analyze':
        return _cmd_analyze(args)
    if args.command == 'verify':
        return _cmd_verify(args)
    if args.command == 'demo':
        return _cmd_demo(args)
    return 1


if __name__ == '__main__':
    sys.exit(main())
