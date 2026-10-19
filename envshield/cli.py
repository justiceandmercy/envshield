import argparse
import json
import sys
from pathlib import Path
from dataclasses import asdict

from .scanner import scan_environment, scan_path
from . import __version__

SEVERITY_ORDER = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='envshield', description='Scan environment variables and .env files for leaked secrets.')
    parser.add_argument('--env', action='store_true', help='scan current process environment')
    parser.add_argument('--path', type=Path, help='file or directory to scan')
    parser.add_argument('--json', action='store_true', help='emit JSON')
    parser.add_argument('--min-severity', choices=sorted(SEVERITY_ORDER), default='low', help='minimum severity to report')
    parser.add_argument('--fail', action='store_true', help='exit with status 1 when findings exist')
    args = parser.parse_args(argv)

    if not args.env and not args.path:
        parser.error('choose --env or --path')

    findings = []
    if args.env:
        findings.extend(scan_environment())
    if args.path:
        findings.extend(scan_path(args.path))

    threshold = SEVERITY_ORDER[args.min_severity]
    findings = [finding for finding in findings if SEVERITY_ORDER.get(finding.severity, 0) >= threshold]

    seen = set()
    unique = []
    for finding in findings:
        key = (finding.source, finding.key, finding.pattern, finding.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    findings = unique

    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2))
    else:
        if not findings:
            print('no findings')
        for finding in findings:
            print(f'{finding.source}: {finding.key}={finding.value} [{finding.pattern}/{finding.severity}]')

    if args.fail and findings:
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
