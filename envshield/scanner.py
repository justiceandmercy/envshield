from dataclasses import dataclass
from pathlib import Path
import os

from .patterns import PATTERNS, WEAK_VALUES, MIN_SECRET_LENGTH


@dataclass
class Finding:
    source: str
    key: str
    value: str
    pattern: str
    severity: str


def mask_value(value):
    if len(value) <= 4:
        return '*' * len(value)
    return value[:2] + '*' * (len(value) - 4) + value[-2:]


def _scan_one(source, key, value):
    findings = []
    if not isinstance(value, str) or not value:
        return findings

    lowered = value.lower()
    matched = False
    for pattern in PATTERNS:
        if pattern.regex.search(value):
            findings.append(Finding(source, key, mask_value(value), pattern.name, pattern.severity))
            matched = True

    if lowered in WEAK_VALUES:
        findings.append(Finding(source, key, mask_value(value), 'weak-value', 'high'))

    sensitive_key = any(term in key.lower() for term in ('password', 'secret', 'token', 'key'))
    if sensitive_key and len(value) >= MIN_SECRET_LENGTH and not matched and lowered not in WEAK_VALUES:
        findings.append(Finding(source, key, mask_value(value), 'sensitive-key-with-value', 'medium'))

    return findings


def scan_mapping(mapping, source):
    findings = []
    for key, value in mapping.items():
        findings.extend(_scan_one(source, key, value))
    return findings


def parse_dotenv(path):
    mapping = {}
    for raw_line in Path(path).read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].strip()
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip()
        if value and value[0] in (chr(34), "'") and value[-1] == value[0]:
            value = value[1:-1]
        mapping[key] = value
    return mapping


def scan_path(path):
    path = Path(path)
    findings = []
    if path.is_dir():
        candidates = []
        for candidate in path.rglob('*'):
            if candidate.is_file() and (candidate.name == '.env' or candidate.name.startswith('.env.')):
                candidates.append(candidate)
        for candidate in sorted(candidates):
            findings.extend(scan_mapping(parse_dotenv(candidate), str(candidate)))
    elif path.exists():
        findings.extend(scan_mapping(parse_dotenv(path), str(path)))
    return findings


def scan_environment():
    return scan_mapping(dict(os.environ), 'environment')
