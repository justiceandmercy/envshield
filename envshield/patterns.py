import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern
    severity: str


PATTERNS = [
    Pattern('aws-access-key', re.compile(r'AKIA[0-9A-Z]{16}'), 'high'),
    Pattern('github-token', re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'), 'high'),
    Pattern('gitlab-token', re.compile(r'glpat-[A-Za-z0-9_-]{20,}'), 'high'),
    Pattern('private-key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), 'critical'),
    Pattern('jwt', re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), 'high'),
    Pattern('generic-secret', re.compile(r'(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s]{8,}'), 'medium'),
]

WEAK_VALUES = {
    'password', '123456', 'admin', 'changeme', 'secret', 'letmein',
    'qwerty', 'password1', 'root', 'toor',
}

MIN_SECRET_LENGTH = 8
