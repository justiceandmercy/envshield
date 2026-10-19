from pathlib import Path

from envshield.scanner import scan_mapping, parse_dotenv, scan_path


def test_detects_aws_key():
    findings = scan_mapping({'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE'}, 'test')
    assert any(finding.pattern == 'aws-access-key' for finding in findings)


def test_weak_value():
    findings = scan_mapping({'DB_PASSWORD': 'password'}, 'test')
    assert any(finding.pattern == 'weak-value' for finding in findings)


def test_parse_dotenv(tmp_path):
    env_file = tmp_path / '.env'
    env_file.write_text('API_TOKEN=ghp_' + 'a' * 36 + '\nDB_PASS=changeme\n', encoding='utf-8')
    mapping = parse_dotenv(env_file)
    assert mapping['API_TOKEN'].startswith('ghp_')
    findings = scan_path(env_file)
    assert len(findings) >= 2


def test_clean_values_have_no_findings():
    findings = scan_mapping({'APP_NAME': 'envshield', 'PORT': '8080'}, 'test')
    assert findings == []
