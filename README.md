# envshield

Scan environment variables and `.env` files for leaked secrets, weak values, and risky assignments.

## Features

- Detects common secret formats such as AWS keys, GitHub tokens, GitLab tokens, JWTs, and private keys.
- Flags weak or default values such as `password` and `changeme`.
- Highlights sensitive variable names that contain long values.
- Reads `.env` files and directories recursively.
- Supports text and JSON output.
- Uses only the Python standard library.

## Install

```bash
python -m pip install .
```

## Usage

Scan the current environment:

```bash
envshield --env
```

Scan one file:

```bash
envshield --path .env
```

Scan a project directory:

```bash
envshield --path . --min-severity medium
```

JSON output:

```bash
envshield --path .env --json
```

Fail in CI when findings exist:

```bash
envshield --path . --fail
```

## Library

```python
from envshield.scanner import scan_mapping

findings = scan_mapping({'API_TOKEN': 'ghp_' + 'a' * 36}, 'ci')
for finding in findings:
    print(finding.key, finding.pattern, finding.severity)
```

## License

MIT
