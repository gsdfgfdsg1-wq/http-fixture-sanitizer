# http-fixture-sanitizer

A dependency-free CLI for converting HTTP fixtures into shareable test data without exposing selected request or response fields.

## Quick start

```bash
python sanitize.py fixture.json --header Authorization --query token --json-path /user/email
```

The sanitizer redacts named headers, query parameters, and response JSON paths while preserving fixture shape. It emits the transformed fixture and an audit list of applied rules.

## Test

```bash
python -m unittest discover -v
```

## License

MIT.
