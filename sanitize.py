#!/usr/bin/env python3
"""Sanitize HTTP fixtures while preserving request and response structure."""
import argparse
import json
from copy import deepcopy
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def sanitize(fixture, header_names=(), query_names=(), json_paths=()):
    output, audit = deepcopy(fixture), []
    headers = output.get("request", {}).get("headers", {})
    for name in header_names:
        if name in headers:
            headers[name] = "[REDACTED]"; audit.append(f"header:{name}")
    url = output.get("request", {}).get("url")
    if url:
        parts = urlsplit(url)
        query = [(k, "[REDACTED]" if k in query_names else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
        output["request"]["url"] = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
        audit.extend(f"query:{name}" for name in query_names if name in dict(parse_qsl(parts.query)))
    body = output.get("response", {}).get("json", {})
    for path in json_paths:
        target, parts = body, path.strip("/").split("/")
        for part in parts[:-1]: target = target.get(part, {}) if isinstance(target, dict) else {}
        if isinstance(target, dict) and parts[-1] in target:
            target[parts[-1]] = "[REDACTED]"; audit.append(f"json:{path}")
    return {"fixture": output, "audit": audit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture"); parser.add_argument("--header", action="append", default=[]); parser.add_argument("--query", action="append", default=[]); parser.add_argument("--json-path", action="append", default=[])
    args = parser.parse_args()
    print(json.dumps(sanitize(json.loads(Path(args.fixture).read_text()), args.header, args.query, args.json_path), indent=2))


if __name__ == "__main__":
    main()
