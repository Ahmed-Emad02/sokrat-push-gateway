#!/usr/bin/env python3
"""Validate operator-supplied gateway UDP media endpoints for the host firewall.

The value is a comma-separated list of unprivileged ports or inclusive
``start:end`` ranges. Empty means no direct/plain gateway media endpoint is
exposed. Output is the canonical comma-separated list with an explicit ``/udp``
suffix, suitable for ufw, firewalld and the sanitized host-firewall summary.
This helper never changes a firewall by itself and never invents a default.
"""
import argparse
import re
import sys

MAX_ENTRIES = 8
PORT_RE = re.compile(r"[0-9]{1,5}")


def parse(value):
    if not isinstance(value, str):
        raise ValueError("port list must be a string")
    entries = []
    if not value.strip():
        return entries
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            raise ValueError("empty media port entry")
        if item.endswith("/udp"):
            item = item[:-4]
        if "/" in item:
            raise ValueError("media ports must use UDP")
        start_text, separator, end_text = item.partition(":")
        if not PORT_RE.fullmatch(start_text) or (separator and not PORT_RE.fullmatch(end_text)):
            raise ValueError("invalid media port")
        start = int(start_text)
        end = int(end_text) if separator else start
        if start < 1024 or end > 65535 or start > end:
            raise ValueError("media ports must be unprivileged and ordered")
        entry = str(start) if start == end else f"{start}:{end}"
        if entry not in entries:
            entries.append(entry)
    if len(entries) > MAX_ENTRIES:
        raise ValueError("too many media port entries")
    return entries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ports", nargs="?", default="")
    args = parser.parse_args(argv)
    try:
        entries = parse(args.ports)
    except ValueError as error:
        # Never echo the caller's value: it is interpolated into firewall rules.
        print(f"media-udp-ports: {error}", file=sys.stderr)
        return 2
    print(",".join(entry + "/udp" for entry in entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
