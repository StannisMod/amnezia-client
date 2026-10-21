#!/usr/bin/env python3
"""Retain only allowlisted native error categories from CI strace output.

Never persist full syscall traces: service writes may contain fixture keys.
"""
import json
import re
import sys

allowed = {
    "system resolver bus unavailable", "system resolver link configuration failed",
    "system resolver link configuration lost", "capture policy installation failed",
    "native TUN creation failed", "capture reverse-path configuration failed",
    "routing statistics unavailable",
}
for line in sys.stdin:
    match = re.search(r'write\(1,\s*("(?:\\.|[^"\\])*")', line)
    if not match:
        continue
    try:
        row = json.loads(json.loads(match[1]))
    except (ValueError, TypeError):
        continue
    if isinstance(row, dict) and row.get("type") == "error":
        message = row.get("message")
        print(json.dumps({"native_failure": message if message in allowed else "unclassified native failure"}), flush=True)
