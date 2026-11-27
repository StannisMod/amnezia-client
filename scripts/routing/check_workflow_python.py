#!/usr/bin/env python3
"""Parse embedded Python heredocs before expensive platform builds start."""
import ast
from pathlib import Path
import re
import sys
import textwrap


def check(path):
    lines = Path(path).read_text().splitlines(keepends=True)
    count = 0
    for index, line in enumerate(lines):
        match = re.search(r"\bpython3?\s+-\s+<<['\"]?(\w+)['\"]?\s*$", line)
        if not match:
            continue
        marker = match.group(1)
        end = next((i for i in range(index + 1, len(lines))
                    if lines[i].strip() == marker), None)
        if end is None:
            raise ValueError(f"{path}:{index + 1}: missing heredoc terminator {marker}")
        source = textwrap.dedent("".join(lines[index + 1:end]))
        ast.parse(source, filename=f"{path}:{index + 2}")
        count += 1
    if not count:
        raise ValueError(f"{path}: no Python heredocs found")
    print(f"{path}: {count} embedded Python blocks parsed")


if __name__ == "__main__":
    for path in sys.argv[1:]:
        check(path)
