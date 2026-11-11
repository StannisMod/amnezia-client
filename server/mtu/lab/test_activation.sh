#!/bin/bash
set -euo pipefail
source_dir=$(cd "$(dirname "$0")/.." && pwd)
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT
mkdir -p "$workspace/old" "$workspace/next" "$workspace/bad"
cp "$source_dir/controller.py" "$source_dir/supervisor.py" "$workspace/next/"
ln -s "$workspace/old" "$workspace/current"
activate() {
    python3 -m py_compile "$1/controller.py" "$1/supervisor.py" &&
    ln -sfn "$1" "$workspace/current.next" &&
    mv -Tf "$workspace/current.next" "$workspace/current"
}
activate "$workspace/next"
test "$(readlink "$workspace/current")" = "$workspace/next"
printf '%s\n' 'invalid python syntax' > "$workspace/bad/controller.py"
cp "$source_dir/supervisor.py" "$workspace/bad/"
if activate "$workspace/bad" 2>/dev/null; then
    exit 1
fi
test "$(readlink "$workspace/current")" = "$workspace/next"
echo 'valid activation and failed-update preservation PASS'
