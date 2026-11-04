#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
git_metadata=$(git -C "$repo" rev-parse --absolute-git-dir)
git_common_metadata=$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir)
rebuild=${1:-}
if [[ -n "$rebuild" && "$rebuild" != --rebuild ]]; then
    echo 'Usage: build-full.sh [--rebuild]' >&2
    exit 2
fi
docker info >/dev/null
ensure_image() {
    if [[ "$rebuild" == --rebuild ]] || ! docker image inspect "$1" >/dev/null 2>&1; then
        docker build --network host -t "$1" -f "$repo/scripts/local-tests/$2" "$repo/scripts/local-tests"
    fi
}
ensure_image amnezia-local-qt-tests Dockerfile.qt
ensure_image amnezia-local-full-build Dockerfile.full
# Dependencies and build artifacts persist in this dedicated Docker volume;
# source changes made by CMake/Qt translation tools stay in the private copy.
docker run --rm --network host \
    -e CONAN_HOME=/work/conan -e GOMODCACHE=/work/go/modules \
    -e GOCACHE=/work/go/build-cache -e CCACHE_DIR=/work/ccache \
    -e LANG=C.UTF-8 -e LC_ALL=C.UTF-8 \
    --mount "type=bind,source=$repo,target=/src,readonly" \
    --mount "type=bind,source=$git_metadata,target=/input/worktree-git,readonly" \
    --mount "type=bind,source=$git_common_metadata,target=/input/common-git,readonly" \
    --mount type=volume,source=amnezia-local-full-build,target=/work \
    amnezia-local-full-build bash -ec '
        mkdir -p /work/src
        tar -C /src --exclude=./.git -cf - . | tar -C /work/src -xf -
        if [ -f /work/src/.git ]; then rm -f /work/src/.git; fi
        mkdir -p /work/src/.git
        cp -a /input/common-git/. /work/src/.git/
        cp /input/worktree-git/HEAD /work/src/.git/HEAD
        cp /input/worktree-git/index /work/src/.git/index
        rm -f /work/src/.git/commondir /work/src/.git/gitdir
        git config --file /work/src/.git/config core.worktree /work/src
        if [ -f /work/src/.git/config.worktree ]; then
            git config --file /work/src/.git/config.worktree core.worktree /work/src
        fi
        git config --global --add safe.directory /work/src
        conan profile detect --force
        cmake -S /work/src -B /work/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DAMNEZIA_BUILD_TESTS=ON -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
        cmake --build /work/build -j 6
        ctest --test-dir /work/build/client/tests --output-on-failure --timeout 120
    '
