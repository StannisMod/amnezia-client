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
    local image=$1 dockerfile=$2
    shift 2
    local options=()
    [[ "$rebuild" != --rebuild ]] || options+=(--rebuild)
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --build-arg) options+=(--build-arg "$2"); shift 2 ;;
            *) echo "Unsupported build option: $1" >&2; return 2 ;;
        esac
    done
    python3 "$repo/scripts/local-tests/lab_cache.py" image "$image" \
        --dockerfile "$repo/scripts/local-tests/$dockerfile" \
        --context "$repo/scripts/local-tests" "${options[@]}"
}
# The full build uses Ubuntu22 only. Do not install an unused Ubuntu24 Qt image.
ensure_image amnezia-local-qt-tests-ubuntu22 Dockerfile.qt --build-arg BASE_UBUNTU_VERSION=22.04
ensure_image amnezia-local-full-build-ubuntu22 Dockerfile.full
# Dependencies and build artifacts persist in this dedicated Docker volume;
# source changes made by CMake/Qt translation tools stay in the private copy.
docker run --rm --pull=never --network host --cpus 2 --memory 4g --memory-swap 4g \
    -e CONAN_HOME=/work/conan -e GOMODCACHE=/work/go/modules \
    -e GOCACHE=/work/go/build-cache -e CCACHE_DIR=/work/ccache \
    -e LANG=C.UTF-8 -e LC_ALL=C.UTF-8 \
    --mount "type=bind,source=$repo,target=/src,readonly" \
    --mount "type=bind,source=$git_metadata,target=/input/worktree-git,readonly" \
    --mount "type=bind,source=$git_common_metadata,target=/input/common-git,readonly" \
    --mount type=volume,source=amnezia-local-full-build-ubuntu22,target=/work \
    amnezia-local-full-build-ubuntu22 flock -x /work/build.lock bash -ec '
        # Source must exactly match this worktree; dependencies/build caches live elsewhere.
        python3 /src/scripts/local-tests/prepare_cached_source.py /src /work/src \
            /input/worktree-git /input/common-git
        git config --global --add safe.directory /work/src
        if ! conan profile path default >/dev/null 2>&1; then conan profile detect; fi
        cmake -S /work/src -B /work/build -G Ninja -DCMAKE_BUILD_TYPE=Release -DAMNEZIA_BUILD_TESTS=ON -DAMNEZIA_CONAN_PREBUILTS=OFF -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
        cmake --build /work/build -j 2
        ctest --test-dir /work/build/client/tests --output-on-failure --timeout 120
    '
