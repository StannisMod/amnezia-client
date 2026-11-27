# Local lab cache

Normal validation **reuses installed images, SDKs, downloads and workspaces**.
Do not create a new source/build/toolchain directory for each run or commit.
Evidence directories contain logs, input hashes and small test results, not
copies of SDKs, VM disks, Gradle build trees or identical AARs.

## Docker and installed tools

`build-full.sh` and `run.sh` reuse existing image IDs. They do not build or pull
an installed image on every run. First bootstrap or an intentional image recipe
upgrade requires `--rebuild`; normal source changes do not:

```sh
bash scripts/local-tests/build-full.sh          # installed images only
bash scripts/local-tests/run.sh qt             # installed image only
# Explicit, potentially large first bootstrap/recipe upgrade:
bash scripts/local-tests/build-full.sh --rebuild
```

Existing legacy image IDs are recorded as reused, **not** claimed to match a
new Dockerfile. Docker builds use the engine's own BuildKit store, not another
exported multi-GB `cache-to=local` copy. The Dockerfiles add locked apt/apk/pip
download caches. The Qt SDK is a separate stage so unrelated build-tool changes
do not reinstall it.

`aqt_cached.py` verifies existing archives against the hash supplied by aqt,
including in aqt's spawned workers. `--keep` alone is insufficient: aqt3.3 would
download and overwrite the archive again. No checksum/TLS checks are disabled.
If the SDK stage really must run, aqt can still retrieve small upstream metadata
to obtain current official hashes; verified bulk archives are reused.

Conan, Go, Gradle, ccache and Android SDK/NDK directories remain in their existing
named volumes. No cache migration, global prune, image deletion, volume deletion,
VM compaction or failure-evidence deletion happens automatically.

## Incremental source/build workspaces

`lab_cache.Cache.workspace(profile)` holds an exclusive lock for the **entire
build**. Profiles identify toolchain/ABI/purpose, not a source commit or test-run
number. `sync_tree` writes only changed sources and preserves build outputs.
Only unchanged previously manifested source files may be retired when removed
from the input; unowned/externally edited files cause a refusal, never overwrite.

`prepare_cached_source.py` replaces the former `rm -rf /work/src` + full tar copy
in `build-full.sh`. It also references the mounted read-only Git object database,
rather than repeatedly copying all object packs. An unmanifested legacy private
copy with differing files is retained and must be inspected, not blindly adopted.

For Android Xray Kotlin checks, use the reusable runner:

```sh
python3 scripts/routing/check_android_native_dns_cached.py \
  --cache-root /work/lab-cache \
  --evidence /evidence/unique-run-name \
  --aar /path/to/verified-api-fixture.aar \
  --aar-sha256 ACTUAL_VERIFIED_SHA256
```

Run inside the existing Android tools image with the existing `/work` volume,
`--pull=never --network none --cpus 2 --memory 4g --memory-swap 4g`.
The AAR is referenced in place, not copied into each evidence directory.
The runner uses Gradle `--offline`, records the source/dependency identity and
distinguishes reused test outputs from new device/backend acceptance.

## Downloads and VM reuse

`lab_cache.py fetch URL SHA256 BYTE_LENGTH` is offline by default. An explicit
`--online` permits a missing immutable object to download once. Hits verify the
digest/length without rewriting it. Owned partials resume only after an exact
HTTP Range confirmation; corrupt objects/partials are retained and refused.

The Windows harness already keeps the evaluation VHD and qcow2 state in its
existing volume. `prepare_disk.py` now returns a read-only cache hit when its
base identity and owned disks/config agree: no guestfish uploads, formatting,
OS installation or disk recreation. Missing/mismatched existing state is an
error, not permission to reinstall. This is a preparation cache hit, not a claim
that the guest has passed runtime acceptance. `download_image.py` still checks
the base SHA256 but no longer rewrites unchanged provenance or file permissions.

The VM runner also takes a per-VM ownership lock and caps guest resources
without rewriting stored identity. A graceful shutdown timeout retains QEMU;
use `docker stop --timeout=-1` when requesting a graceful container stop.
A finite Docker timeout can itself SIGKILL the container and is not a native
cleanup/join guarantee. VM boot/shutdown acceptance was not rerun for cache tests.

## Checks

```sh
python3 -m unittest discover -s scripts/local-tests -p test_lab_cache.py -v
```

Measured on 2026-11-26: the second real Android cached run had **47/47 Gradle
tasks up-to-date**, **0 source bytes rewritten** and workspace growth of
**2,450 bytes**, not a new build tree. The first workspace was 2,416,601 bytes.
Actual cached VM preparation succeeded on read-only mounts with zero provisioning
commands/disk writes. No heavy SDK/Docker cold rebuild was performed just to test
the cache change; installed image reuse and cache primitives were executed.
