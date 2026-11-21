"""Production startup assets for disposable server acceptance fixtures."""
import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def startup_assets(kind):
    """Mirror scriptsRegistry composition and installController release layout."""
    scripts = REPO / "client/server_scripts"
    startup = (scripts / kind / "start.sh").read_text()
    first, rest = startup.split("\n", 1)
    assert first.startswith("#!")
    startup = first + "\n" + (scripts / "enable_ipv6_forwarding.sh").read_text() + "\n" + rest
    files = {"start.sh": startup}
    release = None
    if kind == "awg":
        assets = {name: (REPO / "server/mtu" / name).read_text()
                  for name in ("controller.py", "supervisor.py")}
        release = hashlib.sha256("".join(assets.values()).encode()).hexdigest()
        files.update({"mtu/" + release + "/" + name: data for name, data in assets.items()})
    return files, release
