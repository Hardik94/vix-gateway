"""WireGuard hub-spoke client commands (paid tier)."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from meshdrive.constants import SHARE, VAR, WG_STATE, ensure_runtime_dirs
from meshdrive.license import require_addon

WG_CONF_DEST = Path("/etc/wireguard/wg0.conf")
NFT_DEST = Path("/etc/nftables.d/meshdrive-wg-client.nft")


def _repo_wg_root() -> Path | None:
    candidates = [
        SHARE / "wireguard",
        Path("/opt/meshdrive/share/wireguard"),
        Path(__file__).resolve().parents[4] / "infra" / "wireguard-hub-spoke",
    ]
    for path in candidates:
        if (path / "scripts" / "bootstrap-wg-debian.sh").is_file():
            return path
    return None


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def _require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("this command must run as root (sudo meshdrive wireguard …)")


def _parse_wg_addresses(conf_text: str) -> tuple[str | None, str | None]:
    v4 = v6 = None
    for line in conf_text.splitlines():
        line = line.strip()
        if line.lower().startswith("address"):
            _, _, rest = line.partition("=")
            for part in rest.split(","):
                part = part.strip()
                if ":" in part:
                    v6 = part.split("/")[0]
                elif "." in part:
                    v4 = part.split("/")[0]
    return v4, v6


def bootstrap(_args: argparse.Namespace) -> int:
    require_addon("wireguard")
    _require_root()
    root = _repo_wg_root()
    if not root:
        raise RuntimeError("wireguard templates not found in package share/")
    script = root / "scripts" / "bootstrap-wg-debian.sh"
    if not script.is_file():
        raise RuntimeError(f"bootstrap script missing: {script}")
    proc = subprocess.run(["bash", str(script), "client"], check=False)
    if proc.returncode != 0:
        raise RuntimeError("wireguard bootstrap failed")
    print("WireGuard OS packages installed.")
    return 0


def apply(args: argparse.Namespace) -> int:
    require_addon("wireguard")
    _require_root()
    ensure_runtime_dirs()
    src = Path(args.file).expanduser().resolve()
    if not src.is_file():
        raise RuntimeError(f"config not found: {src}")
    conf_text = src.read_text(encoding="utf-8")
    if "PrivateKey" in conf_text and re.search(r"PrivateKey\s*=\s*\S+", conf_text):
        pass
    WG_CONF_DEST.parent.mkdir(parents=True, exist_ok=True)
    WG_CONF_DEST.write_text(conf_text, encoding="utf-8")
    WG_CONF_DEST.chmod(0o600)

    v4 = args.v4
    v6 = args.v6
    if not v4 or not v6:
        parsed_v4, parsed_v6 = _parse_wg_addresses(conf_text)
        v4 = v4 or parsed_v4
        v6 = v6 or parsed_v6

    wg_root = _repo_wg_root()
    nft_template = None
    if wg_root:
        nft_template = wg_root / "scripts" / "nft-client.nft"
    if not nft_template or not nft_template.is_file():
        nft_template = SHARE / "wireguard" / "nft-client.nft"
    if nft_template.is_file() and v4 and v6:
        nft_text = nft_template.read_text(encoding="utf-8")
        nft_text = re.sub(r"define THIS_V4\s*=\s*[^\n]+", f"define THIS_V4   = {v4}", nft_text)
        nft_text = re.sub(r"define THIS_V6\s*=\s*[^\n]+", f"define THIS_V6   = {v6}", nft_text)
        NFT_DEST.parent.mkdir(parents=True, exist_ok=True)
        NFT_DEST.write_text(nft_text, encoding="utf-8")
        if shutil.which("nft"):
            _run(["nft", "-f", str(NFT_DEST)], check=False)

    state = {
        "config": str(WG_CONF_DEST),
        "source": str(src),
        "this_v4": v4,
        "this_v6": v6,
    }
    WG_STATE.parent.mkdir(parents=True, exist_ok=True)
    WG_STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    WG_STATE.chmod(0o600)

    if shutil.which("systemctl"):
        _run(["systemctl", "enable", "wg-quick@wg0"], check=False)
    print(f"Applied WireGuard config to {WG_CONF_DEST}")
    return 0


def up(_args: argparse.Namespace) -> int:
    require_addon("wireguard")
    _require_root()
    if not WG_CONF_DEST.is_file():
        raise RuntimeError(f"missing {WG_CONF_DEST}; run meshdrive wireguard apply first")
    if not shutil.which("wg-quick"):
        raise RuntimeError("wg-quick not found; run meshdrive wireguard bootstrap")
    _run(["systemctl", "enable", "--now", "wg-quick@wg0"])
    print("WireGuard tunnel wg0 started.")
    return 0


def down(_args: argparse.Namespace) -> int:
    require_addon("wireguard")
    _require_root()
    _run(["systemctl", "stop", "wg-quick@wg0"], check=False)
    print("WireGuard tunnel wg0 stopped.")
    return 0


def status(_args: argparse.Namespace) -> int:
    require_addon("wireguard")
    if shutil.which("wg"):
        proc = subprocess.run(["wg", "show"], text=True, capture_output=True)
        print(proc.stdout or proc.stderr or "(no output)")
    else:
        print("wg command not found")
    if WG_STATE.is_file():
        print("\nstate:", WG_STATE.read_text(encoding="utf-8"))
    hub_v4 = "10.200.22.1"
    if shutil.which("ping"):
        proc = subprocess.run(["ping", "-c", "2", "-W", "2", hub_v4], capture_output=True, text=True)
        print(f"\nping {hub_v4}: exit={proc.returncode}")
    return 0
