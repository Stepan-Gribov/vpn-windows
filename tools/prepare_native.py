#!/usr/bin/env python3
"""Stage pinned, already-cached native modules without changing global caches.

No network access, downloads, package installation, or mobile-repository writes.
The Windows-owned native snapshot is retained when this script is rerun.
"""
from pathlib import Path
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "native" / "CombinedXray"
# Treat private module copies as standalone patch trees even inside this repo.
ENV = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local",
           GIT_CEILING_DIRECTORIES=str(ROOT / ".build"))
MODULES = (
    ("github.com/xtls/xray-core", "github.com/autorepobot/xray-core@v0.0.0-20260704054728-50c452881eb9", "xray", "XrayCoreIOS.patch"),
    ("github.com/amnezia-vpn/amneziawg-go/v3", "github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260828", "awg", "AmneziaWGTimers.patch"),
)


def run(args, cwd=ENGINE):
    result = subprocess.run(args, cwd=cwd, env=ENV, text=True, capture_output=True)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"Command failed: {args[0]}")
    return result.stdout.strip()


def prepare():
    cache = Path(run(["go", "env", "GOMODCACHE"]))
    for module, cached_name, name, patch in MODULES:
        source = cache / cached_name
        target = ROOT / ".build" / name
        patch_file = ENGINE / patch
        if not target.exists():
            if not source.is_dir():
                raise SystemExit(f"Required module is not cached: {cached_name}. No download attempted.")
            shutil.copytree(source, target)
        # Module-cache directories are read-only too. Git patches replace files,
        # so making just the copied files writable is insufficient.
        for p in [target, *target.rglob("*")]:
            p.chmod(p.stat().st_mode | (0o700 if p.is_dir() else 0o200))
        forward = subprocess.run(["git", "apply", "--check", str(patch_file)], cwd=target, env=ENV, capture_output=True)
        if forward.returncode == 0:
            run(["git", "apply", "--check", str(patch_file)], target)
            run(["git", "apply", str(patch_file)], target)
        else:
            # A failed/partial or manually modified staging tree is never silently
            # accepted. Reverse-check confirms that the expected patch is present.
            run(["git", "apply", "--reverse", "--check", str(patch_file)], target)
        if name == "xray":
            for name in ("desktop_physical_windows.go", "desktop_packet.go", "desktop_release_windows.go"):
                shutil.copyfile(ROOT / "patches" / name, target / "proxy" / "tun" / name)
            for name in ("WindowsDesktop.patch", "WindowsReleaseRoutes.patch"):
                desktop_patch = ENGINE / name
                check = subprocess.run(["git", "apply", "--check", str(desktop_patch)], cwd=target, env=ENV, capture_output=True)
                if check.returncode == 0:
                    run(["git", "apply", str(desktop_patch)], target)
                else:
                    run(["git", "apply", "--reverse", "--check", str(desktop_patch)], target)
        relative = os.path.relpath(target, ENGINE)
        run(["go", "mod", "edit", f"-replace={module}={relative}"])
    print("Prepared private Xray/AWG copies from the existing cache; downloads disabled.")


if __name__ == "__main__":
    prepare()

