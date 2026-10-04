"""Shared helpers for shell tests (pytest). Shell versions come from the
environment: containers for minimum versions, Homebrew on macOS."""
import os
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FAKE = ROOT / "tests/shell/fake_bingsu.sh"
SHELL_CMD = {"zsh": ["zsh", "-f"], "bash": ["bash", "--noprofile", "--norc"], "fish": ["fish", "--no-config"]}


def real_bin():
    return pathlib.Path(os.environ.get("BINGSU_BIN", ROOT / "target/debug/bingsu")).resolve()


class Install:
    """A folder holding `bingsu` as a symlink. init runs through the symlink
    (so the symlink path is pinned); use_fake() then swaps the target."""

    def __init__(self, base: pathlib.Path, name: str = "bin"):
        self.dir = base / name
        self.dir.mkdir(parents=True)
        self.exe = self.dir / "bingsu"
        os.symlink(real_bin(), self.exe)

    def init(self, shell, env):
        r = subprocess.run([str(self.exe), "init", shell], env=env, capture_output=True)
        assert r.returncode == 0, r.stderr
        return r.stdout

    def use_fake(self, record: bytes):
        (self.dir / "record.bin").write_bytes(record)
        self.exe.unlink()
        os.symlink(FAKE, self.exe)

    def calls(self):
        log = self.dir / "argv.log"
        if not log.exists():
            return []
        out, cur = [], []
        for a in log.read_bytes().split(b"\0")[:-1]:
            if a == b"END":
                out.append(cur)
                cur = []
            else:
                cur.append(a)
        return out


def trusted_env(base: pathlib.Path, tag: str = "t"):
    return {
        "PATH": os.environ["PATH"],
        "XDG_RUNTIME_DIR": str(base / f"run-{tag}"),
        "XDG_CONFIG_HOME": str(base / f"cfg-{tag}"),
        "XDG_STATE_HOME": str(base / f"state-{tag}"),
        "XDG_CACHE_HOME": str(base / f"cache-{tag}"),
        "LC_ALL": os.environ.get("BINGSU_TEST_LOCALE", "C.UTF-8"),
    }


def run_shell_script(shell, script: bytes, env, tmp: pathlib.Path):
    f = tmp / f"script.{shell}"
    f.write_bytes(script)
    return subprocess.run(SHELL_CMD[shell] + [str(f)], env=env, capture_output=True, timeout=60)


def short_dir():
    """A short directory for canary files: pytest tmp paths are long enough
    that a prompt embedding two of them exceeds 80 columns."""
    import tempfile
    return pathlib.Path(tempfile.mkdtemp(prefix="bc", dir="/tmp"))


def minimal_record(status=b"ok:none", left=b"> "):
    return b"B1\x1f7\x1f" + left + b"\x1f\x1f\x1f\x1f\x1f\x1f" + status + b"\x1e"


@pytest.fixture
def shells():
    return [s for s in os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()]
