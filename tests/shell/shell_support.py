"""Shared helpers for shell tests. Shell versions come from the
environment: containers for minimum versions, Homebrew on macOS."""
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
FAKE = ROOT / "tests/shell/fake_bingsu.sh"
SHELL_CMD = {"zsh": ["zsh", "-f"], "bash": ["bash", "--noprofile", "--norc"], "fish": ["fish", "--no-config"]}


def real_bin():
    return pathlib.Path(os.environ.get("BINGSU_BIN", ROOT / "target/debug/bingsu")).resolve()


def real_collector():
    return pathlib.Path(os.environ.get("BINGSU_COLLECTOR_BIN", real_bin().with_name("bingsu-collect"))).resolve()


COLD_INIT_NOTICE = (b"bingsu: reading your settings did not finish in time; the prompt starts with "
                    b"the built-in look and takes your settings when they are ready\n")


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
        # A warning here (an executable another user can change, a root that
        # could not be pinned) means the test runs in an arrangement it was
        # not written for, such as a CI binary owned by another uid.
        # The cold-init notice is the one allowed line: a busy machine (CI
        # containers) can need more than the 500 ms first-compile wait.
        # 이것을 실패시키는 것: 다른 경고를 이 예외에 넣는 것(그 줄만 지운 뒤 비어 있어야 한다).
        rest = r.stderr.replace(COLD_INIT_NOTICE, b"")
        assert r.returncode == 0 and rest == b"", r.stderr
        return r.stdout

    def use_fake(self, record: bytes, script=FAKE):
        (self.dir / "record.bin").write_bytes(record)
        self.exe.unlink()
        os.symlink(script, self.exe)

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


_SHORT_DIRS = []


def short_dir():
    """A short directory for canary files. The hostile record embeds the
    three canary paths in the left prompt and RPROMPT, and zsh drops RPROMPT
    when the line is wider than the terminal (200 columns in
    test_zsh_hooks.start): with a 120-character directory the 8 option-matrix
    cases that draw the record fail. Removed after the test by _cleanup()."""
    d = pathlib.Path(tempfile.mkdtemp(prefix="bc", dir="/tmp"))
    _SHORT_DIRS.append(d)
    return d


def minimal_record(status=b"ok:none", left=b"> "):
    return b"B1\x1f8\x1f" + left + b"\x1f\x1f\x1f\x1f\x1f\x1f\x1f" + status + b"\x1e"




class Blocked(Exception):
    """A fixture the test needs cannot be built on this host (reason in args[0]).

    A test that catches it fails with "BLOCKED: <reason>"; it never skips,
    because a skip would count a missing fixture as a pass."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _role(pid: str):
    """Role of a live bingsu process: front, helper or collector (None otherwise).

    A zombie has an empty cmdline and no exe link, so only live parents get a role."""
    try:
        argv = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None
    name = os.path.basename(exe)
    if name == "bingsu-collect":
        return "collector"
    if name == "bingsu" and argv[1:2] == [b"__refresh-v1"]:
        return "helper"
    if name == "bingsu" and argv[1:2] == [b"prompt"]:
        return "front"
    return None


def zombie_children(roles: set[str]) -> list[int]:
    """PIDs of zombies whose parent is a live process of one of `roles` (Linux /proc)."""
    import sys
    assert sys.platform == "linux", "zombie_children reads /proc"
    status = {}
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = dict(line.split(":", 1) for line in (entry / "status").read_text().splitlines() if ":" in line)
        except OSError:
            continue
        status[entry.name] = (fields["State"].split()[0], fields["PPid"].strip())
    return sorted(int(pid) for pid, (state, parent) in status.items()
                  if state == "Z" and _role(parent) in roles)


def role_processes(roles: set[str]) -> list[int]:
    """PIDs of live processes of one of `roles` (Linux /proc)."""
    return sorted(int(entry.name) for entry in pathlib.Path("/proc").iterdir()
                  if entry.name.isdigit() and _role(entry.name) in roles)
