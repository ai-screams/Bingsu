"""Shared helpers for shell tests. Shell versions come from the
environment: containers for minimum versions, Homebrew on macOS."""
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The fsbudget package (strace parsing and the call formulas) lives under tools/; every module that
# imports it gets the path here once, so no import depends on which test module was loaded first.
if str(ROOT / "tools/fsbudget") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools/fsbudget"))
FAKE = ROOT / "tests/shell/fake_bingsu.sh"
SHELL_CMD = {"zsh": ["zsh", "-f"], "bash": ["bash", "--noprofile", "--norc"], "fish": ["fish", "--no-config"]}


def real_bin():
    return pathlib.Path(os.environ.get("BINGSU_BIN", ROOT / "target/debug/bingsu")).resolve()


# Terminal logs (each a function giving the output so far) of tests that ran
# bingsu as a background job and printed its pid as `BPID=<pid>`.
_BACKGROUND = []


def track_background(log):
    """At the end of the test, `end_background` kills each bingsu that `log()`
    names with `BPID=<pid>` and that is still running: a bingsu that does not
    end (a failing or mutated build) would otherwise outlive the test, its
    shell and its terminal."""
    _BACKGROUND.append(log)


def end_background():
    """Kills the tracked background bingsu processes still running, and waits
    (at most 2 s each) until they are gone. A pid is only killed while its
    command line still names `real_bin()`, so a number taken by another
    process since is left alone."""
    while _BACKGROUND:
        log = _BACKGROUND.pop()()
        for pid in sorted({int(n) for n in re.findall(rb"BPID=(\d+)", log)}):
            args = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(pid)], capture_output=True, text=True,
                                  check=False).stdout
            if str(real_bin()) not in args:
                continue
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            end = time.monotonic() + 2
            while time.monotonic() < end:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)


def cargo_test_binaries(profile_dir, package, name):
    """Executables cargo built for the target `name` of `package` under
    `profile_dir` (target/debug, target/<triple>/release). Cargo up to 1.99
    puts them in `deps/`; Cargo 1.100 gives each unit its own
    `build/<package>/<hash>/out/`, beside its object and dep-info files,
    which are not executable."""
    found = [*profile_dir.glob(f"deps/{name}-*"), *profile_dir.glob(f"build/{package}/*/out/{name}-*")]
    return [p for p in found if p.is_file() and os.access(p, os.X_OK)]


def real_prompt():
    return pathlib.Path(os.environ.get("BINGSU_PROMPT_BIN", real_bin().with_name("bingsu-prompt"))).resolve()


def real_collector():
    return pathlib.Path(os.environ.get("BINGSU_COLLECTOR_BIN", real_bin().with_name("bingsu-collect"))).resolve()


def plain_script(shell, script):
    """The init script as text: zsh's is one `$'…'` word for an eval."""
    if shell != "zsh":
        return script
    word = script.split(b"eval $'", 1)[1].rsplit(b"'\n}\n", 1)[0]
    return re.sub(rb"\\(.)", lambda m: b"\n" if m[1] == b"n" else m[1], word, flags=re.S)


def rewrapped_script(shell, script, text):
    """`text`, an edited plain_script(shell, script), in the form init gives it,
    so a test of the edit also runs the real bootstrap."""
    if shell != "zsh":
        return text
    word = text.replace(b"\\", b"\\\\").replace(b"'", b"\\'").replace(b"\n", b"\\n")
    return script.split(b"eval $'", 1)[0] + b"eval $'" + word + b"'\n}\n"


def prompt_program(script: bytes) -> bytes:
    """The program the hook of plain_script() runs for the prompt: init's
    verified `bingsu-prompt` sibling, or `bingsu` when it has none."""
    found = re.findall(rb"'([^']+)' prompt --ctx ", script)
    assert len(found) == 1, found
    return found[0]


def swap_prompt_program(script: bytes, program) -> bytes:
    """plain_script() text whose prompt call runs `program` instead."""
    old = b"'" + prompt_program(script) + b"' prompt --ctx "
    return script.replace(old, b"'" + os.fsencode(program) + b"' prompt --ctx ")


COLD_INIT_NOTICE = (b"bingsu: reading your settings did not finish in time; the prompt starts with "
                    b"the built-in look and takes your settings when they are ready\n")


class Install:
    """A folder holding `bingsu` and `bingsu-prompt` as symlinks. init runs
    through the `bingsu` symlink (so that path is pinned); use_fake() then
    swaps both targets.

    init writes the canonical path of the verified `bingsu-prompt` sibling
    into the hook, which a symlink swap cannot reach; init() rewrites that one
    word to this folder's `bingsu-prompt` link (the generated call is otherwise
    unchanged), so a stand-in sees every prompt call."""

    def __init__(self, base: pathlib.Path, name: str = "bin"):
        self.dir = base / name
        self.dir.mkdir(parents=True)
        self.exe = self.dir / "bingsu"
        self.prompt = self.dir / "bingsu-prompt"
        os.symlink(real_bin(), self.exe)
        os.symlink(real_prompt(), self.prompt)
        self.dedicated = None

    def init(self, shell, env, entry=None):
        """`entry="cli"` makes the hook call `bingsu prompt` (the fallback
        entry, its `--helper-exe=` word unchanged) where init chose
        `bingsu-prompt`; a test whose trace formulas count the CLI front uses it."""
        r = subprocess.run([str(self.exe), "init", shell], env=env, capture_output=True)
        # A warning here (an executable another user can change, a root that
        # could not be pinned) means the test runs in an arrangement it was
        # not written for, such as a CI binary owned by another uid.
        # The cold-init notice is the one allowed line: a busy machine (CI
        # containers) can need more than the 500 ms first-compile wait.
        # 이것을 실패시키는 것: 다른 경고를 이 예외에 넣는 것(그 줄만 지운 뒤 비어 있어야 한다).
        rest = r.stderr.replace(COLD_INIT_NOTICE, b"")
        assert r.returncode == 0 and rest == b"", r.stderr
        script = self.route_prompt(r.stdout)
        if entry == "cli" and self.dedicated:
            assert script.count(os.fsencode(self.prompt)) == 1, script
            script = script.replace(os.fsencode(self.prompt), os.fsencode(self.exe))
            self.dedicated = False
        return script

    def route_prompt(self, script: bytes) -> bytes:
        """Point the hook's prompt call at this folder's `bingsu-prompt` link.
        init picks the sibling of the resolved `bingsu`; a folder whose
        `bingsu` is a copy without a sibling keeps the `bingsu prompt` call."""
        # Only the prompt call names bingsu-prompt (the folders of these tests do not).
        self.dedicated = b"bingsu-prompt" in script
        sibling = os.fsencode(pathlib.Path(os.path.realpath(self.exe)).with_name("bingsu-prompt"))
        if not self.dedicated or os.fsencode(self.prompt) == sibling:
            return script
        # A plain path is written once, as the program of the prompt call.
        assert script.count(sibling) == 1, script
        return script.replace(sibling, os.fsencode(self.prompt))

    def front(self):
        """The program the hook of the last init() runs for the prompt."""
        assert self.dedicated is not None, "init() first"
        return self.prompt if self.dedicated else self.exe

    def use_fake(self, record: bytes, script=FAKE):
        (self.dir / "record.bin").write_bytes(record)
        for link in (self.exe, self.prompt):
            if link.is_symlink() or link.exists():
                link.unlink()
                os.symlink(script, link)

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


def setup_env(home: pathlib.Path):
    """The environment of a `bingsu setup` test: every XDG folder under
    `home`. Without XDG_STATE_HOME the account's own state folder (named
    from the account's home, not $HOME) holds the settings choice setup
    reads and `config use` writes."""
    return {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "cfg"),
        "XDG_STATE_HOME": str(home / "state"),
        "XDG_RUNTIME_DIR": str(home / "run"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "SHELL": "/bin/zsh",
        "PATH": os.environ["PATH"],
    }


def account_state_listing():
    """The names and metadata (never the contents) of what the account's own
    bingsu state folders hold: the one named from the account's home and,
    when the test run has one, XDG_STATE_HOME's."""
    import pwd
    folders = [pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/state/bingsu"]
    if os.environ.get("XDG_STATE_HOME"):
        folders.append(pathlib.Path(os.environ["XDG_STATE_HOME"]) / "bingsu")
    listing = []
    for folder in folders:
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except FileNotFoundError:
            listing.append((str(folder), None))
            continue
        for e in entries:
            st = e.stat(follow_symlinks=False)
            listing.append((str(folder), e.name, st.st_ino, st.st_size, st.st_mtime_ns))
    return listing


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
    return b"B1\x1f12\x1f" + left + b"\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f" + status + b"\x1e"




def status_bait_record(status, bait=b""):
    """A record with `bait` in left_vicmd, the element that held the status
    before the vi command mode fields came (bash 9, zsh and fish 10)."""
    return b"\x1f".join([b"B1", b"12", b"> ", *[b""] * 6, bait, b"", b"", b"", status]) + b"\x1e"


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
    if name in ("bingsu", "bingsu-prompt") and argv[1:2] == [b"prompt"]:
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
