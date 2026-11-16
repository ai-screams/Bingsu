"""Live helper fixtures: what starts the refresh helper and collector for a traced
run (stage plans, warm-up, the helper-stage fixture, builtin-language folders,
cgroups). Nothing here judges a trace; `trace_captures.py` and `trace_support.py`
do."""
import hashlib
import os
import re
import subprocess
from pathlib import Path

from shell_support import SHELL_CMD, Install, real_bin, trusted_env


CALL = b"_bingsu_call --width 80\n"


def init_collector_exe(script):
    # This bash fixture uses plain paths; consume init's quoted pin, not the
    # build location or a sibling guessed from the symlink used to run init.
    pins = re.findall(rb"'--collector-exe=([^']*)'", script)
    assert len(pins) == 1, ("exactly one init collector pin", pins)
    path = os.fsdecode(pins[0])
    assert path.startswith("/") and os.path.normpath(path) == path, path
    assert os.path.basename(path) == "bingsu-collect", path
    return path


# GATE-FS-HELPER.1: helper calls per publication stage of a release build.
HELPER_STAGES = {"unchanged": ("unchanged",), "publish": ("publish",),
                 "collect": ("unchanged", "collect"), "failure-last-good": ("failure-last-good",),
                 "failure-recover": ("failure-recover",),
                 "command_miss": ("unchanged", "command_miss"), "command_hit": ("unchanged", "command_hit"),
                 "command_not_run": ("unchanged", "command_not_run"),
                 "builtin_probe": ("unchanged", "collect", "builtin_probe"),
                 "builtin_fast": ("unchanged", "collect", "builtin_fast")}


COMMAND_PATH = "/usr/bin"


TEMPLATES = {"plain": "[style]\ntemplate='BASE {char}'\n", "edited": "[style]\ntemplate='EDIT {char}'\n",
             "collect": "[style]\ntemplate='BASE {dir} {git} {char}'\n", "broken": "[broken"}


def path_names(path):
    return len(Path(os.path.realpath(path)).parts) - 1


def nss_reads(libc, user_uid):
    """(nsswitch.conf, /etc/passwd) read calls of the helper's passwd lookup.

    glibc reads nsswitch.conf to EOF and /etc/passwd up to the user's line in
    st_blksize stdio buffers; musl reads only /etc/passwd, in its 1 KiB BUFSIZ
    buffer. An nscd socket would add a different exchange, so it must be absent.
    """
    for socket_path in ("/var/run/nscd/socket", "/run/nscd/socket"):
        assert not os.path.exists(socket_path), "an nscd socket changes the NSS calls; run without nscd"
    data = Path("/etc/passwd").read_bytes()
    at = next(m.end() for m in re.finditer(rb"(?m)^[^:\n]*:[^:\n]*:(\d+):.*$\n?", data)
              if int(m.group(1)) == user_uid)
    if libc == "musl":
        return 0, -(-at // 1024)
    nsswitch, passwd = os.stat("/etc/nsswitch.conf"), os.stat("/etc/passwd")
    return -(-nsswitch.st_size // nsswitch.st_blksize) + 1, -(-at // passwd.st_blksize)


def passwd_seeks(libc, user_uid, data=None):
    """musl's fclose of /etc/passwd seeks back once over the bytes its 1 KiB
    reads took past the user's line; computed from this host's file."""
    if libc != "musl":
        return 0
    data = Path("/etc/passwd").read_bytes() if data is None else data
    at = next(m.end() for m in re.finditer(rb"(?m)^[^:\n]*:[^:\n]*:(\d+):.*$\n?", data)
              if int(m.group(1)) == user_uid)
    return int(min(-(-at // 1024) * 1024, len(data)) > at)


# exec_path's LINKS_MAX: the product follows at most this many hops.
TARGET_LINKS_MAX = 40


def target_links(path):
    """Symlink hops from `path` to its file, each a plain name in the same
    folder ending at a regular file: the only shape the formula counts.
    Anything else (another folder, `.` or `..`, a loop, a broken link, a
    folder, more hops than the product follows) fails here."""
    # A loop ends at the hop cap; `.` and `..` end at a folder, which the
    # last check refuses.
    hops, folder, name = 0, os.path.dirname(path), os.path.basename(path)
    while os.path.islink(os.path.join(folder, name)):
        name = os.readlink(os.path.join(folder, name))
        assert "/" not in name, ("unreviewed target link", path, name)
        hops += 1
        assert hops <= TARGET_LINKS_MAX, ("too many target links", path)
    final = os.path.join(folder, name)
    assert os.path.isfile(final) and not os.path.islink(final), ("target is not a regular file", path, name)
    return hops


# A collect fixture's untraced warm-up: at most this many prompts.
COLLECT_WARMUP_MAX = 10


def warm_until(prompt, ready, *, least, most):
    """Run `prompt` `least` times, then on until `ready()` holds, at most
    `most` times in all; returns how many ran. Past `most` the caller's own
    assertion on the state fails."""
    # 이것을 실패시키는 것: least 전에 멈추는 것, ready를 보지 않고 멈추는 것, most를 넘어 도는 것.
    ran = 0
    while ran < most:
        prompt()
        ran += 1
        if ran >= least and ready():
            break
    return ran


def collect_files(store, runtime):
    """The collection stores and session breakers a collect warm-up leaves."""
    return (list((store / "collections-v1").glob("*/store")),
            list((runtime / "collection-control-v1/sessions").glob("*/breaker")))


def collect_ready(store, runtime):
    """A collect warm-up is done when it left a store and a breaker."""
    stores, breakers = collect_files(store, runtime)
    return bool(stores) and bool(breakers)


# A command stage's untraced warm-up: at most this many prompts.
COMMAND_WARMUP_MAX = 10


def command_ready(store):
    """A command warm-up is done when a command response is stored."""
    return bool(list((store / "collections-v1").glob("*/store/command")))


def stage_warmup(stage, prompt, store, runtime):
    """HelperStageFixture's untraced warm-up for `stage`; returns the prompts run."""
    command, builtin = stage.startswith("command_"), stage.startswith("builtin_")
    if stage == "collect" or builtin:
        warm = warm_until(prompt, lambda: collect_ready(store, runtime), least=3, most=COLLECT_WARMUP_MAX)
        print(f"collect warm-up prompts: {warm}")
    elif command and stage != "command_not_run":
        warm = warm_until(prompt, lambda: command_ready(store), least=2, most=COMMAND_WARMUP_MAX)
        print(f"command warm-up prompts: {warm}")
    else:
        warm = warm_until(prompt, lambda: True, least=2 if command else 1, most=2 if command else 1)
    return warm


def context_store(runtime, config, state):
    path = Path(runtime) / "bingsu" / "contexts-v2" / "config"
    for index, value in enumerate((os.fsencode(config), os.fsencode(state))):
        for i in range(0, len(value), 60):
            path /= value[i:i + 60].hex()
        if index == 0:
            path /= "state"
    return path / "store"


def helper_processes(base):
    """Running refresh helpers of this fixture (cmdline names its roots)."""
    found = []
    for entry in Path("/proc").iterdir():
        try:
            line = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if entry.name.isdigit() and b"__refresh-v1" in line and os.fsencode(str(base)) in line:
            found.append(entry.name)
    return found


def wait_helpers(base, timeout=15):
    import time
    end = time.monotonic() + timeout
    while helper_processes(base):
        assert time.monotonic() < end, ("refresh helper did not exit", helper_processes(base))
        time.sleep(0.05)


def warm_collection_previous(store, prompt, wait):
    """Reach the formula's two-publication state before starting any trace.

    CollectionStore::publish rotates only an existing response. Three warm-up
    prompts need not produce two responses (admission/deadline may defer one).
    Missing previous is normal; unsafe files and other IO errors are not.
    Allow at most three further untraced prompts, then fail preparation clearly.
    """
    import stat

    def size(name):
        info = (store / name).lstat()
        assert stat.S_ISREG(info.st_mode), ("non-regular collection slot", store / name)
        assert info.st_size >= 64, ("short collection slot", store / name)
        return info.st_size

    for attempt in range(4):
        response_bytes = size("response")  # also proves the parent still exists
        try:
            previous_bytes = size("previous")
        except FileNotFoundError:
            # Only an absent leaf is a preparation state. Recheck the parent
            # so removal of the store is not silently treated as first publish.
            assert stat.S_ISDIR(store.lstat().st_mode), ("collection store", store)
            if attempt == 3:
                raise AssertionError(f"warm-up did not rotate response into previous: {store}")
            prompt()
            wait()
        else:
            return {"response_bytes": response_bytes, "previous_bytes": previous_bytes}


def bash_prompt_script(script, pwd, seq, probe=b""):
    import shlex
    return (script + b"\n_bingsu_seq=" + str(seq).encode() + b"\ncd "
            + os.fsencode(shlex.quote(str(pwd))) + b"\n" + probe + CALL)


class HelperStageFixture:
    """Real init, warm-up prompts and one traced prompt for a helper stage.

    The base lives next to the build output, not under /tmp: a group- or
    world-writable ancestor makes every trust walk add ACL and group queries
    the stage formula does not include, so the fixture refuses one.
    """

    def __init__(self, stage, *, template=None, config="plain", entry="cli"):
        import tempfile
        root = real_bin().parent.parent
        self.base = Path(tempfile.mkdtemp(prefix="helper-stage-", dir=root)).resolve()
        for ancestor in [self.base, *self.base.parents]:
            assert not os.stat(ancestor).st_mode & 0o022, ("group/other-writable ancestor", ancestor)
        self.stage = stage
        self.seq = 0
        self.inst = Install(self.base)
        self.env = trusted_env(self.base)
        self.env["HOME"] = str(self.base / "home-t")
        os.mkdir(self.env["HOME"], 0o700)
        self.config = Path(self.env["XDG_CONFIG_HOME"]) / "bingsu"
        self.config.mkdir(parents=True, mode=0o700)
        command = stage.startswith("command_")
        builtin = stage.startswith("builtin_")
        self.put("collect" if stage == "collect" else stage if command or builtin else config, template=template)
        if command:
            self.env["PATH"] = COMMAND_PATH
        self.tools = None
        if builtin:
            self.tools = folder_outside_repository(Path.home(), "bingsu-builtin-tools-")
            # The language's folder first; the shell itself comes from /usr/bin.
            if stage == "builtin_probe":
                self.env["PATH"] = f"{self.tools / 'bin'}:{COMMAND_PATH}"
                self.language = builtin_install(self.tools / "bin", "node")
            else:
                self.env["PATH"] = COMMAND_PATH
                self.language = pyenv_layout(self.tools, self.env)
        # The helper-stage formulas count the `bingsu prompt` front; the helper
        # is the same process under either entry. child_capture traces the
        # `bingsu-prompt` front ("dedicated").
        self.script = self.inst.init("bash", self.env, entry=entry)
        self.collector = init_collector_exe(self.script)
        wait_helpers(self.base)
        self.pwd = self.base
        self.shell_root = None
        if stage == "collect" or builtin:
            # The collector's discovery walks the shell's folder from "/" within
            # its 5 ms stage budget (budget::A_MS), five traced calls a level:
            # next to the build output it is eight names deep on a CI runner,
            # under a shallow folder of the home folder four, as in the local
            # containers. Only collect and builtin stages: command stages scan
            # the shell's folder too and keep the one they were measured with.
            self.shell_root = folder_outside_repository(Path.home(), "bingsu-stage-shell-")
            self.pwd = self.shell_root / "repo"
            self.pwd.mkdir()
            subprocess.run(["git", "init", "-q", str(self.pwd)], check=True, env={"PATH": os.environ["PATH"]})
            (self.pwd / "a").write_text("x")
            if stage == "builtin_fast":
                (self.pwd / ".python-version").write_text("3.12.1\n")
        self.store = context_store(self.env["XDG_RUNTIME_DIR"], os.path.realpath(self.config),
                                   os.path.realpath(Path(self.env["XDG_STATE_HOME"]) / "bingsu"))
        runtime = Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu"

        def prompt_and_wait():
            self.prompt()
            wait_helpers(self.base)
        # The first prompts publish and, for collect, admit and store a response
        # untraced: under strace a cold admission can exceed its 20 ms budget,
        # and on a slow runner so can an untraced one, so collect goes on past
        # its three prompts until the store and the breaker are there.
        # Command stages: the first round publishes the snapshot, the second
        # leaves the unit's response (and the session cgroup parent); a slow
        # runner can defer that round, so a stage that runs its unit goes on
        # until the response is there. Builtin stages warm as collect does:
        # their round needs the stored answer.
        stage_warmup(stage, prompt_and_wait, self.store, runtime)
        assert (self.store / "snapshot").is_file(), "warm-up did not publish"
        # The GC stats every session lock's name (m6-C4a7); the warm-up left
        # this session's, if its config has command units.
        self.session_locks = len(list(runtime.glob("command-*.lock")))
        self.collection = {}
        if stage == "collect" or builtin:
            stores, breakers = collect_files(self.store, runtime)
            assert len(stores) == len(breakers) == 1, ("one store and breaker after warm-up", stores, breakers)
            sizes = warm_collection_previous(stores[0], self.prompt, lambda: wait_helpers(self.base))
            self.collection = {"catalog_bytes": (runtime / ".collections.catalog").stat().st_size,
                               "breaker_bytes": breakers[0].stat().st_size,
                               **sizes,
                               "collector_components": path_names(Path(self.collector).parent),
                               "collector_bytes": Path(self.collector).stat().st_size}
        self.command = {}
        if command or builtin:
            # A unit off the screen never ran: no response, no lookup.
            responses = list((self.store / "collections-v1").glob("*/store/command"))
            assert len(responses) == int(stage != "command_not_run"), ("command responses after warm-up", responses)
            procs = own_cgroup() / "cgroup.procs"
            self.command = {"command_bytes": responses[0].stat().st_size if responses else 0,
                            "catalog_bytes": (Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu/.collections.catalog").stat().st_size
                            if responses else 0,
                            "cgroup_procs_bytes": len(procs.read_bytes()),
                            "cgroup_parent": session_cgroup_parent(
                                self.script, Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu"),
                            "path_names": sum(path_names(f) for f in self.env["PATH"].split(":")) if builtin
                            else path_names(COMMAND_PATH),
                            "target_names": path_names(self.language.parent if stage == "builtin_probe" else
                                                       self.tools / "pyenv" / "shims") if builtin
                            else path_names("/usr/bin"),
                            "target_links": target_links("/usr/bin/true") if stage == "command_miss" else 0,
                            # The repository scan walks the shell's folder by its names
                            # : a canonical folder, so no link is followed.
                            "shell_names": path_names(self.pwd)}
            assert os.path.realpath(self.pwd) == str(self.pwd), ("a canonical shell folder", self.pwd)
            if builtin:
                # One catalog: the collection's (the same file, read once).
                assert self.command.pop("catalog_bytes") == self.collection["catalog_bytes"]
                # The probe's node is no manager's: classify stats each shim
                # home bingsu knows (version_manager::unsupported: asdf,
                # mise's data folder and /usr/local/share/mise, volta, nodenv,
                # goenv; ASDF_DIR and MISE_SHIMS_DIR add one each when set).
                # pyenv's shim folder matches first; python3 is a link to
                # python3.12 inside its bin.
                assert not {"ASDF_DIR", "MISE_SHIMS_DIR"} & set(self.env), "two more shim homes"
                self.command.update(path_folders=len(self.env["PATH"].split(":")),
                                    manager_homes=6 if stage == "builtin_probe" else 0,
                                    bin_links=int(stage == "builtin_fast"))
        if stage == "builtin_probe":
            # A new node (its identity changed): the cached probe no longer
            # matches, so the traced round runs it again.
            stamp = self.language.stat().st_mtime_ns + 1_000_000_000
            os.utime(self.language, ns=(stamp, stamp))
        if stage == "publish":
            self.put("edited")
        elif stage == "failure-last-good":
            (self.store / "snapshot").unlink()
            self.put("broken")
        elif stage == "failure-recover":
            (self.store / "snapshot").chmod(0o644)

    def put(self, name, *, template=None):
        path = self.config / "config.toml"
        pending = path.with_name("config.toml.new")
        pending.write_text(TEMPLATES[name] if template is None else
                           f"[style]\ntemplate='{template}'\n[layout.when.narrow.style]\ntemplate='{template}'\n")
        pending.chmod(0o600)
        pending.replace(path)

    def prompt(self, trace=None, prelude=b"", pass_fds=()):
        f = self.base / "prompt.bash"
        # Each run is a fresh bash: start its prompt counter after the last
        # run's, as one long-lived shell would, so the collection breaker
        # sees a new sequence instead of a replayed one.
        self.seq += 1
        f.write_bytes(bash_prompt_script(self.script, self.pwd, self.seq, prelude))
        strace = ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-s", "4096",
                  "-e", "trace=all",
                  "-o", str(trace)] if trace else []
        r = subprocess.run(strace + SHELL_CMD["bash"] + [str(f)], env=self.env, capture_output=True, timeout=60,
                           pass_fds=pass_fds)
        assert r.returncode == 0, r.stderr
        return r

    def plan(self, libc):
        import platform
        from fsbudget.formula import HelperAxes, HelperPlan, MAX_RW_COUNT
        nsswitch_reads, passwd_reads = nss_reads(libc, os.getuid())
        state = Path(self.env["XDG_STATE_HOME"]) / "bingsu"
        config_bytes = (self.config / "config.toml").stat().st_size
        snapshot = self.store / ("last-good" if self.stage == "failure-last-good" else "snapshot")
        context = 4 + -(-len(os.fsencode(os.path.realpath(self.config))) // 60) + -(-len(os.fsencode(os.path.realpath(state))) // 60)
        return HelperPlan(
            stages=HELPER_STAGES[self.stage],
            ax=HelperAxes(F=1, P=path_names(self.config), L=0, R=3, D=0, M=0, B=[config_bytes]),
            runtime_components=path_names(Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu"),
            context_components=context,
            snapshot_bytes=snapshot.stat().st_size, marker_bytes=208, buf=MAX_RW_COUNT,
            state_components=path_names(state), exe_link_components=path_names(self.inst.dir),
            exe_components=path_names(real_bin().parent),
            nsswitch_reads=nsswitch_reads, passwd_reads=passwd_reads, libc=libc,
            passwd_seeks=passwd_seeks(libc, os.getuid()),
            arch=platform.machine(), session_locks=self.session_locks, **self.collection, **self.command)


def folder_outside_repository(parent, prefix):
    """A new folder under `parent`, outside every git repository and with no
    ancestor writable by group or others. A builtin stage's language tools
    live there: the round leaves PATH folders inside the shell's repository,
    or any folder above it holding `.git`, out of its lookup,
    and a fixture base next to the build output sits in the source checkout,
    as on a CI runner. The collect and builtin stages' shell folder too, to
    keep the collector's discovery shallow."""
    import tempfile
    parent = Path(parent).resolve()
    # 이것을 실패시키는 것: 도구 폴더를 fixture 기반(저장소 checkout 안)에 두는 것(CI 러너에서 PATH가 비고 내장
    # 회차가 아무것도 결정하지 않음), 저장소 안이거나 남이 쓸 수 있는 부모를 받는 것.
    for folder in [parent, *parent.parents]:
        assert not os.path.lexists(folder / ".git"), ("a tools folder inside a git repository", folder)
        assert not os.stat(folder).st_mode & 0o022, ("group/other-writable ancestor of the tools", folder)
    folder = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    folder.chmod(0o755)
    return folder


def builtin_install(folder, name):
    """The version stub (crates/bingsu-bench) copied under a language's
    command name: a probe never runs a `#!` script."""
    stub = Path(os.environ.get("BINGSU_VERSION_STUB", real_bin().with_name("version-stub")))
    assert stub.is_file(), f"build it first: cargo build -p bingsu-bench --bin version-stub ({stub})"
    folder.mkdir(parents=True, mode=0o755, exist_ok=True)
    target = folder / name
    target.write_bytes(stub.read_bytes())
    target.chmod(0o755)
    return target


def pyenv_layout(tools, env):
    """pyenv as it installs: its shim folder first on PATH (a `#!` script),
    3.12.1 installed with python3 a link to python3.12, and the repository's
    `.python-version` selecting it."""
    root = tools / "pyenv"
    shim = root / "shims" / "python3"
    shim.parent.mkdir(parents=True, mode=0o755)
    shim.write_text("#!/usr/bin/env bash\nexec pyenv exec python3 \"$@\"\n")
    shim.chmod(0o755)
    real = builtin_install(root / "versions" / "3.12.1" / "bin", "python3.12")
    (real.parent / "python3").symlink_to("python3.12")
    for folder in (root, root / "versions", root / "versions" / "3.12.1"):
        folder.chmod(0o755)
    env["PYENV_ROOT"] = str(root)
    env["PATH"] = f"{shim.parent}:{env['PATH']}"
    return real


def own_cgroup():
    """The cgroup v2 folder of this process (the helper's, as its descendant)."""
    line = next(l for l in Path("/proc/self/cgroup").read_text().splitlines() if l.startswith("0::"))
    return Path("/sys/fs/cgroup" + line[3:].rstrip("/"))


def session_cgroup_parent(script, runtime, own=None):
    """Whether the helper takes the atomic path, decided from the host and
    never from the traced calls. A cgroup folder this process may write to
    (not read-only, not someone else's) delegates: the warm-up must then have
    made this session's own parent (its exact name, owned by this user), or
    the fixture fails; the privileged cell must delegate. Otherwise the round
    is best effort."""
    own = own_cgroup() if own is None else own
    # init writes the session as a shell word (quoted or not) in the hooks.
    session = re.search(rb"_bingsu_session:=['\"]?([0-9a-f]{32})", script)[1]
    root = os.stat(runtime)
    key = root.st_dev.to_bytes(8, "little") + root.st_ino.to_bytes(8, "little") + b"\0" + session
    parent = own / f"bingsu-cmd-{hashlib.sha256(key).digest()[:16].hex()}"
    delegated = os.access(own, os.W_OK) and not os.statvfs(own).f_flag & os.ST_RDONLY
    # 이것을 실패시키는 것: 특권 셀에서 위임을 요구하지 않는 것, 같은 uid의 아무 bingsu-cmd-* 폴더를 이 세션의 부모로
    # 받는 것, 위임된 셀에서 부모가 없을 때 best effort로 셈하는 것(데움 실패가 원자 경로 비용을 지움).
    assert delegated or os.environ.get("BINGSU_CGROUP_CELL") != "priv", ("the privileged cell delegates", own)
    if delegated:
        assert (parent.is_dir() and not parent.is_symlink()
                and parent.stat().st_uid == os.getuid()), ("the warm-up's session parent", parent)
    return delegated
