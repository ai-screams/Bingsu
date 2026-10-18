"""Real CLI fixtures shared by N7 shell tests and measurements."""
import os
import pathlib
import shlex
import struct
import subprocess
import time

from conftest import COLD_INIT_NOTICE, real_bin, trusted_env


class SnapshotSession:
    def __init__(self, base, tag="n7", config=None, state=None, runtime=None):
        self.base = pathlib.Path(base).resolve()
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.env = trusted_env(self.base, tag)
        for key, value in (("XDG_CONFIG_HOME", config), ("XDG_STATE_HOME", state),
                           ("XDG_RUNTIME_DIR", runtime)):
            if value is not None:
                self.env[key] = str(value)
        self.config = pathlib.Path(self.env["XDG_CONFIG_HOME"]) / "bingsu"
        self.config.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.words = []

    def run(self, *args, timeout=5):
        return subprocess.run([str(real_bin()), *args], cwd=self.base, env=self.env,
                              capture_output=True, timeout=timeout)

    def put(self, text, name="config.toml"):
        path = self.config / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Atomic rename is intentional: it also observes identical-byte replacement.
        pending = path.with_name(path.name + ".n7")
        pending.write_text(text)
        pending.chmod(0o600)
        pending.replace(path)
        return path

    def init(self):
        result = self.run("init", "bash")
        assert result.returncode == 0, result.stderr
        assert result.stderr.replace(COLD_INIT_NOTICE, b"") == b"", result.stderr
        # Read the values actually pinned by init; no reimplementation of root pins.
        script = result.stdout + b"\nprintf '%s\\0' \"$BINGSU_ROOTS\"\n"
        output = subprocess.run(["bash", "--noprofile", "--norc"], input=script,
                                env=self.env, cwd=self.base, capture_output=True, timeout=5)
        assert output.returncode == 0 and output.stderr == b"", output.stderr
        self.env["BINGSU_ROOTS"] = output.stdout.rstrip(b"\0").decode()
        # Init embeds quoted one-word roots in the hook. Inspect shell tokens,
        # never run the hook with reconstructed paths.
        for line in result.stdout.decode().splitlines():
            if "--runtime-root=" in line and "--config-root=" in line:
                self.words = [word for word in shlex.split(line)
                              if word.startswith(("--runtime-root=", "--runtime-groups=",
                                                  "--config-root=", "--config-root-written=",
                                                  "--state-root=", "--log-root=", "--home="))
                              or word == "--config-root-shape-only"]
                break
        assert self.words, "init did not pin prompt roots"
        return result

    def prompt_args(self):
        return ["prompt", "--ctx", "1", "--record", "B1", "--shell", "bash",
                "--width", "120", "--pwd", str(self.base), "--log-level=off", *self.words]

    def prompt(self):
        result = self.run(*self.prompt_args(), timeout=2)
        assert result.returncode == 0 and result.stderr == b"", result.stderr
        assert result.stdout.startswith(b"B1\x1f") and result.stdout.endswith(b"\x1e"), result.stdout
        return result.stdout

    def store(self):
        config = os.fsencode(str(self.config.resolve()))
        state = os.fsencode(str((pathlib.Path(self.env["XDG_STATE_HOME"]) / "bingsu").resolve()))
        path = pathlib.Path(self.env["XDG_RUNTIME_DIR"]) / "bingsu" / "contexts-v2" / "config"
        for index, value in enumerate((config, state)):
            for i in range(0, len(value), 60):
                path /= value[i:i + 60].hex()
            if index == 0:
                path /= "state"
        return path / "store"

    def identity(self):
        wire = (self.store() / "snapshot").read_bytes()
        assert wire[:8] == b"BNGSNP02"
        return wire[88:120], struct.unpack_from("<Q", wire, 16)[0]

    def await_text(self, text, timeout=4):
        end = time.monotonic() + timeout
        records = []
        while time.monotonic() < end:
            record = self.prompt()
            records.append(record)
            if text.encode() in record:
                return record
            time.sleep(0.02)
        raise AssertionError(("completed refresh never reached prompt", text, records[-3:]))

    def wait_quiet(self):
        # Helpers have an independent two-second lifetime; cleanup must not race them.
        time.sleep(2.1)


def require_native_boot():
    """Only the observed macOS sandbox denial is a skip; other failures remain failures."""
    import sys
    if sys.platform == "darwin":
        probe = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], capture_output=True)
        if probe.returncode and b"Operation not permitted" in probe.stderr:
            import pytest
            pytest.skip("kern.bootsessionuuid denied by sandbox; run native snapshot integration outside it")
