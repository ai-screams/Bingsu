#!/usr/bin/env python3
"""Build host-only audit fixtures before running compiler-free shell tests."""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def interposer(tmp_path):
    # Resolve every observed entry statically. No dlsym dependency in the worker.
    names = ("posix_spawn", "posix_spawnp", "execve", "execv", "execvp", "execvP",
             "execl", "execlp", "execle", "fork", "vfork", "system", "popen")
    source = '#include <unistd.h>\n#include <spawn.h>\n#include <stdlib.h>\n#include <stdio.h>\n'
    source += 'static int refused(void) { _exit(86); }\n'
    for i, name in enumerate(names):
        source += (f'__attribute__((used,section("__DATA,__interpose"))) static const '
                   f'struct {{ const void *replacement; const void *original; }} pair{i} '
                   f'= {{ (const void *)refused, (const void *){name} }};\n')
    source += '__attribute__((constructor)) static void clean(void) { unsetenv("DYLD_INSERT_LIBRARIES");'
    source += ' }\n'
    c = tmp_path / "canary.c"
    dylib = c.with_suffix(".dylib")
    c.write_text(source)
    subprocess.run(["cc", "-dynamiclib", "-Wall", "-Werror", "-Wno-deprecated-declarations", str(c), "-o", str(dylib)], check=True, capture_output=True)
    return dylib


def startup_binary():
    result = subprocess.run(["cargo", "test", "-j", "2", "-p", "bingsu-collect", "--test", "startup",
                             "--no-run", "--message-format=json"], cwd=ROOT, check=True, capture_output=True, text=True)
    artifacts = [json.loads(line) for line in result.stdout.splitlines()]
    startup, = [a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact"
                and a["target"]["name"] == "startup" and a.get("executable")]
    return startup


def main():
    directory = ROOT / "target/collector-audit"
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {"startup": startup_binary(),
                "worker": str(ROOT / "target/release/bingsu-collect"),
                "front": str(ROOT / "target/release/bingsu")}
    if sys.platform == "darwin":
        manifest["canary"] = str(interposer(directory))
        source = directory / "mutation.c"
        source.write_text('''#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) { usleep(250000); _exit(0); }
    return waitpid(child, 0, 0) == child ? 0 : 1;
}
''')
        mutant = directory / "mutation"
        subprocess.run(["cc", str(source), "-o", str(mutant)], check=True)
        manifest["mutant"] = str(mutant)
    for value in manifest.values():
        if not pathlib.Path(value).is_file():
            raise SystemExit("build the release sibling pair before preparing the audit")
    (directory / "fixture.json").write_text(json.dumps(manifest))


if __name__ == "__main__":
    main()
