#!/usr/bin/env python3
"""Does interactive bash expand PS0 in POSIX mode with promptvars off/on?
Prints one line per state: 'posix=1 promptvars=0 ps0=expanded|literal|absent'.

PS0 is printed right before the command's own output, with no newline in
between, so the marker is typed as d""one and matched as `done` (the echoed
input never contains the marker)."""
import pexpect

for pv in ("-u", "-s"):
    p = pexpect.spawn("bash", ["--noprofile", "--norc", "-i"], env={"PATH": "/usr/bin:/bin"}, timeout=10)
    p.sendline(f"set -o posix; shopt {pv} promptvars; PS0='P0[$((6*7))]'; PS1='$ '")
    p.sendline('echo d""one')
    p.expect(r"done\r")
    out = p.before.decode()
    state = "expanded" if "P0[42]" in out else ("literal" if "P0[$((6*7))]" in out else "absent")
    print(f"posix=1 promptvars={1 if pv == '-s' else 0} ps0={state}")
    p.sendline("exit")
    p.expect(pexpect.EOF)
