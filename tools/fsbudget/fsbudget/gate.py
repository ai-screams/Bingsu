"""Compare measured counts with expected counts per role and per kind.
A surplus in one kind is never offset by slack in another (spec 8). A gated
role with no measured calls at all is a violation in either mode: its calls
went to another role or nowhere, and `le` would otherwise pass it empty.
Calls of a task attribution could not place (role `unresolved`) are a
violation too, whatever roles the caller gates."""

MODES = ("exact", "le")
# The supervisor's read-only absence probe of a stage name (musl adds O_LARGEFILE).
ABSENCE_PROBE = {"O_RDONLY", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"}
OPEN_ALIASES = {"open", "creat", "openat", "openat2"}


def open_names(name, args, ret=""):
    """Last path components a successful open alias names: (annotation, argument).

    The annotation is the returned fd's -y path (absolute); the argument is
    the path as passed (open and creat take it first), relative to its dirfd
    otherwise, so only basenames compare. Either is None when absent or
    unparsable, such as strace's truncated form `"..."...`."""
    import ast
    import posixpath
    import re
    opened = re.fullmatch(r"\d+<(/[^<>]*)>", ret)
    raw = args[0] if name in {"open", "creat"} else args[1] if len(args) > 1 else ""
    try:
        argument = posixpath.basename(ast.literal_eval(raw))
    except (SyntaxError, ValueError):
        argument = None
    return (posixpath.basename(opened[1]) if opened else None), argument


def check(measured, expected, mode: str, gated_roles) -> list[str]:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, not {mode!r}")
    bad = []
    if measured.get("unresolved"):
        bad.append(f"unresolved: {measured['unresolved']} (calls of a task with no known role)")
    for role in gated_roles:
        if not measured.get(role):
            bad.append(f"{role}: no calls measured")
            continue
        got, want = measured[role], expected.get(role, {})
        for k in sorted(set(got) | set(want)):
            g, w = got.get(k, 0), want.get(k, 0)
            if (mode == "exact" and g != w) or (mode == "le" and g > w):
                bad.append(f"{role}.{k}: measured {g}, formula {w} ({mode})")
    return bad


class _PublicationWatch:
    """The collection supervisor's publication of its response, as both the
    collect and the builtin checks judge it: a rename of `.response.stage`
    to `response` counts only if every supervisor call before it succeeded,
    the one tolerated failure being the absence check of the stage and
    legacy request names (ENOENT) before the stage is created, and every
    open names its file."""

    def __init__(self):
        self.published = False
        self.staged = False
        self.failed = []  # supervisor calls that failed before the installing rename
        self.unverified = []
        self.unresolved = []  # supervisor opens whose file could not be named (fail closed)
        self.disagreeing = []  # supervisor opens whose annotation and argument disagree on the stage

    def observe(self, c, args):
        if self.published:
            return
        # 이것을 실패시키는 것: 단계 이름 부재 확인의 허용을 지우는 것(정상 발행이 실패), 만든 뒤의
        # 부재까지 허용하는 것, 쓰기·생성 flags의 실패한 open을 부재 확인으로 보는 것, 실패한 감독 호출을
        # 보지 않는 것.
        if c.ret.startswith("-1") and not (
                not self.staged and c.ret.startswith("-1 ENOENT")
                and args[1:2] in (['".response.stage"'], ['".stage-request"'])
                and set("".join(args[2:3]).split("|")) - {"O_LARGEFILE"} == ABSENCE_PROBE):
            self.failed.append(c)
        # 이것을 실패시키는 것: 생성을 openat으로만 추적하는 것(open·creat·openat2 생성 뒤 부재가 예외를 받음),
        # 이름을 알 수 없는 open을 생성 아님으로 넘기는 것(잘린 경로 뒤 부재가 예외를 받음).
        if c.name in OPEN_ALIASES and not c.ret.startswith("-1"):
            annotation, argument = open_names(c.name, args, c.ret)
            if annotation is None and argument is None:
                self.unresolved.append(c)
            # Only the stage name is compared: /proc/self legitimately
            # resolves to /proc/<pid>, so other names may differ.
            # 이것을 실패시키는 것: 단계 이름을 가리키는 인자와 다른 fd 주석을 받아들이는 것(생성이 숨겨짐).
            if annotation and argument and (annotation == ".response.stage") != (argument == ".response.stage"):
                self.disagreeing.append(c)
            if (annotation or argument) == ".response.stage":
                self.staged = True  # the stage's creation
        if (c.name == "renameat" and c.ret == "0"
                and len(args) == 4 and args[1] == '".response.stage"' and args[3] == '"response"'):
            self.published = True
            self.unverified = self.failed[:1]

    def errors(self, name):
        out = [f"{name}: supervisor open annotation disagrees with its path: {c.name}({c.args}) = {c.ret}"
               for c in self.disagreeing]
        out += [f"{name}: supervisor open of an unresolved path: {c.name}({c.args}) = {c.ret}" for c in self.unresolved]
        out += [f"{name}: publication after a failed supervisor call: {c.name}({c.args}) = {c.ret}"
                for c in self.unverified]
        return out


def check_collect(attribution, expected, *, deadline=None, evidence=None):
    """Separate concurrent collect streams; never subtract prefix from totals.

    `expected` is the publication formula. `deadline`, given for an exit-75
    attempt, is the formula without publication. It applies only when the
    supervisor renamed no response: a collector that sent a verified update
    and then hit its own stage deadline leaves a Deadline partial, which the
    supervisor stores after reaping exit 75 (spec message row: the results so
    far; S-17). That attempt is held to the publication formula, as exit 0 is.
    A rename counts as publication only if every supervisor call before it
    succeeded; the one tolerated failure is the absence check of the stage
    and legacy request names (ENOENT) before the stage is created.

    Attribution retains counted helper events in syscall-entry order, including
    pre-exec child setup. The two successful helper thread creations identify
    watchdog and supervisor; a changed topology fails closed. Main-thread tail
    starts after the successful snapshot.lock unlock (LockedStore::drop).
    Every attempt must reach that boundary, including exit 75. The prefix
    is always exact; only the supervisor and finish/GC tails use upper bounds.
    """
    from collections import Counter
    from .classify import split_args

    calls = attribution.helper_calls
    mains = [c.pid for c, kind in calls if kind == "exec" and c.ret == "0"]
    if len(mains) != 1:
        return ["collect: expected one helper exec"], False
    main = mains[0]
    threads = [int(c.ret.split()[0]) for c, kind in calls
               if kind == "thread" and c.pid == main and c.ret.split()[0].isdigit()]
    if len(threads) != 2:
        return ["collect: expected watchdog and supervisor threads"], False
    supervisor = threads[1]
    measured = {phase: Counter() for phase in expected}
    unlocked = False
    watch = _PublicationWatch()
    for c, kind in calls:
        phase = ("supervisor" if c.pid == supervisor else
                 "finish_gc" if c.pid == main and unlocked else "prefix")
        measured[phase][kind] += 1
        args = split_args(c.args)
        if (c.pid == main and c.name == "flock" and c.ret == "0"
                and len(args) == 2 and args[0].endswith("/snapshot.lock>") and args[1] == "LOCK_UN"):
            if unlocked:
                return ["collect: duplicate snapshot unlock boundary"], False
            unlocked = True
        if c.pid == supervisor:
            watch.observe(c, args)
    # 이것을 실패시키는 것: 발행 여부와 무관하게 exit 75에 마감 공식을 쓰는 것(발행한 마감 회차가 실패),
    # exit 75에 늘 발행 공식을 쓰는 것(발행 없는 마감 회차의 감독 tail 초과를 놓침).
    published = watch.published
    if deadline is not None and not published:
        expected = deadline
    if evidence is not None:
        evidence.update(phase_counts=measured, phase_expected=expected,
                        prefix_complete=unlocked, published=published)
    errors = []
    if not unlocked:
        errors.append("collect: missing snapshot unlock boundary")
    errors += watch.errors("collect")
    # Independent phase and kind limits prevent tail slack hiding a prefix
    # regression, and GC slack hiding an extra supervisor call on exit 75.
    for phase, want in expected.items():
        mode = "exact" if phase == "prefix" else "le"
        got = measured[phase]
        if phase == "prefix" and not got:
            errors.append("prefix: no calls measured")
        for kind in sorted(set(got) | set(want)):
            g, w = got.get(kind, 0), want.get(kind, 0)
            if (mode == "exact" and g != w) or (mode == "le" and g > w):
                errors.append(f"{phase}.{kind}: measured {g}, formula {w} ({mode})")
    return errors, published


def check_command(attribution, expected, *, evidence=None):
    """command_miss: the helper's calls through the command response's
    install (and, on the atomic path, the unit cgroup reclaim after it) are
    exact; from the next clock observation (its boot_id open) on they are the
    GC's, held to an upper bound. The round must install its response.
    Calls of the supervisor, relay and target are other roles (Q7)."""
    from collections import Counter
    from .classify import split_args

    measured = {phase: Counter() for phase in expected}
    installed, gc, errors = False, False, []
    for c, kind in attribution.helper_calls:
        args = split_args(c.args)
        # 이것을 실패시키는 것: 경계를 설치 전 시계(boot_id)로 잡는 것(앞부분이 꼬리로 새어 정확 검사를 빠져나감),
        # 설치 뒤 첫 시계를 앞부분에 넣는 것(GC 호출이 정확 검사에 들어가 회차마다 실패).
        if (installed and not gc and c.name in OPEN_ALIASES
                and '"/proc/sys/kernel/random/boot_id"' in args[:2]):
            gc = True
        measured["gc" if gc else "prefix"][kind] += 1
        if (c.name in {"renameat", "renameat2"} and c.ret == "0"
                and len(args) >= 4 and args[1] == '".command.stage"' and args[3] == '"command"'):
            installed = True
    if evidence is not None:
        evidence.update(phase_counts=measured, phase_expected=expected, installed=installed)
    # 이것을 실패시키는 것: 설치 성공을 요구하지 않는 것(rename이 실패하고 GC도 없는 미스가 정확 앞부분만으로 통과).
    if not installed:
        errors.append("command: the round installed no command response")
    for phase, want in expected.items():
        mode = "exact" if phase == "prefix" else "le"
        got = measured[phase]
        for kind in sorted(set(got) | set(want)):
            g, w = got.get(kind, 0), want.get(kind, 0)
            if (mode == "exact" and g != w) or (mode == "le" and g > w):
                errors.append(f"{phase}.{kind}: measured {g}, formula {w} ({mode})")
    return errors


def check_builtin(attribution, expected, stage, *, deadline=None, evidence=None):
    """A builtin language round (helper_builtin_expected). The helper's main
    thread is `prefix` until the collection's snapshot unlock, then
    `builtin` until the GC's first clock: after the command response's
    install (probe), or after the breaker's save (fast, which installs
    nothing). Both markers must succeed. The collection supervisor thread is
    `supervisor`; the collector's and supervisor's pre-exec setup is
    `prefix`. `prefix` and `builtin` are exact, `supervisor` and `gc` upper
    bounds.

    Which formula applies is read from the trace, never from the collector's
    exit: a round whose supervisor published the collection's response (by
    check_collect's rules: no failed call before the rename but the stage's
    absence probes) decides its language and is held to `expected`, even
    after a deadline (a verified partial). Without that publication
    (a deadline with nothing verified) `deadline` applies: the same exact
    prefix and the supervisor's clock-only bound; the rest of the main
    thread is bounded by the full round's builtin and gc together, unless
    the round installed a command response, which is a decision: then its
    builtin part is exact again. Returns (errors, published, installed)."""
    from collections import Counter
    from .classify import split_args

    calls = attribution.helper_calls
    mains = [c.pid for c, kind in calls if kind == "exec" and c.ret == "0"]
    if len(mains) != 1:
        return ["builtin: expected one helper exec"], False, False
    main = mains[0]
    threads = [int(c.ret.split()[0]) for c, kind in calls
               if kind == "thread" and c.pid == main and c.ret.split()[0].isdigit()]
    if len(threads) != 2:
        return ["builtin: expected watchdog and supervisor threads"], False, False
    supervisor = threads[1]
    measured = {phase: Counter() for phase in ("prefix", "supervisor", "builtin", "gc")}
    phase, saved, installed = "prefix", False, False
    watch = _PublicationWatch()
    for c, kind in calls:
        args = split_args(c.args)
        renamed = c.name in {"renameat", "renameat2"} and c.ret == "0" and len(args) >= 4
        if c.pid == supervisor:
            measured["supervisor"][kind] += 1
            watch.observe(c, args)
            continue
        if c.pid != main:
            measured["prefix"][kind] += 1
            continue
        # 이것을 실패시키는 것: GC 경계를 첫 시계로 잡는 것(breaker 마무리의 시계에서 끊겨 결정이 GC 상한으로 샘),
        # probe에서 설치 전 시계를 경계로 보는 것, fast에서 breaker 저장 전 시계를 경계로 보는 것.
        if (phase == "builtin" and c.name in OPEN_ALIASES and '"/proc/sys/kernel/random/boot_id"' in args[:2]
                and (installed if stage == "builtin_probe" else saved)):
            phase = "gc"
        measured[phase][kind] += 1
        if (phase == "prefix" and c.name == "flock" and c.ret == "0" and len(args) == 2
                and args[0].endswith("/snapshot.lock>") and args[1] == "LOCK_UN"):
            phase = "builtin"
        elif phase == "builtin" and renamed:
            saved |= args[1] == '".breaker.stage"' and args[3] == '"breaker"'
            installed |= saved and args[1] == '".command.stage"' and args[3] == '"command"'
    # 이것을 실패시키는 것: rename 성공만으로 발행을 인정하는 것(마지막 확인이 실패한 단계 파일의 rename이 발행이 됨).
    published = watch.published
    errors = watch.errors("builtin")
    if published:
        # 이것을 실패시키는 것: breaker 저장의 성공을 요구하지 않는 것, probe 설치의 성공을 요구하지 않는 것(실패한
        # rename도 같은 종류로 세져, GC가 없으면 정확 개수가 맞음).
        if not saved:
            errors.append("builtin: the breaker was not saved after the unlock")
        # A fast round's install is a counted rename its formula has not.
        if stage == "builtin_probe" and not installed:
            errors.append("builtin: the probe round installed no command response")
        want = {**expected}
        modes = {"prefix": "exact", "supervisor": "le", "builtin": "exact", "gc": "le"}
    else:
        if deadline is None:
            return errors + ["builtin: the collection published no response and no deadline formula was given"], \
                False, installed
        # 이것을 실패시키는 것: 발행 없는 회차의 command 설치를 무시하는 것(결정한 회차의 내장 구간을 GC 여유가
        # 덮음).
        if installed:
            want = {"prefix": deadline["prefix"], "supervisor": deadline["supervisor"],
                    "builtin": expected["builtin"], "gc": expected["gc"]}
            modes = {"prefix": "exact", "supervisor": "le", "builtin": "exact", "gc": "le"}
        else:
            measured["tail"] = measured.pop("builtin") + measured.pop("gc")
            want = {**deadline}
            modes = {"prefix": "exact", "supervisor": "le", "tail": "le"}
    if evidence is not None:
        evidence.update(phase_counts=measured, phase_expected=want, installed=installed, saved=saved,
                        published=published)
    for phase, mode in modes.items():
        got, w = measured[phase], want[phase]
        for kind in sorted(set(got) | set(w)):
            g, n = got.get(kind, 0), w.get(kind, 0)
            if (mode == "exact" and g != n) or (mode == "le" and g > n):
                errors.append(f"{phase}.{kind}: measured {g}, formula {n} ({mode})")
    return errors, published, installed
