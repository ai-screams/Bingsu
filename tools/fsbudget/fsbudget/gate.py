"""Compare measured counts with expected counts per role and per kind.
A surplus in one kind is never offset by slack in another (spec 8). A gated
role with no measured calls at all is a violation in either mode: its calls
went to another role or nowhere, and `le` would otherwise pass it empty.
Calls of a task attribution could not place (role `unresolved`) are a
violation too, whatever roles the caller gates."""

MODES = ("exact", "le")


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


def check_collect(attribution, expected, *, deadline=False, evidence=None):
    """Separate concurrent collect streams; never subtract prefix from totals.

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
    published = False
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
        if (c.pid == supervisor and c.name == "renameat" and c.ret == "0"
                and len(args) == 4 and args[1] == '".response.stage"' and args[3] == '"response"'):
            published = True
    if evidence is not None:
        evidence.update(phase_counts=measured, phase_expected=expected,
                        prefix_complete=unlocked, published=published)
    errors = []
    if not unlocked:
        errors.append("collect: missing snapshot unlock boundary")
    if deadline and published:
        errors.append("collect: deadline attempt published")
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
