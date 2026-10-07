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
