"""Compare measured counts with expected counts per role and per kind.
A surplus in one kind is never offset by slack in another (spec 8)."""


def check(measured, expected, mode: str, gated_roles) -> list[str]:
    bad = []
    for role in gated_roles:
        got, want = measured.get(role, {}), expected.get(role, {})
        for k in sorted(set(got) | set(want)):
            g, w = got.get(k, 0), want.get(k, 0)
            if (mode == "exact" and g != w) or (mode == "le" and g > w):
                bad.append(f"{role}.{k}: measured {g}, formula {w} ({mode})")
    return bad
