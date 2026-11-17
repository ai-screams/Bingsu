"""The counting engine under every formula: the call table `_add` counts with,
and the context that selects a libc and platform table for one formula call.

Single-threaded by design: the selected table is one module variable, so two
formula calls must not run at the same time."""
from contextlib import contextmanager
from .tables import MUSL_PRIMITIVES, PRIMITIVES, STARTUP_PRIMITIVES


_LIBC = {"gnu": {}, "musl": MUSL_PRIMITIVES}


_primitives = PRIMITIVES


@contextmanager
def _primitives_for(libc: str, arch: str):
    """Count with this libc's and platform's table inside the `with`, and put
    the previous table back after, also when the body raises."""
    global _primitives
    previous = _primitives
    _primitives = {**PRIMITIVES, **_LIBC[libc], **STARTUP_PRIMITIVES[arch, libc]}
    try:
        yield
    finally:
        _primitives = previous


def _add(total: dict, name: str, times: int = 1) -> None:
    if times < 0:
        raise ValueError(name)
    for kind, n in _primitives[name].items():
        total[kind] = total.get(kind, 0) + n * times
