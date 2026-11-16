"""Front formulas: the synthetic front and the front attempts."""
from dataclasses import dataclass
from typing import Literal
from ..strace_parse import Trace
from .common import ceil_div


def front_expected(C: int, section_bytes: int, session_bytes: int, buf: int) -> dict[str, int]:
    return {
        "openat": C + 3,
        "fstat": C + 3,
        "read": ceil_div(section_bytes, buf) + 1 + 1 + ceil_div(session_bytes, buf),
    }


@dataclass(frozen=True)
class FrontAttempt:
    copy: Literal["current", "last_good"]
    header_read: bool
    prefix_read: bool
    # Bytes read after the prefix, parsed or dropped; see front_body_bytes.
    body_bytes_read: int
    checksum_checked: bool


def front_body_bytes(front: int, body: int, variant_end: int, chunk: int) -> int:
    """Bytes the front reads of a compiled section of `body` bytes.

    Reads are whole chunks from the section's start until INDEX is complete at
    `front`, which names the selected variant; they then stop at `variant_end`.
    Bytes before the variant are read and dropped, so they count (seek is not in
    the filter), and the last read before the plan can pass the variant.
    """
    # 이것을 실패시키는 것: 버린 바이트를 빼거나 구획 끝 너머(TrustMetadata)까지 세는 것.
    if not 0 < front <= variant_end <= body or chunk <= 0:
        raise ValueError("invalid front layout")
    return max(min(ceil_div(front, chunk) * chunk, body), variant_end)


def front_attempts_expected(C: int, attempts: list[FrontAttempt], chunk: int,
                            marker: int = 208) -> dict[str, int]:
    """Linux front, excluding loader and the separate collection increment.

    C is the runtime/context directory walk INCLUDING '/'. Three files are
    prefetched regardless of selection. ClockPins prepares nine descriptors
    (one O_PATH root), reads the 37-byte boot ID and EOF, and three links.
    O_PATH ACL queries each require the counted /proc/self/fd fallback.
    The immutable snapshot/marker reads have no EOF probe.
    """
    # 이것을 실패시키는 것: 음수 축·0 청크 또는 고정 marker 208 변경을 허용하는 것.
    if C < 1 or chunk <= 0 or marker != 208:
        raise ValueError("invalid front axes")
    copies = [a.copy for a in attempts]
    # 이것을 실패시키는 것: last-good 선택 뒤 현재 사본 재읽기를 공식에 흡수하는 것.
    if copies not in (["current"], ["current", "last_good"]):
        raise ValueError("invalid front attempt order")
    for a in attempts:
        # 이것을 실패시키는 것: prefix 없이 본문을 읽거나 checksum 전에 완료로 세는 것.
        if (not 0 <= a.body_bytes_read <= 16 * 1024 * 1024
                or a.prefix_read and not a.header_read
                or a.body_bytes_read and not a.prefix_read
                or a.checksum_checked and not a.prefix_read):
            raise ValueError("invalid front attempt")
    return {"openat": C + 3 + 9, "fstat": C + 3 + 9,
            "fstatfs": C + 3 + 9, "fgetxattr": C + 3 + 9,
            "getxattr": C + 1, "readlinkat": 3,
            "read": sum(int(a.header_read) + int(a.prefix_read)
                        + ceil_div(a.body_bytes_read, chunk) for a in attempts) + 1 + 2}


def front_read_bytes(trace: "Trace", paths: list[str]) -> dict[str, int]:
    """Returned bytes, never requested bytes; caller supplies one front PID.

    Kernel -y names identify descriptors across close/reuse. A malformed trace
    or unmeasurable read is a failure, not zero. No helper data is admissible.
    """
    import re
    from ..strace_parse import scan
    # 이것을 실패시키는 것: 파싱 실패 또는 helper 읽기를 앞단 바이트로 수용하는 것.
    if trace.errors or len({c.pid for c in trace}) > 1:
        raise ValueError("front byte accounting needs a valid single-PID trace")
    result = dict.fromkeys(paths, 0)
    for c in trace:
        args = scan(c.args)[0]
        fd = re.fullmatch(r"\d+<(/[^<>]*)>", args[0]) if args else None
        if not fd or fd[1] not in result:
            continue
        # 이것을 실패시키는 것: readv/pread를 사용해 앞단 read 바이트 계수를 우회하는 것.
        if c.name in {"readv", "preadv", "preadv2", "pread64"}:
            raise ValueError("unexpected front read primitive")
        if c.name != "read":
            continue
        # 이것을 실패시키는 것: 실패한 read를 0으로 버리거나 요청 길이를 반환 바이트로 세는 것.
        if len(args) != 3 or not c.ret.isdecimal() or not args[2].isdecimal() or int(c.ret) > int(args[2]):
            raise ValueError("unmeasurable front read")
        result[fd[1]] += int(c.ret)
    return result
