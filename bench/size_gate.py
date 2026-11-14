#!/usr/bin/env python3
"""Pull request gate verdicts for full prompt time and stripped binary size.

Pure judgement over D1 `Paired` rows and `git-product.py --prepare` size maps. The
p50 and p95 ratio limits and the two size caps are inputs (1.03, 1.10; the
first release: 2,500,000 bytes for front + collector, 7,000,000 bytes for the
three shipped files together); a missing one leaves its verdict BLOCKED, never
FAIL. The CLI exits 0 unless --enforce is given, and then exits 1 only on FAIL;
BLOCKED stays visible in the report and summary but passes. Absolute time is
recorded only; it is never a reason to fail. The release size (each of the three
shipped files stripped, and their sum) is recorded with its change from the base.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import TypedDict

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol

MIN_PAIRS = 200
# Spec section 1303: warm prompt median target, recorded next to the verdict only.
ABSOLUTE_TARGET_MS = 10.0
SIZE_KEYS = ("front", "collector", "combined")
PENDING = "not set"
# Cases the gate records without judging (--record-only): the command time
# fixtures (M6 C4b-3). A base that reads no command response makes their ratio
# the whole added cost, and their worst increment is bounded by +0.5 ms.
RECORD_ONLY = ("record only: a base without command values makes the ratio the whole added cost; "
               "the worst increment is bounded by +0.5 ms (U-23), not by this ratio")


class GateResult(TypedDict, total=False):
    status: str
    metric: str
    base: dict
    candidate: dict
    ratio_p50: float
    ratio_p95: float
    threshold: dict | None
    absolute: dict
    reason: str


def _blocked(metric, reason, **extra):
    return GateResult(status="BLOCKED", metric=metric, reason=reason, **extra)


def _recomputed(row, samples, metric):
    """The summary recomputed from the raw samples by the D1 summarizer, or None.

    None when the samples are missing, malformed, non-finite or too large for a float, or
    when the given summary disagrees with them: the verdict never trusts a summary alone.
    """
    if not isinstance(row, dict) or not isinstance(samples, list):
        return None
    try:
        values = [x[metric] for x in samples]
        if any(type(v) not in (int, float) for v in values):
            return None
        got = protocol.summary(values)
    except (KeyError, TypeError, ValueError, ArithmeticError):
        return None
    # == alone equates True with 1 and 200.0 with 200: check the types first.
    if type(row.get("n")) is not int or not all(
            type(row.get(k)) in (int, float) and math.isfinite(row[k]) for k in got if k != "n"):
        return None
    return got if all(row.get(k) == got[k] for k in got) else None


def relative_gate(paired: dict, metric: str, threshold: tuple | None, target_ms=ABSOLUTE_TARGET_MS) -> GateResult:
    """FAIL when the candidate/base ratio of p50 exceeds `threshold[0]` or that of p95 exceeds `threshold[1]`.

    Missing, non-finite or inconsistent evidence is BLOCKED, never PASS.
    `target_ms` is the absolute target recorded beside it; None records no target.
    """
    try:
        rows = [paired["variants"][n] for n in ("base", "candidate")]
        base, cand = (r["summary"][metric] for r in rows)
        samples = [r["samples"] for r in rows]
    except (KeyError, TypeError):
        return _blocked(metric, "no summary or raw samples for " + str(metric))
    base, cand = _recomputed(base, samples[0], metric), _recomputed(cand, samples[1], metric)
    if base is None or cand is None or base["n"] != cand["n"]:
        return _blocked(metric, "invalid evidence: summary disagrees with samples, or samples are malformed or unpaired")
    if paired.get("status") != "OBSERVED" or min(base["n"], cand["n"]) < MIN_PAIRS:
        return _blocked(metric, "fewer than %d alternated pairs or unobserved" % MIN_PAIRS, base=base, candidate=cand)
    if not (base["p50"] > 0 and base["p95"] > 0):
        return _blocked(metric, "base percentile is zero", base=base, candidate=cand)
    if threshold is not None and not (type(threshold) is tuple and len(threshold) == 2 and all(
            type(t) in (int, float) and math.isfinite(t) and t > 0 for t in threshold)):
        return _blocked(metric, "invalid threshold", base=base, candidate=cand)
    ratios = (cand["p50"] / base["p50"], cand["p95"] / base["p95"])
    if not all(math.isfinite(r) for r in ratios):
        return _blocked(metric, "ratio overflows")
    observed_ms = cand["p50"] / 1e6
    over = target_ms is not None and observed_ms > target_ms
    result = GateResult(
        metric=metric, base=base, candidate=cand,
        ratio_p50=ratios[0], ratio_p95=ratios[1],
        threshold=None if threshold is None else {"p50": threshold[0], "p95": threshold[1]},
        absolute={"target_ms": target_ms, "observed_ms": observed_ms,
                  "disposition": "recorded over target; needs user disposition, not a failure" if over else None})
    if threshold is None:
        result.update(status="BLOCKED", reason="threshold " + PENDING)
    else:
        result["status"] = "FAIL" if ratios[0] > threshold[0] or ratios[1] > threshold[1] else "PASS"
    return result


def _size_ok(v):
    return type(v) is int and v > 0


def size_gate(base: dict, candidate: dict, cap_bytes: int | None, installed_cap_bytes: int | None) -> GateResult:
    """FAIL when the candidate front + collector (`combined`) exceeds `cap_bytes`
    or its three shipped files together (`installed`, checked by `release_side`)
    exceed `installed_cap_bytes`; no per-binary cap.

    A missing or invalid cap is BLOCKED. Each cap reads its own evidence: a
    candidate over one cap FAILs even when the other's evidence (a combined
    that is not front + collector, an installed that is not the three files'
    sum) or the base size is bad; a candidate that fits is then BLOCKED.
    """
    def valid(side):
        return (isinstance(side, dict) and all(_size_ok(side.get(k)) for k in SIZE_KEYS)
                and side["combined"] == side["front"] + side["collector"])
    release = release_side(candidate)
    if not valid(candidate) and release is None:
        return _blocked("stripped_bytes", "missing or inconsistent size")
    result = GateResult(metric="stripped_bytes", base=base, candidate=candidate)
    caps = {"combined": cap_bytes, "installed": installed_cap_bytes}
    if any(cap is None for cap in caps.values()):
        return {**result, "status": "BLOCKED", "reason": "cap " + PENDING}
    if not all(_size_ok(cap) for cap in caps.values()):
        return {**result, "status": "BLOCKED", "reason": "invalid cap"}
    result["cap_bytes"] = caps
    sizes = {"combined": candidate["combined"] if valid(candidate) else None,
             "installed": None if release is None else release["installed"]}
    # 이것을 실패시키는 것: installed를 판정에서 빼는 것, 경계(상한과 같은 크기)를 넘은 것으로 치는 것,
    # 후보 대신 기준의 크기를 재는 것.
    result["over"] = [k for k in caps if sizes[k] is not None and sizes[k] > caps[k]]
    # The caps judge the candidate alone; missing evidence only blocks a candidate that fits.
    # 이것을 실패시키는 것: 어긋난 combined가 installed 초과를 BLOCKED로 덮는 것, 그 combined를 통과로 치는 것.
    if not result["over"] and sizes["combined"] is None:
        return {**result, "status": "BLOCKED", "reason": "missing or inconsistent size"}
    if not result["over"] and release is None:
        return {**result, "status": "BLOCKED", "reason": "missing or inconsistent release size"}
    if not result["over"] and not valid(base):
        return {**result, "status": "BLOCKED", "reason": "missing or inconsistent size"}
    result["status"] = "FAIL" if result["over"] else "PASS"
    return result


# Release size: the three files a release ships, stripped, and their sum
# (`installed`). The candidate's sum is judged by `size_gate`; base, candidate
# and the change are recorded beside the verdict for every pull request.
RELEASE_FILES = (("bingsu", "cli"), ("bingsu-prompt", "front"), ("bingsu-collect", "collector"))


def release_side(side):
    """Each release file's stripped bytes and their sum, or None when the
    preparation lacks a file or its `installed` is not exactly that sum (a tree
    without bingsu-prompt records front = bingsu and no third file)."""
    if not isinstance(side, dict) or not all(_size_ok(side.get(key)) for _, key in RELEASE_FILES):
        return None
    files = {name: side[key] for name, key in RELEASE_FILES}
    if not _size_ok(side.get("installed")) or side["installed"] != sum(files.values()):
        return None
    return {"files": files, "installed": side["installed"]}


def release_size(base: dict, candidate: dict) -> GateResult:
    """The release size of base and candidate and the change, status RECORDED."""
    sides = {"base": release_side(base), "candidate": release_side(candidate)}
    result = GateResult(status="RECORDED", metric="stripped_bytes", base=sides["base"], candidate=sides["candidate"])
    missing = [name for name, side in sides.items() if side is None]
    if missing:
        result["reason"] = "missing or inconsistent release size: " + ", ".join(missing)
        return result
    old, new = sides["base"], sides["candidate"]
    result["delta"] = {**{name: new["files"][name] - old["files"][name] for name, _ in RELEASE_FILES},
                       "installed": new["installed"] - old["installed"]}
    return result


def recorded(result: GateResult) -> GateResult:
    """`result` kept for the record: its own status moves to `observed_status`."""
    return {**result, "status": "RECORDED", "observed_status": result["status"], "record_only": RECORD_ONLY}


def aggregate(results: list[GateResult]) -> str:
    statuses = {r["status"] for r in results}
    return "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses or not statuses else "PASS"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--measurement", type=Path, required=True, help="git-product.py --base/--candidate output")
    p.add_argument("--base-preparation", type=Path, required=True)
    p.add_argument("--candidate-preparation", type=Path, required=True)
    p.add_argument("--ratio-p50", type=float, help="max candidate/base ratio of p50 (U3: 1.03)")
    p.add_argument("--ratio-p95", type=float, help="max candidate/base ratio of p95 (U3: 1.10)")
    p.add_argument("--cap-bytes", type=int, help="cap on stripped front + collector bytes (2500000)")
    p.add_argument("--installed-cap-bytes", type=int,
                   help="cap on the stripped bytes of the three shipped files together (7000000)")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--enforce", action="store_true", help="exit 1 on FAIL; BLOCKED and PASS exit 0")
    p.add_argument("--record-only", default="", help="comma-separated cases recorded but not judged")
    args = p.parse_args(argv)
    if (args.ratio_p50 is None) != (args.ratio_p95 is None):
        p.error("--ratio-p50 and --ratio-p95 go together")
    threshold = None if args.ratio_p50 is None else (args.ratio_p50, args.ratio_p95)
    measurement = json.loads(args.measurement.read_text())
    record_only = {c for c in args.record_only.split(",") if c}
    time_results = {case: relative_gate(row, "prompt_ns", threshold) for case, row in measurement.get("cases", {}).items()}
    time_results = {case: recorded(r) if case in record_only else r for case, r in time_results.items()}
    if not any(r["status"] != "RECORDED" for r in time_results.values()):
        time_results["-"] = _blocked("prompt_ns", "measurement has no judged cases: " + str(measurement.get("reason", "")))
    sizes = [json.loads(f.read_text()).get("stripped_bytes") for f in (args.base_preparation, args.candidate_preparation)]
    size = size_gate(sizes[0], sizes[1], args.cap_bytes, args.installed_cap_bytes)
    release = release_size(sizes[0], sizes[1])  # the record; `size` judges the candidate's sum
    verdict = aggregate([*time_results.values(), size])
    report = {"schema": 1, "status": verdict, "enforced": args.enforce,
              "threshold": None if threshold is None else {k: t if math.isfinite(t) else str(t) for k, t in zip(("p50", "p95"), threshold)},
              "cap_bytes": args.cap_bytes, "installed_cap_bytes": args.installed_cap_bytes,
              "time": time_results, "size": size, "release_size": release}
    args.out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    reasons = sorted({r["reason"] for r in (*time_results.values(), size) if r.get("reason") and r["status"] != "RECORDED"})
    print(json.dumps({"status": verdict, "enforced": args.enforce, "blocked_by": reasons,
                      "time": {c: {k: r.get(k) for k in ("status", "observed_status", "ratio_p50", "ratio_p95", "reason")} for c, r in time_results.items()},
                      "size": {k: size.get(k) for k in ("status", "over", "reason", "cap_bytes")},
                      "release_size": {k: release.get(k) for k in ("status", "base", "candidate", "delta", "reason")}}, indent=2))
    # BLOCKED (no usable evidence) is reported in the report and summary but does not fail the run.
    return 1 if args.enforce and verdict == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
