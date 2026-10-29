#!/usr/bin/env python3
"""Pull request gate verdicts for full prompt time and stripped binary size.

Pure judgement over D1 `Paired` rows and `git-product.py --prepare` size maps. The
threshold and the size cap are inputs: until U3 fixes them the verdict is BLOCKED
("pending U3") and never FAIL, and the CLI exits 0 unless --enforce is given.
Absolute time is recorded only; it is never a reason to fail.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TypedDict

MIN_PAIRS = 200
# Spec section 1303: warm prompt median target, recorded next to the verdict only.
ABSOLUTE_TARGET_MS = 10.0
SIZE_KEYS = ("front", "collector", "combined")
PENDING = "pending U3"


class GateResult(TypedDict, total=False):
    status: str
    metric: str
    base: dict
    candidate: dict
    ratio_p50: float
    ratio_p95: float
    threshold: float | None
    absolute: dict
    reason: str


def _blocked(metric, reason, **extra):
    return GateResult(status="BLOCKED", metric=metric, reason=reason, **extra)


def relative_gate(paired: dict, metric: str, threshold: float | None) -> GateResult:
    """FAIL when the candidate/base ratio of p50 or p95 exceeds `threshold`."""
    try:
        base, cand = (paired["variants"][n]["summary"][metric] for n in ("base", "candidate"))
    except (KeyError, TypeError):
        return _blocked(metric, "no summary for " + metric)
    if paired.get("status") != "OBSERVED" or min(base.get("n", 0), cand.get("n", 0)) < MIN_PAIRS:
        return _blocked(metric, "fewer than %d alternated pairs or unobserved" % MIN_PAIRS, base=base, candidate=cand)
    if not (base["p50"] > 0 and base["p95"] > 0):
        return _blocked(metric, "base percentile is zero", base=base, candidate=cand)
    observed_ms = cand["p50"] / 1e6
    over = observed_ms > ABSOLUTE_TARGET_MS
    result = GateResult(
        metric=metric, base=base, candidate=cand,
        ratio_p50=cand["p50"] / base["p50"], ratio_p95=cand["p95"] / base["p95"], threshold=threshold,
        absolute={"target_ms": ABSOLUTE_TARGET_MS, "observed_ms": observed_ms,
                  "disposition": "recorded over target; needs user disposition, not a failure" if over else None})
    if threshold is None:
        result.update(status="BLOCKED", reason="threshold " + PENDING)
    else:
        result["status"] = "FAIL" if max(result["ratio_p50"], result["ratio_p95"]) > threshold else "PASS"
    return result


def size_gate(base: dict, candidate: dict, cap_bytes: int | dict | None) -> GateResult:
    """FAIL when a candidate size exceeds its cap.

    `cap_bytes` is one int for front, collector and their sum alike, or a dict with
    any of the SIZE_KEYS (a missing key is not checked). U3 picks the reading.
    """
    for side in (base, candidate):
        if not all(type(side.get(k)) is int and side[k] > 0 for k in SIZE_KEYS):
            return _blocked("stripped_bytes", "missing size", base=base, candidate=candidate)
    result = GateResult(metric="stripped_bytes", base=base, candidate=candidate)
    if cap_bytes is None:
        return {**result, "status": "BLOCKED", "reason": "cap " + PENDING}
    caps = dict.fromkeys(SIZE_KEYS, cap_bytes) if isinstance(cap_bytes, int) else dict(cap_bytes)
    result["cap_bytes"] = caps
    result["over"] = [k for k in SIZE_KEYS if k in caps and candidate[k] > caps[k]]
    result["status"] = "FAIL" if result["over"] else "PASS"
    return result


def aggregate(results: list[GateResult]) -> str:
    statuses = {r["status"] for r in results}
    return "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses or not statuses else "PASS"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--measurement", type=Path, required=True, help="git-product.py --base/--candidate output")
    p.add_argument("--base-preparation", type=Path, required=True)
    p.add_argument("--candidate-preparation", type=Path, required=True)
    p.add_argument("--threshold", type=float, help="max candidate/base ratio of p50 and p95 (U3)")
    p.add_argument("--cap-bytes", type=int, help="size cap in bytes, applied to front, collector and combined (U3)")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--enforce", action="store_true", help="exit 1 on FAIL and 2 on BLOCKED (off until U3)")
    args = p.parse_args(argv)
    measurement = json.loads(args.measurement.read_text())
    time_results = {case: relative_gate(row, "prompt_ns", args.threshold) for case, row in measurement.get("cases", {}).items()}
    if not time_results:
        time_results = {"-": _blocked("prompt_ns", "measurement has no cases: " + str(measurement.get("reason", "")))}
    sizes = [json.loads(f.read_text()).get("stripped_bytes", {}) for f in (args.base_preparation, args.candidate_preparation)]
    size = size_gate(sizes[0], sizes[1], args.cap_bytes)
    verdict = aggregate([*time_results.values(), size])
    report = {"schema": 1, "status": verdict, "enforced": args.enforce, "threshold": args.threshold,
              "cap_bytes": args.cap_bytes, "time": time_results, "size": size}
    args.out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"status": verdict, "enforced": args.enforce,
                      "time": {c: {k: r.get(k) for k in ("status", "ratio_p50", "ratio_p95", "reason")} for c, r in time_results.items()},
                      "size": {k: size.get(k) for k in ("status", "over", "reason")}}, indent=2))
    if args.enforce and verdict != "PASS":
        return 1 if verdict == "FAIL" else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
