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


def relative_gate(paired: dict, metric: str, threshold: float | None) -> GateResult:
    """FAIL when the candidate/base ratio of p50 or p95 exceeds `threshold`.

    Missing, non-finite or inconsistent evidence is BLOCKED, never PASS.
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
    if threshold is not None and not (type(threshold) in (int, float) and math.isfinite(threshold) and threshold > 0):
        return _blocked(metric, "invalid threshold", base=base, candidate=cand)
    ratios = (cand["p50"] / base["p50"], cand["p95"] / base["p95"])
    if not all(math.isfinite(r) for r in ratios):
        return _blocked(metric, "ratio overflows")
    observed_ms = cand["p50"] / 1e6
    over = observed_ms > ABSOLUTE_TARGET_MS
    result = GateResult(
        metric=metric, base=base, candidate=cand,
        ratio_p50=ratios[0], ratio_p95=ratios[1], threshold=threshold,
        absolute={"target_ms": ABSOLUTE_TARGET_MS, "observed_ms": observed_ms,
                  "disposition": "recorded over target; needs user disposition, not a failure" if over else None})
    if threshold is None:
        result.update(status="BLOCKED", reason="threshold " + PENDING)
    else:
        result["status"] = "FAIL" if max(result["ratio_p50"], result["ratio_p95"]) > threshold else "PASS"
    return result


def _size_ok(v):
    return type(v) is int and v > 0


def size_gate(base: dict, candidate: dict, cap_bytes: int | dict | None) -> GateResult:
    """FAIL when a candidate size exceeds its cap.

    `cap_bytes` is one int for front, collector and their sum alike, or a dict
    holding all of SIZE_KEYS. A missing or invalid cap, a missing size or a
    combined that is not front + collector is BLOCKED. U3 picks the reading.
    """
    for side in (base, candidate):
        if not (isinstance(side, dict) and all(_size_ok(side.get(k)) for k in SIZE_KEYS)
                and side["combined"] == side["front"] + side["collector"]):
            return _blocked("stripped_bytes", "missing or inconsistent size")
    result = GateResult(metric="stripped_bytes", base=base, candidate=candidate)
    if cap_bytes is None:
        return {**result, "status": "BLOCKED", "reason": "cap " + PENDING}
    caps = dict.fromkeys(SIZE_KEYS, cap_bytes) if type(cap_bytes) is int else cap_bytes
    if not (isinstance(caps, dict) and all(_size_ok(caps.get(k)) for k in SIZE_KEYS)):
        return {**result, "status": "BLOCKED", "reason": "cap incomplete or invalid, " + PENDING}
    result["cap_bytes"] = caps
    result["over"] = [k for k in SIZE_KEYS if candidate[k] > caps[k]]
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
    sizes = [json.loads(f.read_text()).get("stripped_bytes") for f in (args.base_preparation, args.candidate_preparation)]
    size = size_gate(sizes[0], sizes[1], args.cap_bytes)
    verdict = aggregate([*time_results.values(), size])
    report = {"schema": 1, "status": verdict, "enforced": args.enforce, "threshold": args.threshold if args.threshold is None or math.isfinite(args.threshold) else str(args.threshold),
              "cap_bytes": args.cap_bytes, "time": time_results, "size": size}
    args.out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    reasons = sorted({r["reason"] for r in (*time_results.values(), size) if r.get("reason")})
    print(json.dumps({"status": verdict, "enforced": args.enforce, "blocked_by": reasons,
                      "time": {c: {k: r.get(k) for k in ("status", "ratio_p50", "ratio_p95", "reason")} for c, r in time_results.items()},
                      "size": {k: size.get(k) for k in ("status", "over", "reason")}}, indent=2))
    if args.enforce and verdict != "PASS":
        return 1 if verdict == "FAIL" else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
