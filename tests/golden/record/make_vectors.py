#!/usr/bin/env python3
"""Write the B1 record golden vectors (spec section 3, M1 status grammar).

Usage: make_vectors.py OUT_DIR CANARY_PATH
Hostile vectors embed CANARY_PATH; if any shell executes them the file
appears and run.py fails.
"""
import pathlib
import sys

US, RS = b"\x1f", b"\x1e"


def rec(fields, status=b"ok:none", header=b"B1", count=b"7", tail=RS):
    return header + US + count + US + US.join(fields) + US + status + tail


def one(left, **kw):
    return rec([left] + [b""] * 5, **kw)


def main():
    out = pathlib.Path(sys.argv[1])
    canary = sys.argv[2].encode()
    out.mkdir(parents=True, exist_ok=True)
    overhead = len(one(b""))
    v = {
        "good": rec([b"\x1b[31m\x01L\x02", b"R", b"tL", b"tR", b">", b"<"]),
        "good_utf8": one("한글 *[\\%!".encode()),
        "six_empty": rec([b""] * 6),
        "lit_dot": one(b"a.b"),
        "cr": one(b"a\rb"),
        "bad_utf8": one(b"\xff\xfe"),
        "bad_sgr": one(b"\x1b[31X"),
        "ko22000": one(("가" * 22000).encode()),
        "empty_status": one(b"L", status=b""),
        "status_dot": one(b"L", status=b"."),
        "inner_rs": one(b"L" + RS + b"x"),
        "inner_lf": one(b"L\nx"),
        "rs_lf": one(b"L") + b"\n",
        "rs_lflf": one(b"L") + b"\n\n",
        "no_rs": one(b"L", tail=b""),
        "eight": rec([b"L"] + [b""] * 4),
        "ten": rec([b"L"] + [b""] * 6),
        "bad_hdr": one(b"L", header=b"B2"),
        "bad_count": one(b"L", count=b"8"),
        "empty": b"",
        "huge": one(b"x" * 70000),
        "len_65536": one(b"x" * (65536 - overhead)),
        "len_65537": one(b"x" * (65537 - overhead)),
        "st_ok_future": one(b"L", status=b"ok:future-code"),
        "st_notice_future": one(b"L", status=b"notice:future-code"),
        "st_degraded_known": one(b"L", status=b"degraded:runtime-root"),
        "st_error_known": one(b"L", status=b"error:bad-args"),
        "st_degraded_unknown": one(b"L", status=b"degraded:future-x"),
        "st_unknown_class": one(b"L", status=b"weird:thing"),
        "st_no_colon": one(b"L", status=b"ok"),
        "st_empty_code": one(b"L", status=b"ok:"),
        "st_empty_class": one(b"L", status=b":none"),
        "st_upper_class": one(b"L", status=b"OK:none"),
        "st_upper_code": one(b"L", status=b"ok:None"),
        "st_digit": one(b"L", status=b"ok:e1"),
        "st_two_colon": one(b"L", status=b"ok:a:b"),
        "st_cmdsub": one(b"L", status=b"$(touch " + canary + b"):x"),
        "st_backtick": one(b"L", status=b"`touch " + canary + b"`:x"),
        "st_semicolon": one(b"L", status=b"ok:a;touch " + canary),
        "st_dollar_code": one(b"L", status=b"degraded:$(touch " + canary + b")"),
        "trail_us": one(b"L", status=b"ok:none" + US),
        "disp_cmdsub": rec([b"$(touch " + canary + b")"] * 6),
        "disp_backtick": rec([b"`touch " + canary + b"`"] * 6),
        "disp_percent": rec([b"%n%(?.a.b)%F{red}"] * 6),
        "nul_field": one(b"L\x00x"),
        "nul_status": one(b"L", status=b"ok:no\x00ne"),
    }
    # Hostile-value matrix (tests/hostile/classes.tsv), one vector per class.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "hostile"))  # tests/hostile/
    import matrix  # noqa: E402
    for row in matrix.rows():
        cls, spec = row[:2]
        if spec.startswith("repeat:"):
            _, byte, n = spec.split(":")
            data = bytes([int(byte, 16)]) * int(n)
        else:
            data = bytes.fromhex(spec).replace(b"CANARY", canary)
        v[f"hostile_{cls}"] = rec([b"L<" + data + b">L", b"RMARK", b"", b"", b"", b""])
    for name, data in v.items():
        (out / f"{name}.bin").write_bytes(data)
    print(f"wrote {len(v)} vectors")


if __name__ == "__main__":
    main()
