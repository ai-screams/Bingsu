"""N7 actual helper -> store -> prompt integration (same fixture on every OS)."""
import concurrent.futures
import fcntl
import sys

import pytest
from snapshot_support import SnapshotSession, require_native_boot


@pytest.fixture(autouse=True)
def _native_boot_required():
    require_native_boot()


def appearance(word):
    return f"[style]\ntemplate='{word} {{char}}'\n"


# 이것을 실패시키는 것: 새 inode의 같은 내용·편집 복귀·conf.d 추가/삭제를 unchanged로 취급하는 것.
def test_refresh_observes_replacements_and_overlay_membership(tmp_path):
    session = SnapshotSession(tmp_path)
    session.put(appearance("BASE"))
    session.init()
    session.await_text("BASE")
    generations = [session.identity()[1]]
    for text, overlay, expected in [
        (appearance("BASE"), None, "BASE"),
        (appearance("EDIT"), None, "EDIT"),
        (appearance("BASE"), None, "BASE"),
        (None, appearance("OVERLAY"), "OVERLAY"),
        (None, "remove", "BASE"),
    ]:
        if text is not None:
            session.put(text)
        if overlay == "remove":
            (session.config / "conf.d/10.toml").unlink()
        elif overlay is not None:
            session.put(overlay, "conf.d/10.toml")
        # Explicit command ensures a complete validation, not a first-prompt promise.
        result = session.run("reload")
        assert result.returncode in (0, 3), result.stderr  # background helper may own lock
        session.await_text(expected)
        # The matching display may predate an identical-byte replacement. Wait for G.
        import time
        end = time.monotonic() + 4
        while session.identity()[1] <= generations[-1] and time.monotonic() < end:
            session.prompt()
            time.sleep(0.02)
        generations.append(session.identity()[1])
        assert generations[-1] > generations[-2], generations
    session.wait_quiet()


# 이것을 실패시키는 것: 같은 문맥 lock을 세션별로 분리하거나 다른 state 문맥을 전역 lock으로 묶는 것.
def test_shared_context_busy_and_distinct_state_progress(tmp_path):
    a = SnapshotSession(tmp_path, "a")
    a.put(appearance("SHARED"))
    a.init()
    a.await_text("SHARED")
    b = SnapshotSession(tmp_path, "b", config=a.config.parent,
                        runtime=a.env["XDG_RUNTIME_DIR"])
    b.init()
    b.await_text("SHARED")
    a.wait_quiet()
    before_generation = a.identity()[1]
    lock = a.store() / "snapshot.lock"
    before_inode = lock.stat().st_ino
    with lock.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        a.put(appearance("CHANGED"))
        result = a.run("reload")
        assert result.returncode == 3, (result.stdout, result.stderr)
        assert a.identity()[1] == before_generation
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            records = list(pool.map(lambda _: a.prompt(), range(4)))
        assert all(b"SHARED" in record and b"CHANGED" not in record for record in records)
        b.await_text("CHANGED")
        assert a.store() != b.store()
        a.wait_quiet()
        b.wait_quiet()
        assert a.identity()[1] == before_generation
    result = a.run("reload")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert a.identity()[1] > before_generation
    a.await_text("CHANGED")
    assert lock.stat().st_ino == before_inode
    a.wait_quiet()


# 이것을 실패시키는 것: Invalid가 마지막 화면을 지우거나 prompt stderr로 명시 명령 진단을 흘리는 것.
def test_invalid_config_keeps_display_and_recovers(tmp_path):
    session = SnapshotSession(tmp_path)
    session.put(appearance("LASTGOOD"))
    session.init()
    session.await_text("LASTGOOD")
    session.wait_quiet()
    session.put("[broken")
    result = session.run("reload")
    assert result.returncode == 1 and result.stderr
    record = session.prompt()
    assert b"LASTGOOD" in record and b"!" in record and b"degraded:trust-invalid" in record
    session.put(appearance("RECOVERED"))
    session.await_text("RECOVERED")
    session.wait_quiet()


# P-R4: a file that fails its safety check is left out and the rest is published
# with a fresh valid marker; the next prompt keeps the screen and is not degraded.
# 이것을 실패시키는 것: 확인한 신뢰 실패를 Invalid 표식(전부 철회, degraded)이나 Incomplete(옛 표식 유지)로
# 처리하는 것, 빠진 파일을 알리지 않는 것.
def test_untrusted_file_is_left_out_and_the_rest_republished(tmp_path):
    session = SnapshotSession(tmp_path)
    session.put(appearance("KEPT"))
    dropped = session.put('[segment."custom/drop"]\nkind = "command"\ncommand = ["printf", "DROP"]\n',
                          "conf.d/10.toml")
    session.init()
    session.await_text("KEPT")
    session.wait_quiet()
    before = session.identity()[1]
    dropped.chmod(0o646)
    result = session.run("reload")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert b"left out, nothing in it runs: " in result.stdout and b"conf.d/10.toml" in result.stdout, result.stdout
    assert session.identity()[1] > before
    record = session.prompt()
    assert b"KEPT" in record and b"degraded:" not in record, record
    session.wait_quiet()


REVOKE_CONFIG = ('[segment."custom/probe"]\nkind = "command"\ncommand = ["printf", "NEVER_EXECUTE"]\n'
                 '[layout.line1]\nleft = ["custom/probe", "char"]\n')


def trust_window_ns():
    """T from the product source (crates/bingsu-core/src/snapshot.rs), not a copy."""
    import re
    from conftest import ROOT
    text = (ROOT / "crates/bingsu-core/src/snapshot.rs").read_text()
    return int(re.search(r"pub const T_NS: u64 = ([0-9_]+);", text).group(1).replace("_", ""))


# GATE-TRUST-REVOKE.2: the config root sits on a FUSE mount whose daemon is stopped, so no helper can
# re-verify after `chmod g+w` on the config file. The old marker stays byte for byte; prompts before
# verified_at + T keep ok:none, and from verified_at + T on every prompt is degraded:trust-expired, which
# in the front (finish) means no permit and no execution unit (units are not visible live before M6; the
# unit-level assertion is the Rust test chmod_g_w_after_verified_at_plus_t_approves_no_unit). It waits
# out T (about 60 s) on the real CLOCK_BOOTTIME, the clock of a Linux marker.
# 이것을 실패시키는 것: snapshot::eligible의 만료 검사(`now >= verified_at + T`)를 지우는 것. 경계에서 정확히
# 같은 ns를 맞출 수 없으므로 `>=`를 `>`로 바꾸는 변이는 Rust 시험 둘이 잡는다.
@pytest.mark.skipif(sys.platform != "linux", reason="Linux FUSE fixture and CLOCK_BOOTTIME")
def test_chmod_g_w_on_blocked_mount_approves_no_unit_past_t(tmp_path):
    import struct
    import time
    from blocked_mount import blocked_mount
    from shell_support import Blocked
    from test_helper_lifecycle import LifetimeSession, fail_blocked, stop_helpers
    import faulthandler
    import os
    import signal
    import threading
    t_ns = trust_window_ns()
    holder = {}
    # The whole test is bounded: past the limit a watchdog records every thread's stack,
    # resumes the stopped daemon and kills this session's helpers, so a wait on the mount
    # returns and the test fails with that stack instead of reaching the job timeout.
    limit_s = t_ns / 1e9 + 60
    finished, abort, stuck = threading.Event(), threading.Event(), []
    mount_word = os.fsencode(str(tmp_path / "fuse/mount"))

    def watchdog():
        if finished.wait(limit_s):
            return
        trace = tmp_path / "stuck-stacks.txt"
        with trace.open("w") as out:
            faulthandler.dump_traceback(file=out, all_threads=True)
        stuck.append(trace.read_text())
        abort.set()
        for proc in os.listdir("/proc"):
            try:
                words = open(f"/proc/{proc}/cmdline", "rb").read().split(b"\0")
            except (OSError, ValueError):
                continue
            if words and words[0].endswith(b"bindfs") and mount_word in words:
                os.kill(int(proc), signal.SIGCONT)
        if "session" in holder:
            stop_helpers(holder["session"])

    guard = threading.Thread(target=watchdog, daemon=True)
    guard.start()

    def prepare(mount):
        session = LifetimeSession(tmp_path / "s", config=mount / "cfg")
        session.put(REVOKE_CONFIG)
        session.init()
        session.wait_quiet()
        record = session.prompt()
        assert b"ok:none" in record, record
        session.wait_quiet()  # that prompt's helper revalidated; no helper is running now
        holder["session"] = session
        # store() resolves the config root, which lies on the mount: resolve it while it answers.
        holder["marker"] = session.store() / "marker"

    def boottime():
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)

    def prompt_between():
        before = boottime()
        record = session.prompt()
        return before, record, boottime()

    try:
        with blocked_mount(tmp_path / "fuse", prepare=prepare):
            session = holder["session"]
            try:
                marker_path = holder["marker"]
                marker = marker_path.read_bytes()
                assert marker[:8] == b"BNGMRK02" and marker[12] == 1 and marker[13] == 1, marker
                end = struct.unpack_from("<Q", marker, 32)[0] + t_ns
                # 이것을 실패시키는 것: 표식 시각과 이 시험의 CLOCK_BOOTTIME이 다른 시계라 대기가 T를 크게 넘는 것.
                assert 0 < end - boottime() <= t_ns, ("marker clock and CLOCK_BOOTTIME disagree", end, boottime())
                # The daemon is stopped: chmod the file through the mount's source folder.
                (tmp_path / "fuse/source/cfg/bingsu/config.toml").chmod(0o620)
                inside = []
                while True:
                    before, record, after = prompt_between()
                    if after < end:
                        assert b"ok:none" in record, ("inside T", record)
                        inside.append(record)
                        inside_end = after
                    assert marker_path.read_bytes() == marker, "a helper rewrote the marker"
                    if before >= end:
                        break
                    # One prompt shortly before the boundary, then one just past it; never a busy loop.
                    wait = (end - boottime()) / 1e9
                    if abort.wait(max(0.0, wait - 1.0) if wait > 1.5 else max(0.0, wait) + 0.05):
                        break  # the watchdog fired; finally reports its stacks
                assert inside, "no prompt ran inside T"
                print(f"\ntrust revocation: {len(inside)} prompts inside T, last {(end - inside_end) / 1e6:.1f} ms "
                      f"before verified_at + T; first expired {(before - end) / 1e6:.1f} ms after it")
                assert b"degraded:trust-expired" in record and b"!" in record, record
                _, again, _ = prompt_between()
                assert b"degraded:trust-expired" in again, again
                assert marker_path.read_bytes() == marker, "a helper rewrote the marker"
            finally:
                stop_helpers(session)
    except Blocked as error:
        fail_blocked(error)
    finally:
        finished.set()
        guard.join(timeout=30)
        # 이것을 실패시키는 것: 막힌 마운트에서 끝나지 않는 대기(정리 포함)가 job 제한까지 가는 것.
        if stuck:
            pytest.fail(f"exceeded {limit_s:.0f} s; stacks when the watchdog fired:\n{stuck[0]}", pytrace=False)
