"""N7 actual helper -> store -> prompt integration (same fixture on every OS)."""
import concurrent.futures
import fcntl

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
