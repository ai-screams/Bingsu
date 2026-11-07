"""C5: an env segment draws a variable from the prompt's own environment."""
import pytest
from snapshot_support import SnapshotSession, require_native_boot


@pytest.fixture(autouse=True)
def _native_boot_required():
    require_native_boot()


AWS = '[segment."custom/aws"]\nkind = "env"\nenv = "AWS_PROFILE"\n'
READY = '[segment."custom/ok"]\nkind = "text"\ntext = "READY"\n'
LINE = '[layout.line1]\nleft = ["custom/ok", "custom/aws", "char"]\n'


def theme(session, text):
    """A file outside the config root, as a repository would ship it: shape-only."""
    path = session.base / "repo" / "theme.toml"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text(text)
    path.chmod(0o600)
    return path


# 선언한 env segment는 프롬프트 자신의 환경 값을 그리고, 값을 바꾸면 helper 회차 없이 다음 프롬프트와 redraw가 새
# 값을 그린다. 이것을 실패시키는 것: 앞단의 env 값 읽기를 빼는 것, redraw에서 환경 frame을 쓰지 않는 것.
def test_env_segment_shows_value_when_set(tmp_path):
    session = SnapshotSession(tmp_path)
    session.env["AWS_PROFILE"] = "dev-acct"
    session.put(AWS + READY + LINE)
    session.init()
    assert b"dev-acct" in session.await_text("READY")
    session.wait_quiet()
    session.env["AWS_PROFILE"] = "prod-acct"
    assert b"prod-acct" in session.prompt()
    redraw = session.run(*session.prompt_args(), "--redraw", timeout=2)
    assert redraw.returncode == 0 and b"prod-acct" in redraw.stdout, redraw
    del session.env["AWS_PROFILE"]
    record = session.prompt()
    assert b"READY" in record and b"acct" not in record, record
    session.wait_quiet()


# 저장소 레이아웃(모양 전용 파일)만 참조한 env segment는 그리지 않는다. 대조: 같은 선언을 사용자 레이아웃이 참조하면
# 그린다. 이것을 실패시키는 것: env segment에 신뢰 레이아웃 판정을 부르지 않는 것.
@pytest.mark.parametrize("trusted", [False, True])
def test_repository_layout_cannot_show_env(tmp_path, trusted):
    session = SnapshotSession(tmp_path)
    session.env["AWS_PROFILE"] = "dev-acct"
    if trusted:
        session.put(AWS + READY + LINE)
    else:
        session.put(f'extends = ["{theme(session, LINE)}"]\n' + AWS + READY)
    session.init()
    record = session.await_text("READY")
    assert (b"dev-acct" in record) == trusted, record
    session.wait_quiet()


# 모양 전용 파일이 선언한 env segment는 무시된다(W402): 그 파일의 레이아웃이 참조해도 값을 그리지 않는다. 이것을
# 실패시키는 것: 모양 전용 파일의 kind = "env"를 버리지 않는 것.
def test_shape_only_env_ignored(tmp_path):
    session = SnapshotSession(tmp_path)
    session.env["SECRET"] = "zz-secret"
    path = theme(session, '[segment."custom/sec"]\nkind = "env"\nenv = "SECRET"\n'
                          '[layout.line1]\nleft = ["custom/ok", "custom/sec", "char"]\n')
    session.put(f'extends = ["{path}"]\n' + READY)
    session.init()
    record = session.await_text("READY")
    assert b"zz-secret" not in record, record
    session.wait_quiet()
