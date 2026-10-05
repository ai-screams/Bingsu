"""Matcher for nul_expected.tsv: shell x version range x locale group."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from run import nul_override, resolve_observations  # noqa: E402

ROWS = [
    ("nul_field", "zsh", ">=5.9", "C.UTF-8,en_US.UTF-8", "accept", "-"),
    ("nul_field", "zsh", ">=5.9", "C", "reject", "-"),
    ("nul_field", "zsh", "<5.9", "*", "reject", "-"),
    ("nul_field", "fish", "*", "*", "reject", "-"),
]


# 이것을 실패시키는 것: 로캘 묶음을 하나로만 보거나, 버전 범위를 무시하거나, 위에서부터 첫 일치가 아닌 것을 고르는 것.
def test_locale_groups_and_versions():
    assert nul_override(ROWS, "nul_field", "zsh", (5, 9), "en_US.UTF-8") == "accept"
    assert nul_override(ROWS, "nul_field", "zsh", (5, 9), "C.UTF-8") == "accept"
    assert nul_override(ROWS, "nul_field", "zsh", (5, 9), "C") == "reject"
    assert nul_override(ROWS, "nul_field", "zsh", (5, 8), "en_US.UTF-8") == "reject"
    assert nul_override(ROWS, "nul_field", "fish", (3, 6), "ko_KR.UTF-8") == "reject"
    assert nul_override(ROWS, "nul_field", "bash", (5, 1), "C") is None
    assert nul_override(ROWS, "nul_status", "zsh", (5, 9), "C") is None


# 이것을 실패시키는 것: 겹치는 행에서 첫 일치가 아닌 마지막 일치를 고르는 것(두 순서 모두 확인).
def test_overlapping_rows_first_match_wins():
    wide, narrow = ("nul_field", "zsh", "*", "*", "reject", "-"), ("nul_field", "zsh", ">=5.9", "en_US.UTF-8", "accept", "-")
    assert nul_override([narrow, wide], "nul_field", "zsh", (5, 9), "en_US.UTF-8") == "accept"
    assert nul_override([wide, narrow], "nul_field", "zsh", (5, 9), "en_US.UTF-8") == "reject"


# 이것을 실패시키는 것: 고정 행이 없는 observe 벡터를 기본 실행에서 통과시키는 것.
def test_unpinned_observation_fails_unless_recording():
    def want():
        return {"nul_field": ("observe", "-", "-"), "nul_status": ("observe", "-", "-"), "plain": ("accept", "ok", "-")}
    w = want()
    errors = resolve_observations(w, ROWS, "zsh", (5, 9), "en_US.UTF-8", record=False)
    assert w["nul_field"] == ("accept", "ok", "-")
    assert len(errors) == 1 and errors[0].startswith("nul_status: no nul_expected.tsv row for zsh 5.9 en_US.UTF-8")
    w = want()
    assert resolve_observations(w, ROWS, "zsh", (5, 9), "en_US.UTF-8", record=True) == []
    assert w["nul_status"] == ("observe", "-", "-")


PTY = [
    ("hostile_nul", "zsh", ">=5.9", "en_US.UTF-8", "accept", "noexec"),
    ("hostile_nul", "zsh", ">=5.9", "C", "accept", "-"),
    ("hostile_nul", "bash", "*", "*", "accept", "minimal"),
]


# 이것을 실패시키는 것: 화면 결과를 셸·버전·로캘 칸마다 따로 찾지 않거나(한 값으로 합침), "-"(아직 고정 안 됨)를
# 값으로 돌려주는 것.
def test_pty_column_is_keyed_and_dash_is_unpinned():
    assert nul_override(PTY, "hostile_nul", "zsh", (5, 9), "en_US.UTF-8", column="pty") == "noexec"
    assert nul_override(PTY, "hostile_nul", "zsh", (5, 9), "C", column="pty") is None
    assert nul_override(PTY, "hostile_nul", "zsh", (5, 9), "C") == "accept"
    assert nul_override(PTY, "hostile_nul", "bash", (5, 1), "ko_KR.UTF-8", column="pty") == "minimal"
    assert nul_override(PTY, "hostile_nul", "fish", (4, 9), "C", column="pty") is None
