"""`bingsu doctor` asks the terminal two questions: where the cursor is after
each probe character (`ESC [ 6 n`) and what the background is (`OSC 11 ; ?`).

The test plays the terminal on a pseudo-terminal: it keeps a cursor, moves it
by the cells each probe takes, and answers (or does not answer) the way a
terminal would. `sh` prints the terminal settings (`stty -g`) before and after
`bingsu doctor`, so a mode that is not restored shows."""
import json
import os
import pty
import re
import select
import shutil
import signal
import tempfile
import time
from pathlib import Path

import pytest

from conftest import real_bin

# The probe characters in the order doctor writes them
# (crates/bingsu-core/src/terminal_width.rs, PROBES).
PROBES = ["a", "\ud55c", "\u2500", "\u00b0", "\u2192", "\U0001f600",
          "\u2764\ufe0f", "\U0001f469\u200d\U0001f4bb", "\U0001f1f0\U0001f1f7",
          "e\u0301", "\ue0b0", "\uf023"]
NAMES = ["control-narrow", "control-wide", "ambiguous-box", "ambiguous-degree",
         "ambiguous-arrow", "emoji-plain", "emoji-vs16", "emoji-zwj", "emoji-flag",
         "combining", "nerd-separator", "nerd-icon"]
NORMAL = [1, 2, 1, 1, 1, 2, 2, 2, 2, 1, 1, 1]
AMBIGUOUS_WIDE = [1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1]
DARK = b"\x1b]11;rgb:1e1e/1e1e/2e2e\x1b\\"
LIGHT = b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\"

TOKEN = re.compile(
    "|".join(
        [re.escape("\x1b[6n"), re.escape("\x1b]11;?\x1b\\"), re.escape("\x1b[K"),
         re.escape("\r\n"), re.escape("\r"), re.escape("\n")]
        + [re.escape(p) for p in PROBES]
        + ["."]
    ),
    re.S,
)


@pytest.fixture
def home():
    root = Path(tempfile.mkdtemp(prefix="bdoc-")).resolve()
    root.chmod(0o700)
    (root / "cfg/bingsu").mkdir(parents=True)
    (root / "cfg/bingsu").chmod(0o700)
    yield root
    shutil.rmtree(root, ignore_errors=True)


def put_config(home, text):
    f = home / "cfg/bingsu/config.toml"
    f.write_text(text)
    f.chmod(0o600)


def snapshot(home):
    """Every file under the home with its bytes: doctor writes none."""
    out = {}
    for p in sorted(home.rglob("*")):
        out[str(p.relative_to(home))] = p.read_bytes() if p.is_file() else None
    return out


class Terminal:
    """A pseudo-terminal that keeps a cursor and answers doctor's questions."""

    def __init__(self, script, env, widths=NORMAL, background=DARK, answer=True,
                 cancel_on=None):
        self.widths = dict(zip(PROBES, widths))
        self.background, self.answer, self.cancel_on = background, answer, cancel_on
        self.row, self.col = 4, 1
        self.log = b""
        self.seen = []  # the questions asked, in order
        self.line_after = None
        self.pending = ""
        pid, fd = pty.fork()
        if pid == 0:
            os.execve("/bin/sh", ["/bin/sh", "-c", script], env)
        self.pid, self.fd = pid, fd

    def _feed(self, text):
        self.pending += text
        # Keep an incomplete escape for the next read.
        while self.pending:
            if self.pending[0] == "\x1b" and not re.match(
                r"\x1b(\[6n|\]11;\?\x1b\\|\[K)", self.pending
            ) and len(self.pending) < 8:
                break
            m = TOKEN.match(self.pending)
            t = m.group(0)
            self.pending = self.pending[len(t):]
            if t == "\x1b[6n":
                self.seen.append("cpr")
                if self.cancel_on == "sigterm":
                    pid = int(re.search(rb"BPID=(\d+)", self.log).group(1))
                    os.kill(pid, signal.SIGTERM)
                elif self.cancel_on == "cpr":
                    os.write(self.fd, b"\x03")
                elif self.answer:
                    os.write(self.fd, f"\x1b[{self.row};{self.col}R".encode())
            elif t == "\x1b]11;?\x1b\\":
                self.seen.append("osc11")
                if self.cancel_on == "osc11":
                    os.write(self.fd, b"\x03")
                elif self.answer:
                    os.write(self.fd, self.background)
            elif t == "\x1b[K":
                self.seen.append("clear")
            elif t in ("\r\n",):
                self.row, self.col = self.row + 1, 1
            elif t == "\n":
                self.row, self.col = self.row + 1, 1
            elif t == "\r":
                self.col = 1
            elif t in self.widths:
                self.col += self.widths[t]
            else:
                self.col += 1

    def run(self, timeout=15.0):
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            assert left > 0, self.log
            if not select.select([self.fd], [], [], left)[0]:
                continue
            try:
                chunk = os.read(self.fd, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            self.log += chunk
            self._feed(chunk.decode("utf-8", "replace"))
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
        return self.log.decode("utf-8", "replace")


def script_for(home, args, before="", pipe=False):
    cmd = f'"{real_bin()}" doctor {args} 2>/dev/null'
    if pipe:
        cmd += " | cat"
    return (f"echo BEFORE=$(stty -g); {before}{cmd}; rc=$?; echo; echo RC=$rc; "
            "echo AFTER=$(stty -g)")


def env_for(home, **extra):
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "cfg"),
           "XDG_STATE_HOME": str(home / "state"), "XDG_CACHE_HOME": str(home / "cache"),
           "XDG_RUNTIME_DIR": str(home / "run"), "TMPDIR": str(home / "tmp"),
           "PATH": os.environ["PATH"], "TERM": "xterm"}
    env.update(extra)
    return env


def result(text):
    before, after = (re.search(rf"{k}=(\S+)", text).group(1) for k in ("BEFORE", "AFTER"))
    code = int(re.search(r"RC=(\d+)", text).group(1))
    doc = None
    if '{"schema"' in text:
        doc, _ = json.JSONDecoder().raw_decode(text[text.index('{"schema"'):])
    return doc, code, before, after


def row(doc, id):
    return next(i for i in doc["items"] if i["id"] == id)


# 이것을 실패시키는 것: 시험 글자 뒤의 CPR 차이를 칸 수로 읽지 않는 것, 설정과 같은 터미널을 경고로 매기는 것, 밝기를
# 비교하지 않는 것, 터미널 모드를 복구하지 않는 것, 측정이 파일을 쓰는 것, 시험 글자 줄을 지우지 않는 것.
def test_a_terminal_that_matches_the_settings_is_ok_and_nothing_is_written(home):
    put_config(home, 'colors.mode = "auto"\n')
    before_files = snapshot(home)
    t = Terminal(script_for(home, "--terminal --format json"), env_for(home))
    doc, code, before, after = result(t.run())
    assert code == 0, t.log
    assert before == after, (before, after)
    width, background = row(doc, "terminal-width"), row(doc, "terminal-background")
    assert (width["status"], width["fix"]) == ("ok", None), width
    assert [p["cells"] for p in width["details"]["probes"]] == NORMAL
    assert [p["name"] for p in width["details"]["probes"]] == NAMES
    assert width["details"]["recommended"] == {"ambiguous": 1, "emoji": 2}
    assert width["details"]["inside_tmux"] is False
    assert (background["status"], background["fix"]) == ("ok", None), background
    assert background["details"] == {"terminal": "dark", "prompt": "dark", "colors_mode": "auto"}
    # The probe line is cleared once, before the background question.
    assert t.seen[t.seen.index("clear") + 1] == "osc11", t.seen
    assert t.seen.count("clear") == 1
    assert t.seen.count("cpr") == len(PROBES) + 1
    assert snapshot(home) == before_files, "doctor wrote a file"


# 이것을 실패시키는 것: 모호한 폭 글자가 두 칸인 터미널을 정상으로 매기는 것, 경고에서 W613이나 권장 값을 빼는 것.
def test_ambiguous_characters_that_take_two_cells_warn_with_the_fitting_widths(home):
    put_config(home, 'colors.mode = "dark"\n')
    t = Terminal(script_for(home, "--terminal --format json"), env_for(home), widths=AMBIGUOUS_WIDE)
    doc, code, before, after = result(t.run())
    assert code == 0 and before == after, t.log
    width = row(doc, "terminal-width")
    assert (width["status"], width["fix"]) == ("warn", "W613"), width
    assert width["details"]["recommended"]["ambiguous"] == 2
    assert "width.ambiguous = 2" in width["text"]


# 이것을 실패시키는 것: 터미널 배경이 밝은데 프롬프트가 어두운 쪽으로 그리는 것을 정상으로 매기는 것(W614이 없음),
# colors.mode가 auto가 아닌데 OSC 11을 묻는 것.
def test_a_light_terminal_warns_when_auto_and_asks_nothing_otherwise(home):
    put_config(home, 'colors.mode = "auto"\n')
    t = Terminal(script_for(home, "--terminal --format json"), env_for(home), background=LIGHT)
    doc, code, before, after = result(t.run())
    background = row(doc, "terminal-background")
    assert (background["status"], background["fix"]) == ("warn", "W614"), background
    assert background["details"]["terminal"] == "light" and background["details"]["prompt"] == "dark"
    assert before == after
    put_config(home, 'colors.mode = "dark"\n')
    t = Terminal(script_for(home, "--terminal --format json"), env_for(home), background=LIGHT)
    doc, code, before, after = result(t.run())
    assert row(doc, "terminal-background")["status"] == "skipped"
    assert "osc11" not in t.seen, t.seen


# 이것을 실패시키는 것: 응답이 없을 때 시간 제한 없이 기다리는 것, 침묵을 불일치 경고나 오류로 매기는 것, 침묵 뒤에도
# 계속 묻는 것, 침묵 뒤 터미널 모드를 복구하지 않는 것.
def test_a_silent_terminal_gives_unknown_within_the_deadlines(home):
    put_config(home, 'colors.mode = "auto"\n')
    t = Terminal(script_for(home, "--terminal --format json"), env_for(home), answer=False)
    started = time.monotonic()
    doc, code, before, after = result(t.run())
    assert time.monotonic() - started < 4.0
    assert code == 0 and before == after, t.log
    assert row(doc, "terminal-width")["status"] == "unknown"
    assert row(doc, "terminal-background")["status"] == "unknown"
    assert t.seen.count("cpr") == 1, "no question after the first silence"


# 이것을 실패시키는 것: 입력 줄에 반쯤 써 둔 글자 위에 시험 글자를 쓰는 것(1열이 아닐 때 줄바꿈 없이 시작).
def test_a_half_written_line_is_left_alone(home):
    put_config(home, 'colors.mode = "dark"\n')
    t = Terminal(script_for(home, "--terminal --format json", before="printf 'half-line'; "),
                 env_for(home))
    text = t.run()
    doc, code, before, after = result(text)
    assert code == 0 and before == after, text
    assert row(doc, "terminal-width")["status"] == "ok"
    # The first question finds the cursor at column 10, so a new line comes
    # before the first probe character.
    assert re.search(r"half-line\x1b\[6n\r+\n\x1b\[6na", text), text


# 이것을 실패시키는 것: 표준 출력이 터미널이 아닌데 묻는 것, `--terminal`이 /dev/tty로 묻지 않는 것.
def test_standard_output_that_is_not_a_terminal_asks_only_with_the_flag(home):
    put_config(home, 'colors.mode = "auto"\n')
    t = Terminal(script_for(home, "--format json", pipe=True), env_for(home))
    doc, code, before, after = result(t.run())
    assert row(doc, "terminal-width")["status"] == "skipped", doc
    assert row(doc, "terminal-background")["status"] == "skipped"
    assert t.seen == [], "no question without a terminal on standard output"
    t = Terminal(script_for(home, "--terminal --format json", pipe=True), env_for(home))
    doc, code, before, after = result(t.run())
    assert row(doc, "terminal-width")["status"] == "ok", doc
    assert "cpr" in t.seen and before == after


# 이것을 실패시키는 것: Ctrl-C를 취소로 처리하지 않는 것(종료 코드가 130이 아님), 취소 뒤 표를 내는 것, 취소 뒤 터미널을
# 복구하지 않는 것, 배경 질문으로 넘어가는 것.
def test_ctrl_c_during_a_question_ends_with_130_and_restores_the_terminal(home):
    put_config(home, 'colors.mode = "auto"\n')
    t = Terminal(script_for(home, "--terminal --format json"), env_for(home), cancel_on="cpr")
    doc, code, before, after = result(t.run())
    assert doc is None, "no table after a cancel"
    assert code == 130, t.log
    assert before == after
    assert "osc11" not in t.seen


# 이것을 실패시키는 것: 제어 터미널이 없는데(새 세션) `--terminal`이 터미널이 없다는 행 대신 오류나 실패를 내는 것,
# 터미널 없이 질문을 쓰는 것.
def test_no_controlling_terminal_is_a_skipped_row_even_with_the_flag(home):
    put_config(home, 'colors.mode = "auto"\n')
    detach = ("python3 -c 'import subprocess,sys;"
              "sys.exit(subprocess.run(sys.argv[1:],start_new_session=True).returncode)'")
    script = (f"echo BEFORE=$(stty -g); {detach} \"{real_bin()}\" doctor --terminal --format json 2>/dev/null;"
              " rc=$?; echo; echo RC=$rc; echo AFTER=$(stty -g)")
    t = Terminal(script, env_for(home))
    doc, code, before, after = result(t.run())
    assert code == 0 and before == after, t.log
    for id in ("terminal-width", "terminal-background"):
        assert row(doc, id)["status"] == "skipped", doc
        assert "no terminal to ask" in row(doc, id)["text"]
    assert t.seen == []


# 이것을 실패시키는 것: 질문 도중 SIGTERM에 터미널을 복구하지 않는 것(raw인 채 죽음), 신호를 삼켜 표를 계속 내는 것,
# 신호로 끝나는 대신 다른 종료 코드를 내는 것(셸이 보는 코드는 128 + 15).
def test_sigterm_during_a_question_restores_the_terminal_and_ends_by_the_signal(home):
    put_config(home, 'colors.mode = "auto"\n')
    script = (f"echo BEFORE=$(stty -g); \"{real_bin()}\" doctor --terminal --format json 2>/dev/null & "
              "echo BPID=$!; wait $!; rc=$?; echo; echo RC=$rc; echo AFTER=$(stty -g)")
    t = Terminal(script, env_for(home), cancel_on="sigterm")
    doc, code, before, after = result(t.run())
    assert doc is None, "no table after a signal"
    assert code == 128 + signal.SIGTERM, t.log
    assert before == after, (before, after)
    assert "osc11" not in t.seen
