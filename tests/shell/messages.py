"""The fixed messages of `bingsu`, read from the table the program reads
(`crates/bingsu/src/commands/messages.rs`, the `EN` table), so a test names
a message by its id and does not repeat its words. The words themselves are
pinned in one place, the Rust test `every_message_is_pinned_in_full`."""
import re

from conftest import ROOT

_TABLE = None


def table():
    global _TABLE
    if _TABLE is None:
        text = (ROOT / "crates/bingsu/src/commands/messages.rs").read_text().replace("\r\n", "\n")
        block = text[text.index("const EN"):text.index("pub fn en(")]
        found = re.findall(r'\(\s*MsgId::(\w+),\s*"((?:[^"\\]|\\.)*)",?\s*\)', block)
        _TABLE = {name: words.replace('\\"', '"').replace("\\\\", "\\") for name, words in found}
        assert len(_TABLE) == len(found) and found, "the message table was not read"
    return _TABLE


def msg(name):
    """The words of `MsgId::<name>`."""
    return table()[name]
