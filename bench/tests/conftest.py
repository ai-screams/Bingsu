import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]

# CI sets FSB_REQUIRE_STRACE=1 so that a missing strace or release binary
# fails the read-count test instead of skipping it (as in tools/fsbudget).
REQUIRE_STRACE = os.environ.get("FSB_REQUIRE_STRACE") == "1"

# The shells the writer-order demo runs in. Same name and default as
# tests/shell: every listed shell must be installed, a missing one fails.
SHELLS = os.environ.get("BINGSU_TEST_SHELLS", "zsh bash fish").split()
