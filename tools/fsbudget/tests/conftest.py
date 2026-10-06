import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

# CI sets this so that the Linux-only tests fail instead of skipping when
# strace or the synthetic binary is missing.
REQUIRE_STRACE = os.environ.get("FSB_REQUIRE_STRACE") == "1"
