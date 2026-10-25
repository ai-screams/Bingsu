# Protected Git collection corpus

Run `python3 scripts/prepare_git_corpus.py` on the host, then run
`tests/shell/test_git_collection_security.py` with
`BINGSU_GIT_CORPUS_REQUIRED=1`. Shell tests never build fixtures. Preparation
copies the collector sources into `target/git-corpus`, adds observation hooks
and a fixed test catalog, and keeps the product protection and collection
implementation. Semantic tests inject generous stage deadlines. Only the
dedicated elapsed-time test uses the product's 50 ms deadline.

The Git oracle is an isolated, safely normalized copy. It runs
`git --no-optional-locks status --porcelain=v2 --untracked-files=all
--ignore-submodules=all` with rename detection disabled. Git never runs on
armed configurations. Filter and text/eol paths explicitly assert size/mtime
approximation, `filtered`, `partial`, and `~`, including `!0~`. Unsupported
split-index, unknown global excludes, include uncertainty, case collisions,
and no-follow embedded `.git` links have separate asserted expectations.

U7 counts untracked files individually. The 2- and 255-file fixtures require
exact Git counts. The 256-file fixture alone uses the explicit manifest policy
`untracked-cap-boundary`: an index-free subtree reaching the cap reports cap+
even when Git's count equals the cap, because EOF remains unproven (#131;
`crates/bingsu-collect/tests/git_status_untracked.rs::untracked_subtree_cap_boundary`).
It requires exactly `(256, saturated)`, display `?256+`, and `partial=true`.
The 257- and 1,024-file fixtures retain their saturated positive lower bound
no larger than Git's full count, `N+`, and partial. All four boundary fixtures
also require independently known staged and modified counts. Empty directories
count zero; valid embedded repositories count one.

All corpus cases compare the real collector result with the policy oracle.
The five nonempty untracked-directory cases also run as individual U7 boundary
tests, and CI requires each to pass on Linux and macOS.

Each independent canary has read, spawn, and write negative controls. Each
policy case has wrong-result controls applied to a verified collector baseline;
baseline mismatches fail without synthetic repair. The cap-boundary controls
independently reject exact 256, a saturated number other than 256, non-partial,
and a missing display plus marker. Warm measurements record
200 release runs per case and phase timestamps without tracing; the first
sample is not a cold-cache claim.
This is a collector observation, not an alternating main/PR performance
certification or a measurement of the helper/front end.

Conservative decisions: do not widen the product mask, syscall tables, path
capabilities, or purity rules to make a corpus case pass. Do not turn new
oracle mismatches into expected failures. Linux runtime evidence
requires a native Linux host and strace; portable trace-model tests and macOS
interposition are not substitutes for it.
