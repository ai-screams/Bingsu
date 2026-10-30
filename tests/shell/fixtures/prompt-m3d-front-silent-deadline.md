# Silent front exit trace provenance

`prompt-m3d-front-silent-deadline-linux.strace.gz` is the invalid-marker
capture of one run of
`test_prompt_env_paths.py::test_live_collector_count_ignores_marker_validity`
that ended with an empty record. It was captured on 2026-10-30 in a
`rust:1.98-slim-bookworm` container, as the non-root `tester` user, on Debian
bookworm / glibc / aarch64, with release builds
(`cargo build --release -p bingsu -p bingsu-collect`). The checkout was
`c2e5bc8` with the change that first retried this test's proven deadlines;
the capture had no `-ttt` time column yet:

```text
strace -f -q -y -s 65536 -e trace=all -o TRACE <pinned prompt argv>
```

The front armed `setitimer(ITIMER_REAL, … it_value={tv_sec=0, tv_usec=49713} …) = 0`,
spawned the helper, took no SIGALRM, made no write to fd 1 and exited 0.
Without a time column nothing in the trace proves its deadline passed, so the
marker test does not retry it.

Reduction: in records of `read`, `pread64`, `write` and `pwrite64` (and
resumed `read`/`pread64` records), the first quoted data buffer longer than 120
characters is cut to its first 120 characters in strace's own truncation form
(`"…"...`), never inside an escape. No record was added, removed or reordered; return values and fd
annotations are unchanged. The file is gzip-compressed (`gzip -n -9`).

| Form | SHA-256 | Bytes / records |
| -- | -- | --: |
| original | `6ee61bdbf339b50a959a1ea59122cb7ed29e0063565c122c958bb4bc2aa3a421` | 4,050,201 / 4,812 |
| reduced | `fec18b40e9f44e7ea3010ac4d28ef36984f20f439e854556edf644ab89b68a68` | 801,781 / 4,812 |
| gzip | `2136555a334248a065547b1df529738d7178b18aa7b4db566713ec3873f1655c` | 39,378 |
