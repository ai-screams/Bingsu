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

## Timed valid-marker captures

`prompt-m3d-front-silent-valid-linux.strace.gz` and
`prompt-m3d-marker-valid-linux.strace.gz` are valid-marker captures of the same
test, captured on 2026-10-31 in the same container and builds at `81e7095` with
the change that added them, with `-ttt` times:

```text
strace -f -q -y -s 65536 -e trace=all -ttt -o TRACE <pinned prompt argv>
```

- silent-valid (run 18 of 40): the front armed
  `it_value={tv_sec=0, tv_usec=49105}`, took no SIGALRM, installed no filter,
  wrote nothing and exited 0 with empty stdout. Its exit_group line is 62 µs
  before the setitimer start plus it_value, so the times do not prove its
  deadline.
- valid (run 1 of 40): an ordinary capture with its filter and its record
  write.

Reduction as above, except that buffers starting with `BNG` (the product's
binary formats, which the trace judgment decodes) are kept whole.

| Form | silent-valid SHA-256 | Bytes | valid SHA-256 | Bytes |
| -- | -- | --: | -- | --: |
| original | `86148c48b80d0c224a587ab832b8fa7e112b78e70490e62363eef0d777ded40c` | 4,133,475 | `ecd756d57b2cd0fac75ee7646eba8a7443f501d8ade26e329e3c287cc986f8a5` | 4,184,615 |
| reduced | `2df69e32dc23f026a746b3345676839007b2b324a808cfa8254c9bd3151e023b` | 952,911 | `efd968f1e793e2b4ee73b8bb29e68612503fc771f633c97f3fb3d632646cb473` | 1,002,831 |
| gzip | `4452caefc279384d9054cb3bff623070e66b012e88cd022e72fe425325c8168e` | 62,865 | `0eb9eb0e81a49922ddf6b2bc6f1b194d015e0b8fed5104b02870c20b8376e0c7` | 65,922 |
