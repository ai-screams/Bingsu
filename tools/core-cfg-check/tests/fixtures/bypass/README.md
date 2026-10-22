# Gate bypass fixtures

| Fixture | Gate rule | Bypass shape | Expected verdict |
| --- | --- | --- | --- |
| `identity/worker.rs` | Identity isolation | A cfg-hidden worker module imports Git through the shared identity library. | Reject, even with updated TCB hash pins. |
| `k24/decoy.rs` | K24 | A matching decoy `RULES` table hides extra syscall paths and a different rule consumer. | Reject, even with updated TCB hash pins. |
| `k24/literal.rs` | K24 | `enter()` appends literal syscall number 59 to the table. | Reject, even with updated TCB hash pins. |
| `k24/alias.rs` | K24 | A renamed libc import supplies an extra syscall to `enter()`. | Reject, even with updated TCB hash pins. |
| `k24/miss_allow.rs` | K24 | `enter()` allows calls that miss the table. | Reject, even with updated TCB hash pins. |
| `k68/bin/src/prompt_io.rs` | K68 | A conditional out-of-line module can hide code from the token scan. | Reject, even with updated TCB hash pins. |
| `k68/bin/src/prompt_io/evil.rs` | K68 | The external module reads the environment through `std::env::var`. | Reject the forbidden token. |
| `wt/crates/bingsu-core/src/zz.rs` | K03, K04 | Closure and constructor merges create function pointers; raw borrows permit pointer identity checks. | Reject each isolated bypass. |
| `wt/crates/bingsu-core/src/zz2.rs` | K03 | Tuple and struct fields hide closures from branch and array merge checks. | Reject each isolated bypass. |
| `fx/k03_tuple_struct.rs` | K03 | A tuple-struct constructor is passed as a callback. | Reject the function item. |
| `fx/k03_upper_fn_import.rs` | K03 | An uppercase imported function is passed as a callback. | Reject the function item. |
| `k83/shadow2.rs` | K83 | A second `raw` binding replaces the collected arguments with an empty slice. | Reject, even with updated TCB hash pins. |
| `k83/shadow_dl.rs` | K83 | A second `deadline` binding shadows the validated deadline. | Reject, even with updated TCB hash pins. |
| `k83/init.rs` | K83 | The sole `raw` initializer discards the incoming arguments. | Reject, even with updated TCB hash pins. |
