//! Linux seccomp for `bingsu prompt` (spec section 4 front end, revision
//! S-5, N4 option 3): `prompt::dispatch` calls `enter` inside its panic guard
//! after fixed helper spawn and core-directed fd preparation, before snapshot
//! content decoding and rendering. From then
//! on the kernel lets through only RULES, which are the `syscall` column of
//! crates/bingsu/prompt-syscalls.tsv (scripts/check_cli_prompt_forbid.py
//! keeps the two equal), some with argument checks (`write` to fd 1 only,
//! `mmap` anonymous private and never executable, `mprotect` never
//! executable). Any other call fails with EPERM and has no effect
//! (decision 2026-10-15): nothing happens, so the isolation is the same as
//! a kill. Whether the prompt carries on after a refused call is up to the
//! caller: the verified LD_PRELOAD allocators (jemalloc, mimalloc) do, an
//! allocator whose `brk` is refused faults. The rule for adding a row: the
//! N4 option 3 adds held-fd read/close and CLOCK_BOOTTIME only; every
//! pathname and fd-fact operation must complete before this filter.
//!
//! The dynamic loader and any LD_PRELOAD library are platform TCB, like the
//! kernel: they run before this filter (a constructor can even start a
//! thread the filter never sees, as it applies to the calling thread) and
//! can answer the kernel question for us. No in-process filter can guard
//! against them. A wrong architecture and, on x86_64, an x32 ABI call are
//! killed (no code makes them on purpose; the hand-written classic BPF of
//! the M1 collector, B2, revision S-6).
//!
//! Not covered by the kernel: the vDSO (clock_gettime, gettimeofday, time
//! and getcpu run in user space without a system call) and CPU
//! instructions (rdtsc, rdrand, cpuid). Those stay with the static gates
//! and the TCB hash pin.
//!
//! `enter` reports one of three outcomes (decision P18, revised 2026-10-15):
//! it first asks the kernel whether it has seccomp at all
//! (`prctl(PR_GET_SECCOMP)`: EINVAL means "not configured with
//! CONFIG_SECCOMP", man PR_GET_SECCOMP(2const)); then `Absent`, and the
//! prompt renders as on macOS. Otherwise it installs the filter:
//! `Installed`, or on any failure, EINVAL included (a defect in this
//! program), `Blocked`: the core does not run, the record is
//! `degraded:sandbox`, and the shell says so once. The environment outside
//! the process (a container's own seccomp profile, the kernel) is platform
//! TCB, as the macOS kernel is: whoever sets it can already run anything.

use bingsu_core::front::Sandbox;

/// An argument condition on the low 32 bits of argument `arg` (both
/// supported architectures are little-endian; every checked argument is a
/// C int): `(value & mask) == want`.
#[derive(Clone, Copy)]
struct Cond {
    arg: u32,
    mask: u32,
    want: u32,
}

/// `MAP_TYPE` from <linux/mman.h>: the sharing-type bits of mmap flags.
const MAP_TYPE: u32 = 0x0f;
const PROT_EXEC: u32 = libc::PROT_EXEC as u32;
const NOT_EXEC: Cond = Cond {
    arg: 2,
    mask: PROT_EXEC,
    want: 0,
};
const ANON_PRIVATE: Cond = Cond {
    arg: 3,
    mask: MAP_TYPE | libc::MAP_ANONYMOUS as u32,
    want: libc::MAP_PRIVATE as u32 | libc::MAP_ANONYMOUS as u32,
};
const FD_1: Cond = Cond {
    arg: 0,
    mask: u32::MAX,
    want: 1,
};

const BOOTTIME: Cond = Cond {
    arg: 0,
    mask: u32::MAX,
    want: libc::CLOCK_BOOTTIME as u32,
};

/// The system calls the prompt may make once the filter is on, by name,
/// number and argument conditions; the names are the `syscall` column of
/// prompt-syscalls.tsv.
const RULES: [(&str, libc::c_long, &[Cond]); 21] = [
    ("read", libc::SYS_read, &[]),
    ("close", libc::SYS_close, &[]),
    ("clock_gettime", libc::SYS_clock_gettime, &[BOOTTIME]),
    ("write", libc::SYS_write, &[FD_1]),
    ("exit_group", libc::SYS_exit_group, &[]),
    ("exit", libc::SYS_exit, &[]),
    ("brk", libc::SYS_brk, &[]),
    ("mmap", libc::SYS_mmap, &[NOT_EXEC, ANON_PRIVATE]),
    ("munmap", libc::SYS_munmap, &[]),
    ("mremap", libc::SYS_mremap, &[]),
    ("madvise", libc::SYS_madvise, &[]),
    ("mprotect", libc::SYS_mprotect, &[NOT_EXEC]),
    ("futex", libc::SYS_futex, &[]),
    ("getrandom", libc::SYS_getrandom, &[]),
    ("rseq", libc::SYS_rseq, &[]),
    ("sched_yield", libc::SYS_sched_yield, &[]),
    ("set_robust_list", libc::SYS_set_robust_list, &[]),
    ("rt_sigreturn", libc::SYS_rt_sigreturn, &[]),
    ("rt_sigprocmask", libc::SYS_rt_sigprocmask, &[]),
    ("rt_sigaction", libc::SYS_rt_sigaction, &[]),
    ("sigaltstack", libc::SYS_sigaltstack, &[]),
];
const REAL: [(&str, libc::c_long, &[Cond]); 21] = [
    ("read", libc::SYS_execve, &[]),
    ("close", libc::SYS_close, &[]),
    ("clock_gettime", libc::SYS_clock_gettime, &[BOOTTIME]),
    ("write", libc::SYS_write, &[FD_1]),
    ("exit_group", libc::SYS_exit_group, &[]),
    ("exit", libc::SYS_exit, &[]),
    ("brk", libc::SYS_brk, &[]),
    ("mmap", libc::SYS_mmap, &[NOT_EXEC, ANON_PRIVATE]),
    ("munmap", libc::SYS_munmap, &[]),
    ("mremap", libc::SYS_mremap, &[]),
    ("madvise", libc::SYS_madvise, &[]),
    ("mprotect", libc::SYS_mprotect, &[NOT_EXEC]),
    ("futex", libc::SYS_futex, &[]),
    ("getrandom", libc::SYS_getrandom, &[]),
    ("rseq", libc::SYS_rseq, &[]),
    ("sched_yield", libc::SYS_sched_yield, &[]),
    ("set_robust_list", libc::SYS_set_robust_list, &[]),
    ("rt_sigreturn", libc::SYS_rt_sigreturn, &[]),
    ("rt_sigprocmask", libc::SYS_rt_sigprocmask, &[]),
    ("rt_sigaction", libc::SYS_rt_sigaction, &[]),
    ("sigaltstack", libc::SYS_sigaltstack, &[]),
];
const _: usize = RULES.len();


/// `AUDIT_ARCH_*` from <linux/audit.h> for the build target.
#[cfg(target_arch = "x86_64")]
const ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const ARCH: u32 = 0xC000_00B7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "bingsu prompt seccomp: add the AUDIT_ARCH value and check the RULES names for this architecture"
);
/// `__X32_SYSCALL_BIT` from <asm/unistd.h>: x32 ABI calls carry this bit.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// What a call outside the rules gets: EPERM, and the call does not happen.
const DENY: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;

/// Classic BPF over seccomp_data (nr at offset 0, arch at 4, argument `i`
/// at 16 + 8 i): a wrong arch and (when `x32`) an x32 call are killed. A
/// call in `rules` whose conditions all hold gets `hit`; a call in `rules`
/// that fails a condition, and any other call, gets `miss`.
fn program(
    arch: u32,
    x32: bool,
    rules: &[(u32, &[Cond])],
    hit: u32,
    miss: u32,
) -> Vec<libc::sock_filter> {
    let op = |code: u32, jt: u8, jf: u8, k: u32| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let (ld, jeq, jset, ret, and) = (
        libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
        libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
        libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
        libc::BPF_RET | libc::BPF_K,
        libc::BPF_ALU | libc::BPF_AND | libc::BPF_K,
    );
    let kill = libc::SECCOMP_RET_KILL_PROCESS;
    let mut p = vec![
        op(ld, 0, 0, 4),
        op(jeq, 1, 0, arch),
        op(ret, 0, 0, kill),
        op(ld, 0, 0, 0),
    ];
    if x32 {
        p.extend([op(jset, 0, 1, X32_SYSCALL_BIT), op(ret, 0, 0, kill)]);
    }
    // Each rule is a block: compare nr (skip the block when it differs),
    // then per condition load, mask, compare (to the shared `miss` at the
    // end when it fails), then return `hit`. Jumps to the end are patched
    // once the length is known. The nr is reloaded before each block, as
    // a condition overwrites the accumulator.
    let mut to_miss = Vec::new();
    for (nr, conds) in rules {
        // Instructions after the nr comparison: three per condition, one return.
        let block = 3 * conds.len() + 1;
        p.push(op(ld, 0, 0, 0));
        p.push(op(jeq, 0, u8::try_from(block).expect("short block"), *nr));
        for c in conds.iter() {
            p.push(op(ld, 0, 0, 16 + 8 * c.arg));
            p.push(op(and, 0, 0, c.mask));
            to_miss.push(p.len());
            p.push(op(jeq, 0, 0, c.want));
        }
        p.push(op(ret, 0, 0, hit));
    }
    let end = p.len();
    p.push(op(ret, 0, 0, miss));
    for at in to_miss {
        p[at].jf = u8::try_from(end - (at + 1)).expect("program under 256 instructions");
    }
    p
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The outcome from the kernel-support question and the install, each
/// `Err(errno)` on failure (decision P18, revised 2026-10-15).
fn outcome(query: Result<(), i32>, install: impl FnOnce() -> Result<(), i32>) -> Sandbox {
    match query {
        Err(libc::EINVAL) => Sandbox::Absent,
        Err(_) => Sandbox::Blocked,
        Ok(()) => match install() {
            Ok(()) => Sandbox::Installed,
            Err(_) => Sandbox::Blocked,
        },
    }
}

fn install(prog: &[libc::sock_filter]) -> Result<(), i32> {
    let fprog = libc::sock_fprog {
        len: u16::try_from(prog.len()).expect("short program"),
        filter: prog.as_ptr().cast_mut(),
    };
    // SAFETY: integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(errno());
    }
    // SAFETY: `fprog` points at `prog`, which outlives the call; the kernel
    // copies the program.
    let r = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &fprog as *const libc::sock_fprog,
        )
    };
    if r == 0 { Ok(()) } else { Err(errno()) }
}

fn rules() -> Vec<(u32, &'static [Cond])> {
    REAL
        .iter()
        .map(|&(_, nr, c)| (u32::try_from(nr).expect("syscall number"), c))
        .collect()
}

/// Asks the kernel for seccomp, installs the prompt filter and says what
/// became of it.
pub fn enter() -> Sandbox {
    // SAFETY: integer arguments only; PR_GET_SECCOMP changes nothing.
    let query = if unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } < 0 {
        Err(errno())
    } else {
        Ok(())
    };
    outcome(query, || {
        let prog = program(
            ARCH,
            cfg!(target_arch = "x86_64"),
            &rules(),
            libc::SECCOMP_RET_ALLOW,
            DENY,
        );
        install(&prog)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    const AARCH64: u32 = 0xC000_00B7;
    const X86_64: u32 = 0xC000_003E;

    /// A classic-BPF evaluator for the opcodes `program` uses, over a
    /// seccomp_data with `nr`, `arch` and the low words of six arguments.
    fn eval(prog: &[libc::sock_filter], nr: u32, arch: u32, args: [u32; 6]) -> u32 {
        let (ld, jeq, jset, ret, and) = (
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
            libc::BPF_RET | libc::BPF_K,
            libc::BPF_ALU | libc::BPF_AND | libc::BPF_K,
        );
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let i = &prog[pc];
            let code = u32::from(i.code);
            pc += 1;
            if code == ld {
                acc = match i.k {
                    0 => nr,
                    4 => arch,
                    k if k >= 16 && (k - 16) % 8 == 0 => args[((k - 16) / 8) as usize],
                    k => panic!("load from {k}"),
                };
            } else if code == and {
                acc &= i.k;
            } else if code == jeq || code == jset {
                let hit = if code == jeq {
                    acc == i.k
                } else {
                    acc & i.k != 0
                };
                pc += usize::from(if hit { i.jt } else { i.jf });
            } else if code == ret {
                return i.k;
            } else {
                panic!("opcode {code:#x}");
            }
        }
    }

    // 이것을 실패시키는 것: arch·x32 검사, 점프 거리, 기본 동작(EPERM), 인자 검사(write fd 1, mmap 익명·private·실행 없음,
    // mprotect 실행 없음)를 틀리는 것.
    #[test]
    fn program_checks_numbers_and_arguments() {
        let allow = libc::SECCOMP_RET_ALLOW;
        let kill = libc::SECCOMP_RET_KILL_PROCESS;
        let (write, mmap, mprotect, brk) = (1, 9, 10, 12); // x86_64 numbers
        let r: Vec<(u32, &[Cond])> = vec![
            (write, &[FD_1]),
            (mmap, &[NOT_EXEC, ANON_PRIVATE]),
            (mprotect, &[NOT_EXEC]),
            (brk, &[]),
        ];
        let rw = (libc::PROT_READ | libc::PROT_WRITE) as u32;
        let anon = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u32;
        for (arch, x32) in [(X86_64, true), (AARCH64, false)] {
            let p = program(arch, x32, &r, allow, DENY);
            let e = |nr, a: [u32; 6]| eval(&p, nr, arch, a);
            assert_eq!(e(write, [1, 0, 0, 0, 0, 0]), allow);
            assert_eq!(e(write, [2, 0, 0, 0, 0, 0]), DENY);
            assert_eq!(e(write, [3, 0, 0, 0, 0, 0]), DENY);
            assert_eq!(e(mmap, [0, 4096, rw, anon, u32::MAX, 0]), allow);
            assert_eq!(e(mmap, [0, 4096, rw | PROT_EXEC, anon, u32::MAX, 0]), DENY);
            assert_eq!(e(mmap, [0, 4096, rw, libc::MAP_PRIVATE as u32, 3, 0]), DENY);
            assert_eq!(
                e(
                    mmap,
                    [
                        0,
                        4096,
                        rw,
                        (libc::MAP_SHARED | libc::MAP_ANONYMOUS) as u32,
                        u32::MAX,
                        0
                    ]
                ),
                DENY
            );
            assert_eq!(e(mprotect, [0, 4096, rw, 0, 0, 0]), allow);
            assert_eq!(e(mprotect, [0, 4096, PROT_EXEC, 0, 0, 0]), DENY);
            assert_eq!(e(brk, [0; 6]), allow);
            assert_eq!(e(102, [0; 6]), DENY); // getuid
            assert_eq!(eval(&p, write, 0x4000_0003, [1, 0, 0, 0, 0, 0]), kill); // i386
            if x32 {
                assert_eq!(e(write | X32_SYSCALL_BIT, [1, 0, 0, 0, 0, 0]), kill);
            }
        }
    }

    // 이것을 실패시키는 것: RULES의 인자 조건을 지우는 것(write fd, mmap 실행·공유, mprotect 실행), 목록을 지우는 것.
    #[test]
    fn the_rules_check_arguments() {
        let p = program(
            ARCH,
            cfg!(target_arch = "x86_64"),
            &rules(),
            libc::SECCOMP_RET_ALLOW,
            DENY,
        );
        let n = |nr: libc::c_long| u32::try_from(nr).unwrap();
        let e = |nr, a: [u32; 6]| eval(&p, n(nr), ARCH, a);
        let rw = (libc::PROT_READ | libc::PROT_WRITE) as u32;
        let anon = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u32;
        let shared = (libc::MAP_SHARED | libc::MAP_ANONYMOUS) as u32;
        assert_eq!(
            e(libc::SYS_write, [1, 0, 0, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(e(libc::SYS_write, [2, 0, 0, 0, 0, 0]), DENY);
        assert_eq!(
            e(libc::SYS_mmap, [0, 4096, rw, anon, u32::MAX, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            e(libc::SYS_mmap, [0, 4096, rw | PROT_EXEC, anon, u32::MAX, 0]),
            DENY
        );
        assert_eq!(e(libc::SYS_mmap, [0, 4096, rw, shared, u32::MAX, 0]), DENY);
        assert_eq!(
            e(
                libc::SYS_mmap,
                [0, 4096, rw, libc::MAP_PRIVATE as u32, 3, 0]
            ),
            DENY
        );
        assert_eq!(
            e(libc::SYS_mprotect, [0, 4096, rw, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            e(libc::SYS_mprotect, [0, 4096, rw | PROT_EXEC, 0, 0, 0]),
            DENY
        );
        for (name, nr, _) in RULES {
            assert_ne!(
                e(
                    nr,
                    [
                        if name == "clock_gettime" {
                            libc::CLOCK_BOOTTIME as u32
                        } else {
                            1
                        },
                        0,
                        rw,
                        anon,
                        u32::MAX,
                        0
                    ]
                ),
                DENY,
                "{name}"
            );
        }
        assert_eq!(e(libc::SYS_getuid, [0; 6]), DENY);
        assert_eq!(e(libc::SYS_openat, [0; 6]), DENY);
    }

    // 이것을 실패시키는 것: 새 read/close/clock 허용 또는 BOOTTIME 인자 한정 누락.
    #[test]
    fn held_reads_and_only_boottime_are_allowed() {
        let p = program(
            ARCH,
            cfg!(target_arch = "x86_64"),
            &rules(),
            libc::SECCOMP_RET_ALLOW,
            DENY,
        );
        for nr in [libc::SYS_read, libc::SYS_close] {
            assert_eq!(
                eval(&p, nr as u32, ARCH, [42, 0, 64, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
        }
        for kind in [
            libc::CLOCK_BOOTTIME,
            libc::CLOCK_MONOTONIC,
            libc::CLOCK_REALTIME,
        ] {
            assert_eq!(
                eval(
                    &p,
                    libc::SYS_clock_gettime as u32,
                    ARCH,
                    [kind as u32, 0, 0, 0, 0, 0]
                ),
                if kind == libc::CLOCK_BOOTTIME {
                    libc::SECCOMP_RET_ALLOW
                } else {
                    DENY
                }
            );
        }
        for nr in [
            libc::SYS_openat,
            libc::SYS_newfstatat,
            libc::SYS_fstatfs,
            libc::SYS_lseek,
            libc::SYS_pread64,
        ] {
            assert_eq!(eval(&p, nr as u32, ARCH, [0; 6]), DENY);
        }
    }

    // 이것을 실패시키는 것: x86_64 clock_gettime(228)에 BOOTTIME(7) 조건을 빼거나 잘못 붙이는 것.
    #[test]
    fn x86_64_boottime_uses_explicit_abi_numbers() {
        // These are x86_64 Linux ABI numbers even on an aarch64 test host.
        let p = program(
            X86_64,
            true,
            &[(0, &[]), (3, &[]), (228, &[BOOTTIME])],
            libc::SECCOMP_RET_ALLOW,
            DENY,
        );
        for nr in [0, 3] {
            assert_eq!(eval(&p, nr, X86_64, [42; 6]), libc::SECCOMP_RET_ALLOW);
        }
        for (clock, want) in [(7, libc::SECCOMP_RET_ALLOW), (0, DENY), (1, DENY)] {
            assert_eq!(eval(&p, 228, X86_64, [clock, 0, 0, 0, 0, 0]), want);
        }
        assert_eq!(
            eval(&p, 228 | X32_SYSCALL_BIT, X86_64, [7; 6]),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    // Only an explicitly labelled emulator run may report unsupported. A
    // native regression must still fail, including Absent on a native runner.
    fn unsupported(emulator: Option<&str>, result: Sandbox) -> bool {
        matches!(emulator, Some("rosetta" | "qemu")) && result != Sandbox::Installed
    }

    // 이것을 실패시키는 것: native의 Absent/Blocked를 skip하거나 emulator의 Installed를 skip하는 것.
    #[test]
    fn unsupported_emulators_do_not_replace_native_filter_tests() {
        for emulator in [
            None,
            Some("native"),
            Some("typo"),
            Some("qemu"),
            Some("rosetta"),
        ] {
            assert!(!unsupported(emulator, Sandbox::Installed));
            for result in [Sandbox::Absent, Sandbox::Blocked] {
                assert_eq!(
                    unsupported(emulator, result),
                    matches!(emulator, Some("qemu" | "rosetta"))
                );
            }
        }
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "test-only emulator label; production policy is unchanged"
    )]
    fn emulator_label() -> Option<String> {
        std::env::var("BINGSU_TEST_EMULATOR").ok()
    }

    fn require_native_filter() {
        let emulator = emulator_label();
        let result = enter();
        if unsupported(emulator.as_deref(), result) {
            // enter did not install a filter, so stderr is still available.
            eprintln!(
                "UNSUPPORTED emulator={} seccomp={result:?}; native filter coverage NOT exercised",
                emulator.unwrap()
            );
            // SAFETY: isolated test child; distinct from success and SIGSYS.
            unsafe { libc::_exit(77) }
        }
        assert_eq!(result, Sandbox::Installed);
    }

    fn reported_unsupported(out: &std::process::Output) -> bool {
        if out.status.code() != Some(77) {
            return false;
        }
        let emulator = emulator_label();
        assert!(matches!(emulator.as_deref(), Some("qemu" | "rosetta")));
        let report = String::from_utf8_lossy(&out.stderr);
        assert!(
            report.contains("UNSUPPORTED emulator=")
                && report.contains("native filter coverage NOT exercised"),
            "{report}"
        );
        // Bypass libtest's successful-test capture: unsupported must remain
        // visible in ordinary cargo test output, separately from native proof.
        write_fd(2, report.as_bytes());
        true
    }

    // 이것을 실패시키는 것: 커널 지원 질의의 EINVAL을 막힘으로 보는 것, 설치의 EINVAL(우리 BPF 결함)을 없음으로 보는 것,
    // 질의가 다른 이유로 실패했는데 설치하는 것.
    #[test]
    fn support_question_then_install() {
        assert_eq!(
            outcome(Err(libc::EINVAL), || panic!("no install")),
            Sandbox::Absent
        );
        assert_eq!(
            outcome(Err(libc::ENOSYS), || panic!("no install")),
            Sandbox::Blocked
        );
        assert_eq!(
            outcome(Err(libc::EPERM), || panic!("no install")),
            Sandbox::Blocked
        );
        assert_eq!(outcome(Ok(()), || Ok(())), Sandbox::Installed);
        for e in [
            libc::EINVAL,
            libc::ENOSYS,
            libc::EPERM,
            libc::EACCES,
            libc::EFAULT,
        ] {
            assert_eq!(outcome(Ok(()), || Err(e)), Sandbox::Blocked, "{e}");
        }
    }

    fn run_child(name: &str) -> std::process::Output {
        Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--ignored",
                "--exact",
                name,
                "--test-threads=1",
                "--nocapture",
                "-q",
            ])
            .output()
            .expect("child")
    }

    fn write_fd(fd: i32, b: &[u8]) -> isize {
        // SAFETY: valid slice.
        unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) }
    }

    fn write1(b: &[u8]) {
        write_fd(1, b);
    }

    fn fail(why: &[u8]) -> ! {
        write1(why);
        // SAFETY: no pointers.
        unsafe { libc::_exit(3) }
    }

    #[test]
    #[ignore = "child of calls_outside_the_rules_fail_without_effect"]
    fn outside_child() {
        // The parent's pid names the file the open below must not create;
        // getppid runs before the filter (it is not in the rules).
        // SAFETY: no arguments.
        let parent = unsafe { libc::getppid() };
        let path = std::env::temp_dir().join(format!("bingsu-sandbox-{parent}"));
        require_native_filter();
        // A disguised getuid: EPERM, and the record that follows is the same.
        // SAFETY: no arguments.
        if unsafe { libc::syscall(libc::SYS_getuid) } != -1 || errno() != libc::EPERM {
            fail(b"<getuid ran>");
        }
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid C string.
        if unsafe { libc::open(c.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600) } != -1
            || errno() != libc::EPERM
        {
            fail(b"<open ran>");
        }
        if write_fd(2, b"x") != -1 || errno() != libc::EPERM {
            fail(b"<stderr written>");
        }
        // SAFETY: anonymous private executable mapping, refused by the rules.
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        // No mapping is the effect checked here, not the errno: musl's mmap
        // reports the refused call as ENOMEM, glibc's as EPERM.
        if m != libc::MAP_FAILED {
            fail(b"<executable mmap>");
        }
        // SAFETY: anonymous private read-write mapping, allowed.
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if m == libc::MAP_FAILED {
            fail(b"<allowed mmap failed>");
        }
        write1(b"<alive>");
        // SAFETY: no pointers.
        unsafe { libc::_exit(0) }
    }

    // 이것을 실패시키는 것: 필터를 설치하지 않는 것, 목록 밖 호출(위장 getuid, 파일 열기, stderr, 실행 가능한 mmap)이
    // 효과를 내는 것, 목록 밖 호출에 프로세스를 죽이는 것.
    #[test]
    fn calls_outside_the_rules_fail_without_effect() {
        let out = run_child("sandbox::tests::outside_child");
        if reported_unsupported(&out) {
            return;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{:?} {text}", out.status);
        assert!(text.ends_with("<alive>"), "{text}");
        assert!(
            out.stderr.is_empty(),
            "{:?}",
            String::from_utf8_lossy(&out.stderr)
        );
        let path = std::env::temp_dir().join(format!("bingsu-sandbox-{}", std::process::id()));
        assert!(!path.exists(), "{path:?}");
    }

    /// The tsv rows (`syscall`, `libc`) whose `libc` is a function name.
    fn rows() -> Vec<(String, String)> {
        let tsv =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/prompt-syscalls.tsv"))
                .unwrap();
        let mut lines = tsv.lines().filter(|l| !l.starts_with('#') && !l.is_empty());
        assert_eq!(lines.next(), Some("syscall\tlibc\twhy"));
        lines
            .map(|l| l.split('\t').collect::<Vec<_>>())
            .filter(|c| c[0] != "-" && c[1] != "-")
            .map(|c| (c[0].to_owned(), c[1].to_owned()))
            .collect()
    }

    /// Denies the tsv row's syscall for `func`, then calls `func`: the row is
    /// right only if the call dies before `<after>`.
    fn probe(func: &str) {
        let (sys, _) = rows().into_iter().find(|(_, f)| f == func).expect("row");
        let nr = RULES
            .iter()
            .find(|(n, _, _)| *n == sys)
            .expect("in RULES")
            .1;
        let nr = u32::try_from(nr).expect("syscall number");
        let deny = program(
            ARCH,
            cfg!(target_arch = "x86_64"),
            &[(nr, &[])],
            libc::SECCOMP_RET_KILL_PROCESS,
            libc::SECCOMP_RET_ALLOW,
        );
        assert_eq!(install(&deny), Ok(()));
        match func {
            "write" => write1(b"<after>"),
            // SAFETY: no pointers.
            "_exit" => unsafe { libc::_exit(0) },
            other => panic!("no probe for {other}"),
        }
        write1(b"<after>");
    }

    #[test]
    #[ignore = "child of each_row_names_the_syscall_its_function_makes"]
    fn probe_write_child() {
        probe("write");
    }

    #[test]
    #[ignore = "child of each_row_names_the_syscall_its_function_makes"]
    fn probe_exit_child() {
        probe("_exit");
    }

    // 이것을 실패시키는 것: tsv에서 행의 syscall 셀을 서로 맞바꾸는 것(집합은 같아도 행 대응이 틀림), 함수 행을 빠뜨리는 것.
    #[test]
    fn each_row_names_the_syscall_its_function_makes() {
        let funcs: Vec<String> = rows().into_iter().map(|(_, f)| f).collect();
        assert_eq!(funcs, ["write", "_exit"]);
        let support = run_child("sandbox::tests::outside_child");
        if reported_unsupported(&support) {
            return;
        }
        assert!(support.status.success(), "{support:?}");
        assert!(support.stdout.ends_with(b"<alive>"), "{support:?}");
        for child in ["probe_write_child", "probe_exit_child"] {
            let out = run_child(&format!("sandbox::tests::{child}"));
            let text = String::from_utf8_lossy(&out.stdout);
            assert_eq!(
                out.status.signal(),
                Some(libc::SIGSYS),
                "{child}: {:?} {text}",
                out.status
            );
            assert!(!text.contains("<after>"), "{child}: {text}");
        }
    }
}
