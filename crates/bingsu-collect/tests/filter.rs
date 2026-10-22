//! Both syscall ABIs are evaluated on every host. Kernel probes are isolated.
#[allow(dead_code)]
#[path = "../src/filter.rs"]
mod filter;
#[allow(dead_code)]
#[path = "../src/landlock.rs"]
mod landlock;
use filter as policy;
use policy::{ALLOW, AuditArch, DENY, ENOSYS, Instruction, KILL};

const ARCHES: [AuditArch; 2] = [AuditArch::X86_64, AuditArch::Aarch64];
fn eval(p: &[Instruction], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
    let mut pc = 0;
    let mut a = 0;
    for _ in 0..p.len() {
        let i = &p[pc];
        pc += 1;
        match i.code {
            0x20 => {
                a = match i.k {
                    0 => nr,
                    4 => arch,
                    n @ 16..=60 if n % 4 == 0 => {
                        let arg = args[((n - 16) / 8) as usize];
                        if n % 8 == 0 {
                            arg as u32
                        } else {
                            (arg >> 32) as u32
                        }
                    }
                    _ => panic!("invalid seccomp_data load"),
                }
            }
            0x54 => a &= i.k,
            0x05 => pc += i.k as usize,
            0x15 | 0x25 | 0x35 | 0x45 => {
                let yes = match i.code {
                    0x15 => a == i.k,
                    0x25 => a > i.k,
                    0x35 => a >= i.k,
                    _ => a & i.k != 0,
                };
                pc += usize::from(if yes { i.jt } else { i.jf });
            }
            0x06 => return i.k,
            _ => panic!("unsupported classic BPF opcode"),
        }
        assert!(pc < p.len(), "jump outside program");
    }
    panic!("no terminating return")
}
fn nr(arch: AuditArch, name: &str) -> u32 {
    policy::rows(arch)
        .iter()
        .find(|r| r.name == name)
        .unwrap()
        .nr
}
fn verdict(arch: AuditArch, name: &str, args: [u64; 6]) -> u32 {
    eval(
        &policy::program(arch, filter::Openat2Policy::Deny),
        arch.value(),
        nr(arch, name),
        args,
    )
}
fn positive(condition: &str) -> [u64; 6] {
    let mut a = [0; 6];
    match condition {
        "any" | "enosys" | "query" | "open" | "openat" | "read_root" | "read_layer_restrict" => {}
        "handled_write_set" => a[3] = 24,
        "readonly" => {
            a[2] = 2;
            a[3] = 0x200;
        }
        "read_layer_create" => a[2] = 1,
        "read_layer_add" => a[1] = 1,
        "response" => a[0] = 1,
        "thread" => a[0] = 0x10900,
        "mapping" => {
            a[2] = 3;
            a[3] = 0x22;
        }
        "protect" => a[2] = 3,
        "fcntl" => a[1] = 1,
        "clock" => a[0] = 1,
        "nnp_query" => a[0] = 39,
        "bootstrap_as" => {
            a[1] = 9;
            a[2] = 1;
        }
        "bootstrap_filter" => a[0] = 1,
        _ => panic!("missing probe for {condition}"),
    }
    a
}
// 이것을 실패시키는 것: 표 행 삭제·이름은 같지만 번호 변경·빈 근거·probe 중복.
#[test]
fn table_program_and_row_removal_probes_agree() {
    // Independent Linux UAPI number oracle, deliberately not derived from TSV.
    let expected = [
        ("read", 0, Some(63)),
        ("write", 1, Some(64)),
        ("open", 2, None),
        ("close", 3, Some(57)),
        ("stat", 4, None),
        ("fstat", 5, Some(80)),
        ("lstat", 6, None),
        ("lseek", 8, Some(62)),
        ("mmap", 9, Some(222)),
        ("mprotect", 10, Some(226)),
        ("munmap", 11, Some(215)),
        ("brk", 12, Some(214)),
        ("rt_sigaction", 13, Some(134)),
        ("rt_sigprocmask", 14, Some(135)),
        ("rt_sigreturn", 15, Some(139)),
        ("pread64", 17, Some(67)),
        ("sched_yield", 24, Some(124)),
        ("mremap", 25, Some(216)),
        ("madvise", 28, Some(233)),
        ("getpid", 39, Some(172)),
        ("clone", 56, Some(220)),
        ("exit", 60, Some(93)),
        ("fcntl", 72, Some(25)),
        ("getcwd", 79, Some(17)),
        ("readlink", 89, None),
        ("getrlimit", 97, Some(163)),
        ("geteuid", 107, Some(175)),
        ("sigaltstack", 131, Some(132)),
        ("prctl", 157, Some(167)),
        ("gettid", 186, Some(178)),
        ("futex", 202, Some(98)),
        ("getdents64", 217, Some(61)),
        ("clock_gettime", 228, Some(113)),
        ("exit_group", 231, Some(94)),
        ("openat", 257, Some(56)),
        ("newfstatat", 262, Some(79)),
        ("readlinkat", 267, Some(78)),
        ("set_robust_list", 273, Some(99)),
        ("prlimit64", 302, Some(261)),
        ("getrandom", 318, Some(278)),
        ("statx", 332, Some(291)),
        ("rseq", 334, Some(293)),
        ("clone3", 435, Some(435)),
        ("prlimit64", 302, Some(261)),
        ("seccomp", 317, Some(277)),
        ("openat2", 437, Some(437)),
        ("fstatfs", 138, Some(44)),
        ("faccessat2", 439, Some(439)),
        ("landlock_create_ruleset", 444, Some(444)),
        ("landlock_add_rule", 445, Some(445)),
        ("landlock_restrict_self", 446, Some(446)),
    ];
    for arch in ARCHES {
        let rows = policy::rows(arch);
        let expected: Vec<_> = expected
            .iter()
            .filter_map(|(name, x, a)| {
                (if arch == AuditArch::X86_64 {
                    Some(*x)
                } else {
                    *a
                })
                .map(|n| (*name, n))
            })
            .collect();
        assert_eq!(
            rows.iter().map(|r| (r.name, r.nr)).collect::<Vec<_>>(),
            expected
        );
        let mut probes = std::collections::BTreeSet::new();
        for row in rows {
            assert!(!row.reason.trim().is_empty());
            assert!(probes.insert(row.probe));
            assert_eq!(row.probe, format!("row_{}_{}", row.name, row.condition));
            let args = positive(row.condition);
            let expected = if row.condition == "enosys" {
                ENOSYS
            } else {
                ALLOW
            };
            assert_eq!(
                eval(
                    &policy::bootstrap_program(arch, filter::Openat2Policy::WriteSetCovered),
                    arch.value(),
                    row.nr,
                    args
                ),
                expected,
                "{}",
                row.probe
            );
            assert_eq!(
                eval(
                    &policy::without_row(arch, row.probe),
                    arch.value(),
                    row.nr,
                    args
                ),
                DENY,
                "removed {}",
                row.probe
            );
        }
        for p in [
            policy::program(arch, filter::Openat2Policy::Deny),
            policy::bootstrap_program(arch, filter::Openat2Policy::Deny),
        ] {
            assert!(p.len() <= 4096);
            // Every branch is forward, in bounds and reaches a RET. No loop or
            // falling off the end can hide in an unexercised argument branch.
            let mut terminates = vec![false; p.len()];
            for (at, i) in p.iter().enumerate().rev() {
                let targets = match i.code {
                    0x06 => {
                        terminates[at] = true;
                        continue;
                    }
                    0x05 => vec![at + 1 + i.k as usize],
                    0x15 | 0x25 | 0x35 | 0x45 => {
                        vec![at + 1 + i.jt as usize, at + 1 + i.jf as usize]
                    }
                    0x20 | 0x54 => vec![at + 1],
                    _ => panic!("unexpected instruction"),
                };
                assert!(
                    targets
                        .iter()
                        .all(|t| *t > at && *t < p.len() && terminates[*t])
                );
                terminates[at] = true;
            }
        }
    }
}
// 이것을 실패시키는 것: arch/x32 검사를 없애거나 인자 상·하위32 의미를 바꾸는 것.
#[test]
fn bpf_arch_x32_and_64bit_arguments_are_exact() {
    assert_eq!(AuditArch::X86_64.value(), 0xc000003e);
    assert_eq!(AuditArch::Aarch64.value(), 0xc00000b7);
    for arch in ARCHES {
        for p in [
            policy::program(arch, filter::Openat2Policy::Deny),
            policy::bootstrap_program(arch, filter::Openat2Policy::Deny),
        ] {
            for wrong in [0, 0x40000003, arch.value() ^ 1] {
                assert_eq!(eval(&p, wrong, 0, [0; 6]), KILL);
            }
            if arch == AuditArch::X86_64 {
                for n in (512..=547).chain([0x40000000, 0x40000001, 0x40000038, 0x400001b3]) {
                    assert_eq!(eval(&p, arch.value(), n, [0; 6]), KILL);
                }
                for n in [511, 548] {
                    assert_eq!(eval(&p, arch.value(), n, [0; 6]), DENY);
                }
            }
        }
        // fd and flags typed as int in the kernel truncate to their low word.
        assert_eq!(
            verdict(arch, "write", [0xffff_ffff_0000_0001, 0, 0, 0, 0, 0]),
            ALLOW
        );
        assert_eq!(verdict(arch, "openat", [0, 0, 1 << 32, 0, 0, 0]), ALLOW);
    }
}
// 이것을 실패시키는 것: 프로세스 clone·위험 플래그 허용 또는 clone3 EPERM.
#[test]
fn bpf_clone_allows_threads_only() {
    for arch in ARCHES {
        for flags in [0x10900, 0x3d0f00, 0x13d0f00, 0x7d0f00] {
            assert_eq!(verdict(arch, "clone", [flags, 0, 0, 0, 0, 0]), ALLOW);
        }
        for flags in [0, 17, 0x100, 0x10000, 0x10100, 0x10800] {
            assert_eq!(verdict(arch, "clone", [flags, 0, 0, 0, 0, 0]), DENY);
        }
        for bit in [
            0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 17, 23, 25, 26, 27, 28, 29, 30, 31, 32, 63,
        ] {
            assert_eq!(
                verdict(arch, "clone", [0x10900 | (1u64 << bit), 0, 0, 0, 0, 0]),
                DENY,
                "bit {bit}"
            );
        }
        assert_eq!(verdict(arch, "clone3", [u64::MAX; 6]), ENOSYS);
    }
    for n in [57, 58] {
        assert_eq!(
            eval(
                &policy::program(AuditArch::X86_64, filter::Openat2Policy::Deny),
                AuditArch::X86_64.value(),
                n,
                [0; 6]
            ),
            DENY
        );
    }
}
// 이것을 실패시키는 것: 쓰기 syscall 별칭·O_RDONLY|O_TRUNC·openat2 허용.
#[test]
fn bpf_write_paths_have_no_alias_bypass() {
    let denied = [
        ("creat", 85, None),
        ("unlink", 87, None),
        ("unlinkat", 263, Some(35)),
        ("rename", 82, None),
        ("renameat", 264, Some(38)),
        ("renameat2", 316, Some(276)),
        ("mkdir", 83, None),
        ("mkdirat", 258, Some(34)),
        ("rmdir", 84, None),
        ("link", 86, None),
        ("linkat", 265, Some(37)),
        ("symlink", 88, None),
        ("symlinkat", 266, Some(36)),
        ("chmod", 90, None),
        ("fchmod", 91, Some(52)),
        ("fchmodat", 268, Some(53)),
        ("fchmodat2", 452, Some(452)),
        ("chown", 92, None),
        ("fchown", 93, Some(55)),
        ("lchown", 94, None),
        ("fchownat", 260, Some(54)),
        ("truncate", 76, Some(45)),
        ("ftruncate", 77, Some(46)),
        ("fallocate", 285, Some(47)),
        ("setxattr", 188, Some(5)),
        ("lsetxattr", 189, Some(6)),
        ("fsetxattr", 190, Some(7)),
        ("removexattr", 197, Some(14)),
        ("lremovexattr", 198, Some(15)),
        ("fremovexattr", 199, Some(16)),
        ("socket", 41, Some(198)),
        ("socketpair", 53, Some(199)),
        ("connect", 42, Some(203)),
        ("openat2", 437, Some(437)),
        ("execve", 59, Some(221)),
        ("execveat", 322, Some(281)),
        ("utimensat", 280, Some(88)),
        ("utimes", 235, None),
        ("utime", 132, None),
    ];
    for arch in ARCHES {
        for row in policy::rows(arch)
            .into_iter()
            .filter(|r| matches!(r.condition, "open" | "openat"))
        {
            let arg = if row.condition == "open" { 1 } else { 2 };
            for flags in [1, 2, 3, 0x40, 0x200, 0x400, 0x400000, 0x410000] {
                let mut a = [0; 6];
                a[arg] = flags;
                assert_eq!(
                    verdict(arch, row.name, a),
                    DENY,
                    "{} flags {flags}",
                    row.name
                );
            }
            let mut a = [0; 6];
            a[arg] = 0x80000; // O_CLOEXEC
            assert_eq!(verdict(arch, row.name, a), ALLOW);
        }
        for (name, x, a) in denied {
            if let Some(n) = if arch == AuditArch::X86_64 {
                Some(x)
            } else {
                a
            } {
                assert_eq!(
                    eval(
                        &policy::program(arch, filter::Openat2Policy::Deny),
                        arch.value(),
                        n,
                        [0; 6]
                    ),
                    DENY,
                    "{name}"
                );
            }
        }
    }
}
// 이것을 실패시키는 것: fd1 외 쓰기·복제·공유 쓰기 매핑·EXEC·특권 syscall 허용.
#[test]
fn bpf_fd_and_mapping_rules_cannot_write_files() {
    for arch in ARCHES {
        for fd in [0, 2, 3, 5, 63, u64::MAX, 1 << 32] {
            assert_eq!(verdict(arch, "write", [fd, 0, 0, 0, 0, 0]), DENY);
        }
        for cmd in [0, 2, 4, 1030] {
            assert_eq!(verdict(arch, "fcntl", [0, cmd, 0, 0, 0, 0]), DENY);
        }
        for cmd in [1, 3] {
            assert_eq!(verdict(arch, "fcntl", [0, cmd, 0, 0, 0, 0]), ALLOW);
        }
        for (prot, flags, expected) in [
            (3, 0x22, ALLOW),
            (0, 0x20022, ALLOW),
            (1, 2, ALLOW),
            (0, 2, ALLOW),
            (3, 2, DENY),
            (3, 0x21, DENY),
            (1, 1, DENY),
            (4, 0x22, DENY),
            (7, 0x22, DENY),
            (1 << 32, 0x22, DENY),
            (1, 0x100000022, DENY),
            (1 << 32, 2, DENY),
            (1, 0x100000002, DENY),
        ] {
            assert_eq!(
                verdict(arch, "mmap", [0, 4096, prot, flags, 0, 0]),
                expected
            );
        }
        for prot in [0, 1, 2, 3] {
            assert_eq!(verdict(arch, "mprotect", [0, 0, prot, 0, 0, 0]), ALLOW);
        }
        for prot in [4, 5, 7, 1 << 32] {
            assert_eq!(verdict(arch, "mprotect", [0, 0, prot, 0, 0, 0]), DENY);
        }
        let x = [
            20, 18, 296, 328, 40, 275, 278, 326, 425, 426, 427, 32, 33, 292, 16, 101, 310, 311,
            321, 165,
        ];
        let a = [
            66, 68, 70, 287, 71, 76, 75, 285, 425, 426, 427, 23, 24, 24, 29, 117, 270, 271, 280, 40,
        ];
        for n in if arch == AuditArch::X86_64 { x } else { a } {
            assert_eq!(
                eval(
                    &policy::program(arch, filter::Openat2Policy::Deny),
                    arch.value(),
                    n,
                    [0; 6]
                ),
                DENY
            );
        }
        for clock in [0, 2, 3, 4, 5, 6, 8, u64::MAX] {
            assert_eq!(verdict(arch, "clock_gettime", [clock, 0, 0, 0, 0, 0]), DENY);
        }
        for clock in [1, 7] {
            assert_eq!(
                verdict(arch, "clock_gettime", [clock, 0, 0, 0, 0, 0]),
                ALLOW
            );
        }
    }
}
// 이것을 실패시키는 것: bootstrap 예외가 최종 필터에 남거나 NULL의 상위32 검사 누락.
#[test]
fn bpf_final_filter_refuses_limit_changes() {
    for arch in ARCHES {
        let p = policy::bootstrap_program(arch, filter::Openat2Policy::Deny);
        for pointer in [1, 1 << 32, u64::MAX] {
            assert_eq!(verdict(arch, "prlimit64", [0, 9, pointer, 0, 0, 0]), DENY);
            assert_eq!(
                eval(
                    &p,
                    arch.value(),
                    nr(arch, "prlimit64"),
                    [0, 9, pointer, 0, 0, 0]
                ),
                ALLOW
            );
        }
        for pid in [1, 2, u64::MAX] {
            assert_eq!(
                eval(
                    &p,
                    arch.value(),
                    nr(arch, "prlimit64"),
                    [pid, 9, 1, 0, 0, 0]
                ),
                DENY
            );
        }
        for resource in [0, 1, 4, 7, 8, 10] {
            assert_eq!(
                eval(
                    &p,
                    arch.value(),
                    nr(arch, "prlimit64"),
                    [0, resource, 1, 0, 0, 0]
                ),
                DENY
            );
        }
        for pid in [0, 1, u64::MAX] {
            assert_eq!(verdict(arch, "prlimit64", [pid, 9, 0, 1, 0, 0]), ALLOW);
        }
        for (op, flags, expected) in [
            (1, 0, ALLOW),
            (0, 0, DENY),
            (2, 0, DENY),
            (1, 1, DENY),
            (1, 2, DENY),
        ] {
            let args = [op, flags, 0, 0, 0, 0];
            assert_eq!(eval(&p, arch.value(), nr(arch, "seccomp"), args), expected);
            assert_eq!(verdict(arch, "seccomp", args), DENY);
        }
        assert_eq!(verdict(arch, "prctl", [39, 0, 0, 0, 0, 0]), ALLOW);
        for op in [22, 38, 47] {
            assert_eq!(verdict(arch, "prctl", [op, 2, 0, 0, 0, 0]), DENY);
        }
        for n in if arch == AuditArch::X86_64 {
            [160, 126, 105, 106]
        } else {
            [164, 91, 146, 144]
        } {
            for p in [&p, &policy::program(arch, filter::Openat2Policy::Deny)] {
                assert_eq!(eval(p, arch.value(), n, [0; 6]), DENY);
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[path = "filter/runtime.rs"]
mod runtime;

// 이것을 실패시키는 것: TRUNCATE 대신 ABI 번호로 허용하거나 새 행의 인자 검사를 제거하는 것.
#[test]
fn repository_rows_require_exact_arguments_and_handled_write_set() {
    use filter::Openat2Policy::{Deny, WriteSetCovered};
    assert!(!landlock::LandlockState::Absent.covers_openat2_writes());
    for missing in (0..15).filter(|bit| 0x7ff2 & (1 << bit) != 0) {
        assert!(
            !landlock::LandlockState::Installed {
                abi: 99,
                handled_access_fs: 0x7ff2 & !(1 << missing),
            }
            .covers_openat2_writes()
        );
    }
    assert!(
        landlock::LandlockState::Installed {
            abi: 3,
            handled_access_fs: 0x7ff2
        }
        .covers_openat2_writes()
    );
    for arch in ARCHES {
        for mode in [Deny, WriteSetCovered] {
            let p = policy::program(arch, mode);
            for size in [0, 23, 24, 25, 24 | (1 << 32)] {
                assert_eq!(
                    eval(&p, arch.value(), 437, [0, 0, 1, size, 0, 0]),
                    if size == 24 && mode == WriteSetCovered {
                        ALLOW
                    } else {
                        DENY
                    }
                );
            }
            for (name, good, invalid) in [
                (
                    "faccessat2",
                    [0, 0, 2, 0x200, 0, 0],
                    vec![(2, 0), (2, 4), (2, 6), (3, 0), (3, 0x100)],
                ),
                (
                    "landlock_create_ruleset",
                    [1, 8, 0, 0, 0, 0],
                    vec![(1, 0), (1, 16), (1, 8 | (1 << 32)), (2, 2)],
                ),
                (
                    "landlock_create_ruleset",
                    [0, 0, 1, 0, 0, 0],
                    vec![(0, 1), (0, 1 << 32), (1, 1), (1, 1 << 32), (2, 2)],
                ),
                (
                    "landlock_add_rule",
                    [0, 1, 1, 0, 0, 0],
                    vec![(1, 0), (1, 2), (3, 1)],
                ),
                ("landlock_restrict_self", [0; 6], vec![(1, 1)]),
            ] {
                assert_eq!(
                    eval(&p, arch.value(), nr(arch, name), good),
                    ALLOW,
                    "{name}"
                );
                for (arg, bad) in invalid {
                    let mut args = good;
                    args[arg] = bad;
                    assert_eq!(
                        eval(&p, arch.value(), nr(arch, name), args),
                        DENY,
                        "{name} arg {arg}"
                    );
                }
            }
            if arch == AuditArch::X86_64 {
                for n in [437, 138, 439, 444, 445, 446] {
                    assert_eq!(eval(&p, arch.value(), n | 0x4000_0000, [0; 6]), KILL);
                }
            }
            let bytes: Vec<_> = p
                .iter()
                .flat_map(|i| {
                    let mut b = Vec::from(i.code.to_le_bytes());
                    b.extend([i.jt, i.jf]);
                    b.extend(i.k.to_le_bytes());
                    b
                })
                .collect();
            println!(
                "B3 BPF {arch:?} {mode:?} instructions={} sha256={:02x?}",
                p.len(),
                bingsu_core::collection::cwd_hash::sha256(&bytes)
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/meter.rs"]
mod meter;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/safe_read/mod.rs"]
mod safe_read;
