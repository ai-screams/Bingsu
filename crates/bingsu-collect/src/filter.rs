//! Collector-only classic BPF. Linux UAPI numbers are explicit so both ABIs
//! can be evaluated on any test host. No prompt policy is reused or widened.
use std::{vec, vec::Vec};

#[cfg(target_os = "linux")]
pub type Instruction = libc::sock_filter;
// A layout-compatible instruction for host-side evaluation, never installed.
#[cfg(all(test, not(target_os = "linux")))]
#[derive(Clone, Copy, Debug)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditArch {
    X86_64,
    Aarch64,
}
impl AuditArch {
    pub const fn value(self) -> u32 {
        match self {
            Self::X86_64 => 0xc000_003e,
            Self::Aarch64 => 0xc000_00b7,
        }
    }
    #[cfg(target_os = "linux")]
    pub const fn native() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::X86_64
        }
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("collector policy requires a reviewed Linux syscall ABI");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Openat2Policy {
    Deny,
    WriteSetCovered,
}

pub const TABLE: &str = include_str!("../collector-syscalls.tsv");
pub const ALLOW: u32 = 0x7fff_0000;
pub const DENY: u32 = 0x0005_0001; // ERRNO | EPERM (Linux)
pub const ENOSYS: u32 = 0x0005_0026;
pub const KILL: u32 = 0x8000_0000;
const LD: u16 = 0x20;
const AND: u16 = 0x54;
const JEQ: u16 = 0x15;
const JGT: u16 = 0x25;
const JGE: u16 = 0x35;
const JSET: u16 = 0x45;
const JA: u16 = 0x05;
const RET: u16 = 0x06;
// Linux UAPI: O_ACCMODE, O_CREAT, O_TRUNC, O_APPEND, __O_TMPFILE.
// O_DIRECTORY differs by arch; only the independent __O_TMPFILE bit is denied.
const WRITE_OPEN: u32 = 3 | 0x40 | 0x200 | 0x400 | 0x40_0000;
// CLONE_VM/FS/FILES/SIGHAND/THREAD/SYSVSEM/SETTLS/PARENT_SETTID/
// CHILD_CLEARTID/DETACHED/CHILD_SETTID. No signal, process or namespace bits.
const THREAD_FLAGS: u32 = 0x017d_0f00;
const THREAD_REQUIRED: u32 = 0x0001_0900;

#[derive(Clone, Debug)]
pub struct Row<'a> {
    pub name: &'a str,
    pub nr: u32,
    pub condition: &'a str,
    pub probe: &'a str,
    pub reason: &'a str,
}
pub fn rows(arch: AuditArch) -> Vec<Row<'static>> {
    TABLE
        .lines()
        .filter(|line| !line.starts_with('#'))
        .skip(1)
        .filter_map(|line| {
            let c: Vec<_> = line.split('\t').collect();
            assert_eq!(c.len(), 6, "collector table columns");
            let number = c[if arch == AuditArch::X86_64 { 1 } else { 2 }];
            (number != "-").then(|| Row {
                name: c[0],
                nr: number.parse().expect("syscall number"),
                condition: c[3],
                probe: c[4],
                reason: c[5],
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Cond {
    offset: u32,
    mask: u32,
    want: u32,
}
fn low(arg: u32, mask: u32, want: u32) -> Cond {
    Cond {
        offset: 16 + 8 * arg,
        mask,
        want,
    }
}
fn high(arg: u32, want: u32) -> Cond {
    Cond {
        offset: 20 + 8 * arg,
        mask: u32::MAX,
        want,
    }
}
fn conditions(kind: &str) -> Vec<Vec<Cond>> {
    let eq = |arg, want| low(arg, u32::MAX, want);
    match kind {
        "any" | "enosys" | "read_root" => vec![vec![]],
        // open_how is opaque to BPF. Only the successfully installed write
        // deny set can authorize this row; size is a full-width size_t.
        "handled_write_set" => vec![vec![eq(3, 24), high(3, 0)]],
        "readonly" => vec![vec![eq(2, 2), eq(3, 0x200)]], // W_OK, AT_EACCESS
        "read_layer_create" => vec![
            vec![eq(0, 0), high(0, 0), eq(1, 0), high(1, 0), eq(2, 1)],
            vec![eq(1, 8), high(1, 0), eq(2, 0)],
        ],
        "read_layer_add" => vec![vec![eq(1, 1), eq(3, 0)]], // PATH_BENEATH
        "read_layer_restrict" => vec![vec![eq(1, 0)]],
        "response" => vec![vec![eq(0, 1)]],
        "open" => vec![vec![low(1, WRITE_OPEN, 0)]],
        "openat" => vec![vec![low(2, WRITE_OPEN, 0)]],
        "thread" => vec![vec![
            high(0, 0),
            low(0, !THREAD_FLAGS, 0),
            low(0, THREAD_REQUIRED, THREAD_REQUIRED),
        ]],
        "mapping" => vec![
            vec![high(2, 0), high(3, 0), low(2, !3, 0), low(3, 0x2f, 0x22)], // anonymous private R/W/NONE
            vec![high(2, 0), high(3, 0), low(2, !1, 0), low(3, 0x2f, 2)],    // file private R/NONE
        ],
        "protect" => vec![vec![high(2, 0), low(2, !3, 0)]],
        "fcntl" => vec![vec![eq(1, 1)], vec![eq(1, 3)]], // F_GETFD, F_GETFL
        "clock" => vec![vec![eq(0, 1)], vec![eq(0, 7)]], // MONOTONIC, BOOTTIME
        "nnp_query" => vec![vec![eq(0, 39)]],            // PR_GET_NO_NEW_PRIVS only
        "query" => vec![vec![eq(2, 0), high(2, 0)]],
        // Trusted single-threaded startup lowers and reads back AS. BPF cannot
        // inspect the pointed-to rlimit; the final filter removes this exception.
        "bootstrap_as" => vec![vec![eq(0, 0), eq(1, 9)]],
        "bootstrap_filter" => vec![vec![eq(0, 1), eq(1, 0)]], // SET_MODE_FILTER, flags=0
        _ => panic!("unknown collector condition"),
    }
}
fn op(code: u16, jt: u8, jf: u8, k: u32) -> Instruction {
    Instruction { code, jt, jf, k }
}

/// Final allowlist. Installation stacks it on the bootstrap policy; neither
/// layer can grant what the other layer refuses.
pub fn program(arch: AuditArch, mode: Openat2Policy) -> Vec<Instruction> {
    build(arch, false, mode)
}
pub fn bootstrap_program(arch: AuditArch, mode: Openat2Policy) -> Vec<Instruction> {
    build(arch, true, mode)
}
fn build(arch: AuditArch, bootstrap: bool, mode: Openat2Policy) -> Vec<Instruction> {
    build_rows(arch, bootstrap, mode, &rows(arch))
}
fn build_rows(
    arch: AuditArch,
    bootstrap: bool,
    mode: Openat2Policy,
    rows: &[Row<'_>],
) -> Vec<Instruction> {
    let mut p = vec![
        op(LD, 0, 0, 4),
        op(JEQ, 1, 0, arch.value()),
        op(RET, 0, 0, KILL),
    ];
    if arch == AuditArch::X86_64 {
        p.extend([
            op(LD, 0, 0, 0),
            op(JSET, 0, 1, 0x4000_0000),
            op(RET, 0, 0, KILL),
            op(JGE, 0, 2, 512),
            op(JGT, 1, 0, 547),
            op(RET, 0, 0, KILL),
        ]);
    }
    for row in rows {
        if row.condition == "handled_write_set" && mode == Openat2Policy::Deny {
            continue;
        }
        if row.condition.starts_with("bootstrap_") && !bootstrap {
            continue;
        }
        for conds in conditions(row.condition) {
            // Only short conditional skips; JA handles every variable distance.
            p.extend([op(LD, 0, 0, 0), op(JEQ, 1, 0, row.nr)]);
            let mut skips = vec![p.len()];
            p.push(op(JA, 0, 0, 0));
            for c in conds {
                p.extend([
                    op(LD, 0, 0, c.offset),
                    op(AND, 0, 0, c.mask),
                    op(JEQ, 1, 0, c.want),
                ]);
                skips.push(p.len());
                p.push(op(JA, 0, 0, 0));
            }
            p.push(op(
                RET,
                0,
                0,
                if row.condition == "enosys" {
                    ENOSYS
                } else {
                    ALLOW
                },
            ));
            for at in skips {
                p[at].k = (p.len() - at - 1) as u32;
            }
        }
    }
    p.push(op(RET, 0, 0, DENY));
    assert!(p.len() <= 4096, "classic BPF instruction limit");
    p
}

#[cfg(target_os = "linux")]
fn install(p: &[Instruction]) -> std::io::Result<()> {
    let fprog = libc::sock_fprog {
        len: u16::try_from(p.len()).expect("bounded program"),
        filter: p.as_ptr().cast_mut(),
    };
    // SAFETY: the kernel copies the live program. Startup is single-threaded;
    // all later threads inherit both layers. No TSYNC bootstrap exception.
    let rc = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &fprog) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
#[cfg(target_os = "linux")]
pub fn install_bootstrap(mode: Openat2Policy) -> std::io::Result<()> {
    install(&bootstrap_program(AuditArch::native(), mode))
}
#[cfg(target_os = "linux")]
pub fn seal_limits(mode: Openat2Policy) -> std::io::Result<()> {
    install(&program(AuditArch::native(), mode))
}

// Used by the host evaluator's row-removal mutations, never shipped.
#[cfg(test)]
#[allow(dead_code)]
pub fn without_row(arch: AuditArch, probe: &str) -> Vec<Instruction> {
    let kept: Vec<_> = rows(arch)
        .into_iter()
        .filter(|r| r.probe != probe)
        .collect();
    build_rows(arch, true, Openat2Policy::WriteSetCovered, &kept)
}
