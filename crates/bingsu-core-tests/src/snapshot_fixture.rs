//! Shared native/wasm byte fixture, with every stored field populated.
use bingsu_core::{
    color::palette::{Mode, PaletteWarning},
    config::{
        compile::{BUILTIN_TOML, CompiledConfig, ExecPolicy, ExecUnit, LayoutRef, NotRun, Side},
        merge::Origin,
        source::{ExtendsRef, FileKey, OpenError, Opened, Resolver, Trust},
        tree::Span,
    },
    diag::SourceId,
    handoff::Permit,
    snapshot::{Identity, Marker, Sequence, Snapshot, encode_metadata},
};
struct NoFiles;
impl Resolver for NoFiles {
    fn open(&mut self, _: &Opened, _: &ExtendsRef) -> Result<Opened, OpenError> {
        Err(OpenError {
            reason: "no fixture extends".into(),
            trust: Trust::Executable,
        })
    }
}
pub fn compile(text: &str) -> CompiledConfig {
    let roots = [BUILTIN_TOML, text]
        .iter()
        .enumerate()
        .map(|(i, s)| Opened {
            key: FileKey {
                dev: 1,
                ino: i as u64,
            },
            bytes: s.as_bytes().to_vec(),
            trust: Trust::Executable,
            display: vec![i as u8],
        })
        .collect();
    bingsu_core::config::report::report(roots, &mut NoFiles, [0, 3, 0], Mode::Dark)
        .snapshot
        .expect("fixture compiles")
}
pub fn config() -> CompiledConfig {
    let mut c = compile(
        "icons='nerd'\n[width]\nambiguous=2\nemoji=1\n[layout]\nuse_last_column=true\n[segment.\"custom/hello\"]\nkind='command'\ncommand=['echo','빙수']\ncwd='/tmp/a b'\nenv_allow=['LANG']\ntimeout='123ms'\ncache='45s'\n[layout.line2]\nleft=['custom/hello','char']\n[layout.when.wide]\nmin_cols=100\norder=4\n[layout.when.wide.line1]\nleft=['dir','git']\n[colors]\nmode='auto'\n",
    );
    let origin = |trust| Origin {
        source: SourceId(31),
        key_span: Span { start: 17, end: 23 },
        span: Span { start: 25, end: 99 },
        trust,
    };
    c.exec_units.push(ExecUnit {
        id: "lang/demo".into(),
        policy: ExecPolicy::Language {
            interpreter: Some("python".into()),
            version_argv: vec!["--version".into()],
            detect_files: vec!["pyproject.toml".into()],
        },
        timeout_ms: Some(999),
        cache_ms: Some(30000),
        origins: vec![
            ("interpreter".into(), origin(Trust::ShapeOnly)),
            ("detect_files".into(), origin(Trust::Unsafe)),
        ],
        approved_by: vec![LayoutRef {
            band: Some("wide".into()),
            line: 1,
            side: Side::Right,
            origin: Some(origin(Trust::Executable)),
        }],
        shown_at: vec![LayoutRef {
            band: None,
            line: 0,
            side: Side::Left,
            origin: None,
        }],
        not_run: Some(NotRun::UnsafeFile {
            key: "interpreter".into(),
        }),
    });
    c.palette.warnings = vec![
        PaletteWarning::TextContrast {
            token: 0,
            milli: 4001,
        },
        PaletteWarning::BlockContrast {
            token: 1,
            milli: 2900,
        },
        PaletteWarning::Clipped { token: 2 },
        PaletteWarning::MarkContrast {
            token: 3,
            milli: 2999,
        },
        PaletteWarning::BackgroundClipped,
    ];
    c.light_palette.warnings = c.palette.warnings.clone();
    c
}
pub fn frame() -> Snapshot {
    Snapshot {
        id: Identity {
            boot: [1; 16],
            epoch: [2; 16],
            context: [3; 4],
            generation: 7,
            source: [4; 4],
        },
        config: config(),
        metadata: encode_metadata(b"canonical-evidence\0\xff").unwrap(),
    }
}
/// Header/frame, marker, sequence and relay bytes, in that order.
pub fn bytes() -> Vec<u8> {
    let s = frame();
    let mut b = s.encode(1, 0).unwrap();
    b.extend(
        Marker {
            id: s.id,
            seq: 9,
            verified_at: 100,
            resume: 0,
            kind: 1,
            domain: [5; 16],
            invalid: false,
        }
        .encode(),
    );
    b.extend(
        Sequence {
            boot: s.id.boot,
            epoch: s.id.epoch,
            generation: 7,
            verified: 9,
        }
        .encode(),
    );
    b.extend(
        Permit {
            kind: 1,
            deadline: 60_000_000_100,
            boot: s.id.boot,
            resume: 0,
            domain: [5; 16],
        }
        .encode(),
    );
    b
}
