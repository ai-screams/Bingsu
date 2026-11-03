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
    layout_view::FrontConfig,
    snapshot::{
        FrontDecoder, FrontSnapshot, HEADER, Identity, Marker, PREFIX, Sequence, Snapshot,
        encode_metadata, lengths,
    },
    snapshot_codec::{self, Error},
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
    report(text).snapshot.expect("fixture compiles")
}
/// The whole report of the built-in config with `text` over it.
pub fn report(text: &str) -> bingsu_core::config::report::ConfigReport {
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
        id: "custom/demo".into(),
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
            band: Some(0),
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
/// The front's decode of a compiled section, CRCs included (the frame checksum
/// is not part of it).
pub fn front_compiled(b: &[u8], width: u16) -> Result<FrontConfig, Error> {
    let front = snapshot_codec::front_len(b, b.len())?;
    let plan = snapshot_codec::plan_front(&b[..front], b.len(), width)?;
    let end = plan.offset + plan.len;
    let variant = b.get(plan.offset..end).ok_or(Error::Short)?;
    snapshot_codec::finish_front(plan, variant)
}
/// Where the variant selected at `width` ends in a well-formed file.
pub fn selected_end(wire: &[u8], width: u16) -> usize {
    let (c, _) = lengths(wire).unwrap();
    let compiled = &wire[HEADER + PREFIX..HEADER + PREFIX + c];
    let front = snapshot_codec::front_len(compiled, c).unwrap();
    let plan = snapshot_codec::plan_front(&compiled[..front], c, width).unwrap();
    HEADER + PREFIX + plan.offset + plan.len
}
/// `FrontDecoder` over a whole file, `chunk` bytes per read at most, as the
/// prompt drives it. Returns the snapshot and the bytes it asked to read.
pub fn front_read(wire: &[u8], width: u16, chunk: usize) -> Result<(FrontSnapshot, usize), Error> {
    let mut decoder = FrontDecoder::new(wire.len() as u64, width)?;
    let mut offset = 0;
    while decoder.read_len() != 0 {
        let end = offset + decoder.read_len().min(chunk);
        decoder.push(wire.get(offset..end).ok_or(Error::Short)?)?;
        offset = end;
    }
    Ok((decoder.finish()?, offset))
}
