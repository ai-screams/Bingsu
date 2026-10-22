"""Run with Python -B and a fresh PYTHONPYCACHEPREFIX, from repo root.
Each mutation must compile and fail its assertion, then restore saved bytes.
Linux security rows need isolated Linux container root; macOS reports them BLOCKED.
"""
import json, os, pathlib, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path.cwd()
OUT = ROOT / "target/b1-redesign/mutations"
OUT.mkdir(parents=True, exist_ok=True)
FILES = {key: ROOT / path for key, path in {
"walk":"crates/bingsu-collect/src/safe_read/walk.rs",
"mod":"crates/bingsu-collect/src/safe_read/mod.rs",
"mac":"crates/bingsu-collect/src/safe_read/macos.rs",
"linux":"crates/bingsu-collect/src/safe_read/linux.rs",
"meter":"crates/bingsu-collect/src/meter.rs",
"linux_test":"crates/bingsu-collect/tests/safe_read_linux.rs",
}.items()}
SAVED = pathlib.Path(tempfile.mkdtemp(prefix="b1-redesign-saved-"))
for key, path in FILES.items(): shutil.copyfile(path, SAVED/key)

CASES = [('symlink40', 'x13_resolvers_share_static_verdicts', [('walk', 'links > 40', 'links >= 40')]),
 ('symlink41', 'x13_resolvers_share_static_verdicts', [('walk', 'links > 40', 'links > 41')]),
 ('absolute_symlink',
  'x13_resolvers_share_static_verdicts',
  [('walk', 'if path.starts_with(b"/") {', 'if false {')]),
 ('root_pop',
  'x13_resolvers_share_static_verdicts',
  [('walk',
    'if stack.pop().is_none() {\n                return Err(ReadError::Escape);\n            }',
    'stack.pop();')]),
 ('absolute_path',
  'x13_resolvers_share_static_verdicts',
  [('mod', 'path.starts_with(b"/") || path.contains(&0)', 'path.contains(&0)')]),
 ('missing_class',
  'x13_resolvers_share_static_verdicts',
  [('mod',
    'libc::ENOENT | libc::ENOTDIR => Self::Missing',
    'libc::ENOENT | libc::ENOTDIR => Self::Denied')]),
 ('special_files',
  'x13_resolvers_share_static_verdicts',
  [('walk', 'if !need_directory && kind != libc::S_IFREG {', 'if false {'),
   ('mod', 'if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {', 'if false {')]),
 ('single_link',
  'same_fd_read_and_single_link_policy',
  [('mod', 'if cap.single_link && self.metadata.st_nlink != 1 {', 'if false {'),
   ('walk', 'if single_link && metadata.st_nlink != 1 {', 'if false {')]),
 ('same_fd_bytes',
  'same_fd_read_and_single_link_policy',
  [('mod', 'bytes.truncate(used);', 'bytes.truncate(used);\n        bytes.fill(0);')]),
 ('cap_overflow',
  'read_limit_checks_before_allocation',
  [('mod', 'cap.bytes.checked_add(1).ok_or(ReadError::Limit)?', 'cap.bytes.wrapping_add(1)')]),
 ('oversize_precheck',
  'read_limit_checks_before_allocation',
  [('mod',
    'if self.metadata.st_size < 0 || self.metadata.st_size as u64 > cap.bytes {',
    'if false {')]),
 ('byte_budget',
  'read_limit_checks_before_allocation',
  [('mod', 'capacity as u64 > meter.byte_limit || ', '')]),
 ('allocation_budget',
  'read_limit_checks_before_allocation',
  [('mod', ' || capacity as u64 > meter.allocation_limit', ''),
   ('meter', 'if next > self.allocation_limit {', 'if false {')]),
 ('growing_cap_plus_one',
  'growing_file_stops_at_cap_plus_one',
  [('mod', 'cap.bytes.checked_add(1).ok_or(ReadError::Limit)?', 'cap.bytes')]),
 ('fifo_regular_guard',
  'fifo_open_never_waits_for_writer',
  [('walk', 'if !need_directory && kind != libc::S_IFREG {', 'if false {'),
   ('mod', 'if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {', 'if false {')]),
 ('deadline',
  'acquisition_and_deadline_are_bounded',
  [('meter', 'if Instant::now() >= self.deadline {', 'if false {')]),
 ('ancestor_fds',
  'acquisition_and_deadline_are_bounded',
  [('walk', 'if stack.len() > 33 {', 'if stack.len() > 34 {')]),
 ('component_visits',
  'acquisition_and_deadline_are_bounded',
  [('walk', 'count > 4096', 'count > 8192'), ('walk', '*visits == 4096', '*visits == 8192')]),
 ('discarded_parent',
  'acquisition_and_deadline_are_bounded',
  [('walk',
    '} else if dropped != 0 {\n                return Err(ReadError::Limit);',
    '} else if dropped != 0 {\n                continue;')]),
 ('read_chunk',
  'resolver_observations',
  [('meter', 'READ_CHUNK: usize = 16_384', 'READ_CHUNK: usize = 32_768')]),
 ('fd_limit', 'fd_budget_is_released_on_drop', [('meter', 'if next > LIVE_FDS {', 'if false {')]),
 ('fd_release',
  'fd_budget_is_released_on_drop',
  [('meter', 'self.0.set(self.0.get() - 1);', 'self.0.set(self.0.get());')]),
 ('stat_counter',
  'resolver_observations',
  [('meter', 'Op::Stat => &mut count.stat', 'Op::Stat => &mut count.open')]),
 ('filesystem_counter',
  'resolver_observations',
  [('meter', 'Op::Filesystem => &mut count.filesystem', 'Op::Filesystem => &mut count.mount')]),
 ('scope_guard', 'no_guarantee_exposes_only_stage_a', [('mod', 'access.full()?;', '')]),
 ('stage_a_head',
  'no_guarantee_exposes_only_stage_a',
  [('mod', 'Self::Head => b"HEAD"', 'Self::Head => b"index"')]),
 ('stage_a_directory',
  'no_guarantee_exposes_only_stage_a',
  [('mod', 'StageADirectory::Git => b".git"', 'StageADirectory::Git => b"objects"')]),
 ('dev_ino',
  'component_replacement_is_changed',
  [('walk',
    'before.st_dev == after.st_dev && before.st_ino == after.st_ino',
    '{ let _ = (before, after); true }')]),
 ('ctime_reintroduced',
  'normal_git_writes_do_not_invalidate_held_directories',
  [('walk',
    '    let mut pending = components(path, meter)?;',
    '    let saved = stat(root.fd.as_raw_fd(), meter)?;\n'
    '    let mut pending = components(path, meter)?;'),
   ('walk',
    '        meter.event("after_open_component");',
    '        meter.event("after_open_component");\n'
    '        let now = stat(root.fd.as_raw_fd(), meter)?;\n'
    '        if saved.st_ctime != now.st_ctime || saved.st_ctime_nsec != now.st_ctime_nsec { '
    'return Err(ReadError::Changed); }')])]
MAC = [('darwin_atomic_root',
  'coarse_rename_with_guarantee_reads_zero_external_bytes',
  [('walk', 'if access.guarantee() == Some(Guarantee::DarwinBeneath) {', 'if false {')]),
 ('darwin_ignored_beneath',
  'darwin_each_flag_requires_negative_semantics',
  [('mac', 'if beneath {', 'if true {')]),
 ('darwin_ignored_any',
  'darwin_each_flag_requires_negative_semantics',
  [('mac', '            nofollow_any,', '            nofollow_any: true,')]),
 ('darwin_ignored_unique',
  'darwin_each_flag_requires_negative_semantics',
  [('mac', '            unique,', '            unique: true,')]),
 ('darwin_flag_combination',
  'darwin_flag_behavior_and_mount_backstop',
  [('mac', '            NOFOLLOW_ANY\n', '            NOFOLLOW_ANY | libc::O_NOFOLLOW\n')]),
 ('darwin_unique_use',
  'darwin_optional_flags_are_used_only_when_probed',
  [('mac', 'if single_link && caps.unique {', 'if false {')]),
 ('darwin_mount',
  'darwin_flag_behavior_and_mount_backstop',
  [('walk',
    'if found.device != root.identity.device || found.mount != root.identity.mount {',
    'if false {'),
   ('mod',
    'if found.mount != root.identity.mount || found.device != root.identity.device {',
    'if false {')]),
 ('darwin_reopen_identity',
  'darwin_atomic_reopen_checks_identity',
  [('walk', 'if atomic.identity != opened.identity {', 'if false {')])]
LINUX = [('landlock_install',
  'linux_landlock_backstop_blocks_held_fd_after_coarse_rename',
  [('linux_test',
    'unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd as i32, 0u32) }',
    '0')]),
 ('landlock_upgrade',
  'linux_landlock_backstop_blocks_held_fd_after_coarse_rename',
  [('mod', 'self.guarantee = Some(Guarantee::LandlockReadLayer);', 'self.guarantee = None;')]),
 ('two_uid_ownership',
  'linux_two_uid_victim_canaries_are_unreadable',
  [('linux_test',
    'chown(&path.join(dir).join("canary"), 21001);',
    'chown(&path.join(dir).join("canary"), 21002);')]),
 ('openat2_beneath',
  'linux_openat2_coarse_rename_reads_zero_external_bytes',
  [('linux',
    'libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV',
    'libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_XDEV')])]

selected = CASES + (MAC if sys.platform == "darwin" else LINUX)
results = []
try:
    for label, test, mutations in selected:
        for key, path in FILES.items(): path.write_bytes((SAVED/key).read_bytes())
        for key, old, new in mutations:
            path = FILES[key]
            source = path.read_text().replace("\r\n", "\n")
            assert old in source, (label, old)
            path.write_text(source.replace(old, new))
        suite = "safe_read_linux" if test.startswith("linux_") else "safe_read"
        args = ["cargo", "test", "-j", "2", "-p", "bingsu-collect", "--test", suite, test, "--", "--exact", "--test-threads=1"]
        if test == "resolver_observations" or test.startswith(("linux_landlock", "linux_two_uid")): args += ["--ignored"]
        run = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=50)
        (OUT/(label+".log")).write_text(run.stdout)
        killed = run.returncode != 0 and "test result: FAILED." in run.stdout
        row = dict(mutation=label, test=test, exit=run.returncode, killed=killed)
        results.append(row)
        print(json.dumps(row), flush=True)
finally:
    for key, path in FILES.items(): path.write_bytes((SAVED/key).read_bytes())
    (OUT/"results.json").write_text(json.dumps(results, indent=2)+"\n")
    (OUT/"blocked.json").write_text(json.dumps(LINUX if sys.platform == "darwin" else MAC, indent=2)+"\n")
assert len(results) == len(selected) and all(r["killed"] for r in results), results
