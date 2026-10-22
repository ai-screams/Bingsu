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
"landlock":"crates/bingsu-collect/src/landlock.rs",
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
# 이것을 실패시키는 것: dot을 raw 계수에서 제외·names에 포함하거나 cap 이후 할당·EOF 추정을 허용하는 것.
LINUX = [('entries_dot_not_counted',
  'entries_limit_precedes_filtering_and_allocation',
  [('linux', '            meter.raw_entry()?;\n            raw += 1;\n', ''),
   ('linux', '            if name != b"." && name != b".." {',
    '            if name != b"." && name != b".." {\n                meter.raw_entry()?;\n                raw += 1;')]),
 ('entries_dot_in_names',
  'entries_limit_precedes_filtering_and_allocation',
  [('linux', 'if name != b"." && name != b".." {', 'if true {')]),
 ('entries_allocate_past_cap',
  'entries_limit_precedes_filtering_and_allocation',
  [('linux', '            if raw >= raw_limit {', '            if false {')]),
 ('entries_exact_cap_complete',
  'entries_limit_precedes_filtering_and_allocation',
  [('linux', 'complete: false,', 'complete: raw_limit == 302,')]),
 ('entries_extra_getdents',
  'entries_limit_precedes_filtering_and_allocation',
  [('linux', '\n        if raw >= raw_limit {', '\n        if raw > raw_limit {')]),
 ('entries_allocation_unmetered',
  'entries_limit_precedes_filtering_and_allocation',
  [('linux', '                meter.allocation(name.len() + std::mem::size_of::<Vec<u8>>())?;', '')]),
 ('landlock_install',
  'linux_landlock_backstop_blocks_held_fd_after_coarse_rename',
  [('landlock',
    'unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd.as_raw_fd(), 0u32) }',
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

# 이것을 실패시키는 것: 축소 stage A, 선택된 root, 비공개 capability와 실제 kernel flag 조건을 없애는 것.
REVIEW = [
 ('stage_a_selected_root', 'stage_a_held_directory_keeps_selected_root', [('mod', 'if access.guarantee().is_some() {', 'if false {')]),
 ('stage_a_symlink', 'stage_a_symlink_head_is_unknown', [('mod', 'if access.guarantee().is_none() {', 'if false {')]),
 ('stage_a_symlink_race', 'stage_a_symlink_coarse_rename_reads_zero_external_bytes', [('mod', 'if access.guarantee().is_none() {', 'if false {')]),
 ('stage_a_nofollow', 'stage_a_nofollow_survives_leaf_and_directory_replacement', [('walk', 'libc::O_NOFOLLOW | ', '')]),
 ('stage_a_directories', 'stage_a_operation_directories_are_typed_and_nofollow', [('mod', 'walk::one_component(root, path, true, meter)?', 'resolve(root, path, access, true, false, meter)?')]),
 ('stage_a_directory_type', 'stage_a_operation_directories_are_typed_and_nofollow', [('mod', '_ => return Err(ReadError::Denied),', '_ => b"head-name".as_slice(),')]),
 ('stage_a_component', 'safe_read::walk::tests::stage_a_component_rejects_paths_before_io', [('walk', 'name.is_empty() || name.contains(&b\'/\') || name == b"." || name == b".."', 'false')]),
 ('stage_a_regular', 'stage_a_checks_file_kind_links_and_identity', [('mod', 'if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {', 'if false {')]),
 ('stage_a_nlink', 'stage_a_checks_file_kind_links_and_identity', [('mod', 'if cap.single_link && self.metadata.st_nlink != 1 {', 'if false {')]),
 ('stage_a_identity', 'stage_a_checks_file_kind_links_and_identity', [('walk', 'if !unchanged(&before, &opened.metadata) {', 'if false {')]),
 ('selection_slash', 'content_roots_require_validated_selection', [('mod', 'if root.identity == self.slash {', 'if false {')]),
 ('selection_marker', 'content_roots_require_validated_selection', [('mod', 'if kind != libc::S_IFDIR && (kind != libc::S_IFREG || marker.metadata.st_nlink != 1) {', 'if false {')]),
 ('selection_mount', 'content_roots_require_validated_selection', [('mod', 'if found.device != root.device || found.mount != root.mount {', 'if false {')]),
]
API_TEST = 'capabilities_cannot_be_forged_or_read_as_roots'
for field, typ in [('cwd','Root'), ('ancestors','Vec<AncestorDir>'), ('logical','bool'), ('query','DiscoveryQuery')]:
    REVIEW.append(('private_'+field, API_TEST, [('mod', f'    {field}: {typ},\n' + ('    slash' if field == 'query' else ''), f'    pub {field}: {typ},\n' + ('    slash' if field == 'query' else ''))]))
for typ in ['AncestorDir', "StageADir<'_>"]:
    REVIEW.append(('no_root_'+typ.split('<')[0], API_TEST, [('mod', 'struct Fd {', f'impl std::ops::Deref for {typ} {{ type Target = Root; fn deref(&self) -> &Root {{ &self.root }} }}\nstruct Fd {{')]))
LINUX += [
 ('landlock_rule_error', 'linux_read_layer_failure_cannot_grant_access', [('landlock', '        {\n            return Err(io::Error::last_os_error());\n        }\n        #[cfg(test)]', '        { }\n        #[cfg(test)]')]),
 ('probe_scope', 'access_probe_stepwise_has_no_guarantee', [('mod', 'if access.backend == Resolver::Openat2 {', 'if true {')]),
 ('no_magiclinks', 'safe_read::linux::tests::no_magiclinks_is_enforced_independently', [('linux', ' | libc::RESOLVE_NO_MAGICLINKS', '')]),
 ('procfs_type', 'root_procfs_is_refused', [('linux', 'if fs.f_type as u64 == 0x9fa0 {', 'if false {')]),
 ('ancestor_cap', 'ancestors_only_list_bounded_names', [('mod', 'raw_limit.min(256)', 'raw_limit')]),
 ('metadata_owner', 'linux_two_uid_victim_canaries_are_unreadable', [('mod', 'if metadata.st_uid != unsafe { libc::geteuid() } {', 'if false {')]),
 ('landlock_read_dir', 'linux_landlock_backstop_blocks_held_fd_after_coarse_rename', [('landlock', 'let rights = (1 << 2) | (1 << 3);', 'let rights = 1 << 2;')]),
 ('landlock_read_file', 'linux_landlock_backstop_blocks_held_fd_after_coarse_rename', [('landlock', 'let rights = (1 << 2) | (1 << 3);', 'let rights = 1 << 3;')]),
 ('private_proof', API_TEST, [('landlock', '    _thread: std::marker::PhantomData<std::rc::Rc<()>>,', '    pub _thread: std::marker::PhantomData<std::rc::Rc<()>>,')]),
 ('proof_required', API_TEST, [('mod', '&mut self, _proof: crate::landlock::ReadLayerInstalled', '&mut self')]),
 ('proof_thread', API_TEST, [('landlock', 'std::marker::PhantomData<std::rc::Rc<()>>', 'std::marker::PhantomData<()>')]),
]

selected = CASES + REVIEW + (MAC if sys.platform == "darwin" else LINUX)
results = []
try:
    for label, test, mutations in selected:
        for key, path in FILES.items(): path.write_bytes((SAVED/key).read_bytes())
        for key, old, new in mutations:
            path = FILES[key]
            source = path.read_text().replace("\r\n", "\n")
            assert old in source, (label, old)
            path.write_text(source.replace(old, new))
        suite = "safe_read_api" if test == API_TEST else ("safe_read_linux" if test.startswith("linux_") else "safe_read")
        args = ["cargo", "test", "-j", "2", "-p", "bingsu-collect", "--test", suite, test, "--", "--exact", "--test-threads=1"]
        security_output = test.startswith(("linux_landlock", "linux_two_uid"))
        if test == "resolver_observations" or security_output: args += ["--ignored"]
        if "stage_a_symlink" in test: args += ["--nocapture"]
        if security_output: args += ["--nocapture"]
        run = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=50)
        (OUT/(label+".log")).write_text(run.stdout)
        if security_output: print(run.stdout, end="", flush=True)
        killed = run.returncode != 0 and "test result: FAILED." in run.stdout
        row = dict(mutation=label, test=test, exit=run.returncode, killed=killed)
        results.append(row)
        print(json.dumps(row), flush=True)
finally:
    for key, path in FILES.items(): path.write_bytes((SAVED/key).read_bytes())
    (OUT/"results.json").write_text(json.dumps(results, indent=2)+"\n")
    (OUT/"blocked.json").write_text(json.dumps(LINUX if sys.platform == "darwin" else MAC, indent=2)+"\n")
assert len(results) == len(selected) and all(r["killed"] for r in results), results
