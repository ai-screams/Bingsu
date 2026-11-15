//! Script copies of one round (macOS). Linux runs a script through a sealed memfd the
//! relay makes, so nothing is held there.
use super::*;

/// Script copies of one round. Linux runs a script through a sealed memfd
/// the relay makes, so this holds nothing there. macOS runs the helper's
/// private copy: made after the marker from the descriptor
/// the checks ran on, named after the session, removed once the
/// supervisor has ended, or by a later round of the same session. The
/// `scripts` folder is opened (and swept) at the round's first script.
#[derive(Default)]
pub(super) struct Scripts {
    #[cfg(target_os = "macos")]
    pub(super) runtime: Option<File>,
    #[cfg(target_os = "macos")]
    pub(super) me: u32,
    #[cfg(target_os = "macos")]
    pub(super) tag: String,
    /// `None` until the first script; then the folder, if it passed.
    #[cfg(target_os = "macos")]
    pub(super) copies: Option<Option<exec_path::ScriptCopies>>,
    #[cfg(target_os = "macos")]
    pub(super) made: Vec<std::path::PathBuf>,
}

impl Scripts {
    /// macOS: the round's script copies in the runtime root. Only the
    /// holder of the session lock makes one.
    #[cfg(target_os = "macos")]
    pub(super) fn new(runtime: &File, me: u32, tag: String) -> Self {
        Self {
            runtime: runtime.try_clone().ok(),
            me,
            tag,
            copies: None,
            made: Vec::new(),
        }
    }

    /// macOS: the `scripts` folder, opened at the first call after the
    /// copies an earlier round of this session left were swept. A folder
    /// that fails its checks leaves scripts unresolved; other units run.
    /// Fails without the laziness: test_macos_unit_is_one_process_the_relay_execs_into
    /// (a round without scripts makes no folder).
    #[cfg(target_os = "macos")]
    pub(super) fn copies(&mut self) -> Option<&exec_path::ScriptCopies> {
        if self.copies.is_none() {
            let opened = self
                .runtime
                .as_ref()
                .and_then(|r| exec_path::ScriptCopies::open(r.as_fd(), self.me).ok());
            if let Some(c) = &opened {
                c.sweep(&self.tag);
            }
            self.copies = Some(opened);
        }
        self.copies.as_ref()?.as_ref()
    }

    /// The executable the relay runs for `found` and its pin: the file
    /// itself, or on macOS a script's private copy (no pin: the copy is the
    /// user's 0600 file). `None` when the copy cannot be made.
    pub(super) fn executable(
        &mut self,
        found: &exec_path::Found,
        checked: &exec_path::Checked,
    ) -> Option<(Vec<u8>, Option<bingsu_core::command::path::ExecPin>)> {
        #[cfg(target_os = "macos")]
        if found.interpreter.is_some() {
            let tag = self.tag.clone();
            let copy = self.copies()?.copy(checked, &tag).ok()?;
            self.made.push(copy.clone());
            return Some((copy.into_os_string().into_encoded_bytes(), None));
        }
        let _ = checked;
        Some((
            found
                .executable
                .clone()
                .into_os_string()
                .into_encoded_bytes(),
            found.pin,
        ))
    }

    /// The copy `executable` just made, for a unit left out after all.
    pub(super) fn forget_last(&mut self, executable: &[u8]) {
        #[cfg(target_os = "macos")]
        if let (Some(Some(c)), Some(last)) = (&self.copies, self.made.last())
            && last.as_os_str().as_encoded_bytes() == executable
        {
            c.remove(last);
            self.made.pop();
        }
        let _ = executable;
    }

    /// Removes every copy this round made.
    pub(super) fn remove_all(self) {
        #[cfg(target_os = "macos")]
        if let Some(Some(c)) = &self.copies {
            for copy in &self.made {
                c.remove(copy);
            }
        }
    }
}
