//! The editor's state and what each key does to it. Pure: a key comes in
//! with the id of the read that brought it ([`Input`]), and the result says
//! what the caller does next ([`Effect`]).
//!
//! Each row holds three values: what the target file
//! writes (`written`, maybe nothing), what it inherits when it writes
//! nothing (the sources before it, else the default: for the four part
//! rows the effective preset's own value), and the effective value, which a
//! source after the target can cover. A pick writes only what differs from
//! the inherited value; Backspace removes the target's own value.
//!
//! One step of undo: the state before the last change is kept, and `u`
//! swaps it with the current one, so `u` twice comes back.
use super::layers::Layers;
use super::rows::{self, Row};
use crate::config::starter::{Icons as StarterIcons, Mode as StarterMode};
use crate::config::tree::Format;

/// One key, as the key reader gives it (the variants of `keys::Key`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Printable ASCII, Space to `~`.
    Char(u8),
    Enter,
    Tab,
    BackTab,
    Backspace,
    Esc,
    Up,
    Down,
    Right,
    Left,
    /// Another C0 control byte by its letter: `Ctrl(b'c')` is 0x03.
    Ctrl(u8),
}

/// A key and the read it came in. Keys of one read share the id; a later
/// read has a larger one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub key: Key,
    pub read: u64,
}

/// The file the editor is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// No settings file yet: saving makes one.
    New,
    /// A file in this format is there: it is never changed, the editor
    /// shows what to change in it.
    Existing(Format),
}

/// Values given on the command line (`--icons`, `--mode`): the editor
/// starts with them, marked to be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Given {
    pub icons: Option<StarterIcons>,
    pub mode: Option<StarterMode>,
}

/// `v` when it is one of `row`'s values.
fn valid(row: Row, v: Option<u8>) -> Option<u8> {
    v.filter(|v| usize::from(*v) < row.values().len())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Main,
    /// The list of every key.
    Keys,
    /// What saving does; `opened` is the read whose Enter opened it.
    Save {
        opened: u64,
    },
}

/// What the caller does after a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Nothing changed.
    None,
    /// The state changed: draw a frame.
    Draw,
    /// Ctrl-L: draw the whole screen again.
    Redraw,
    /// Leave, writing nothing.
    Quit,
    /// Ctrl-C: leave at once, writing nothing.
    Cancel,
    /// Ctrl-Z: stop.
    Suspend,
    /// Save confirmed for a new file: write `write::new_file_text`.
    Write,
    /// Save confirmed for an existing file: print the changes and leave.
    Report,
}

/// A one-time message for the status line, from the last key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// A preset change took the four part keys this file wrote.
    PartsReset,
    Undone,
    Restarted,
    QuitAgain,
}

impl Note {
    pub const fn text(self) -> &'static str {
        match self {
            Note::PartsReset => "ends and joint reset; u undoes",
            Note::Undone => "undone; u again brings it back",
            Note::Restarted => "back to the start; u undoes",
            Note::QuitAgain => "press q again to quit without saving",
        }
    }
}

/// What a change replaces, and what `u` brings back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    written: [Option<u8>; 8],
    /// A shape row was changed: icons no longer pick the preset.
    shaped: bool,
}

const PARTS: [Row; 4] = [Row::Outer, Row::Joint, Row::Inner, Row::Gap];

#[derive(Clone, Debug)]
pub struct Model {
    layers: Layers,
    target: Target,
    state: State,
    start: State,
    /// What the target wrote when the editor opened (nothing for a new
    /// file): an existing file's changes are the difference from it.
    original: [Option<u8>; 8],
    undo: Option<State>,
    /// The icons row was changed once: the hint about boxes goes.
    icons_changed: bool,
    row: Row,
    screen: Screen,
    /// The read of a first `q` that needs a second one.
    quit_pending: Option<u64>,
    note: Option<Note>,
    too_small: bool,
    /// The settings folder cannot be trusted: nothing can be written.
    read_only: bool,
}

impl Model {
    /// A new file starts with Nerd Font icons and the preset they pick;
    /// an existing one with what it writes. `given` values start written in either.
    /// Values of `layers` that are not one of their row's values (the
    /// struct is public) count as none.
    pub fn new(mut layers: Layers, target: Target, given: Given) -> Self {
        for row in Row::ALL {
            let l = &mut layers.rows[row.index()];
            l.earlier = valid(row, l.earlier);
            l.written = valid(row, l.written);
            l.later = l.later.filter(|(v, _)| valid(row, Some(*v)).is_some());
        }
        let icons = given
            .icons
            .and_then(|g| StarterIcons::ALL.iter().position(|i| *i == g))
            .map(|i| i as u8);
        let mode = given
            .mode
            .and_then(|g| rows::MODES.iter().position(|w| *w == g.word()))
            .map(|i| i as u8);
        let original = core::array::from_fn(|i| layers.rows[i].written);
        let mut m = Self {
            layers,
            target,
            state: State {
                written: original,
                shaped: false,
            },
            start: State {
                written: original,
                shaped: false,
            },
            original,
            undo: None,
            icons_changed: false,
            row: Row::Style,
            screen: Screen::Main,
            quit_pending: None,
            note: None,
            too_small: false,
            read_only: false,
        };
        let mut s = m.state;
        if target == Target::New {
            let first = icons.unwrap_or(0);
            s = m.picked(s, Row::Icons, first);
            s = m.picked(s, Row::Style, rows::icons_preset(first));
        }
        if let Some(i) = icons {
            s.written[Row::Icons.index()] = Some(i);
        }
        if let Some(c) = mode {
            s.written[Row::Colors.index()] = Some(c);
        }
        // The preset the icons picked is not the user's: icons go on
        // picking it.
        s.shaped = false;
        m.state = s;
        m.start = s;
        m
    }

    pub fn target(&self) -> Target {
        self.target
    }
    pub fn layers(&self) -> &Layers {
        &self.layers
    }
    pub fn row(&self) -> Row {
        self.row
    }
    pub fn screen(&self) -> Screen {
        self.screen
    }
    pub fn note(&self) -> Option<Note> {
        self.note
    }
    /// The hint about boxes or blanks: until the icons row is changed.
    pub fn icons_hint(&self) -> bool {
        !self.icons_changed
    }
    /// The settings folder could not be trusted (`fs_trust::walk_verdict`):
    /// the save screen says so and confirming it writes nothing.
    pub fn set_read_only(&mut self, yes: bool) {
        self.read_only = yes;
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    /// Only `q`, Ctrl-C, Ctrl-Z and Ctrl-L do anything while the screen is
    /// too small to draw the editor (`screen::too_small`).
    pub fn set_too_small(&mut self, small: bool) {
        self.too_small = small;
    }

    /// What the target writes for `row` now.
    pub fn written(&self, row: Row) -> Option<u8> {
        self.state.written[row.index()]
    }
    /// What the target wrote when the editor opened.
    pub fn original(&self, row: Row) -> Option<u8> {
        self.original[row.index()]
    }

    fn default_in(&self, s: &State, row: Row) -> u8 {
        match row {
            Row::Style => 1,
            Row::Outer | Row::Joint | Row::Inner | Row::Gap => {
                rows::preset_part(row, self.effective_in(s, Row::Style))
            }
            Row::Icons => 2,
            Row::Colors | Row::Lines => 0,
        }
    }
    fn inherited_in(&self, s: &State, row: Row) -> u8 {
        self.layers.rows[row.index()]
            .earlier
            .unwrap_or_else(|| self.default_in(s, row))
    }
    fn effective_in(&self, s: &State, row: Row) -> u8 {
        let l = &self.layers.rows[row.index()];
        match (l.later, l.later_keys[row.value_key()]) {
            (Some((v, _)), _) => v,
            // A later source sets the key to a value outside the row's list
            // (`config check` refuses it): this file's value is covered all
            // the same, and the row shows the default.
            (None, Some(_)) => self.default_in(s, row),
            (None, None) => s.written[row.index()].unwrap_or_else(|| self.inherited_in(s, row)),
        }
    }
    fn chosen_in(&self, s: &State, row: Row) -> u8 {
        s.written[row.index()].unwrap_or_else(|| self.inherited_in(s, row))
    }

    /// The value `row` has when the target writes nothing for it.
    pub fn inherited(&self, row: Row) -> u8 {
        self.inherited_in(&self.state, row)
    }
    /// The value of `row` with every source merged: what the prompt draws.
    pub fn effective(&self, row: Row) -> u8 {
        self.effective_in(&self.state, row)
    }
    /// The value the target gives `row` (written, else inherited): what the
    /// row shows as picked, even when a later source covers it.
    pub fn chosen(&self, row: Row) -> u8 {
        self.chosen_in(&self.state, row)
    }
    /// The later source that covers `row`, by its index in `Layers::names`.
    pub fn covered_by(&self, row: Row) -> Option<usize> {
        let keys = self.layers.rows[row.index()].later_keys;
        keys[row.value_key()].or(keys.into_iter().flatten().next())
    }
    /// The later source that covers key number `key` of `row`
    /// (`Row::keys`), by its place in `Layers::names`.
    pub fn covered_key(&self, row: Row, key: usize) -> Option<usize> {
        self.layers.rows[row.index()]
            .later_keys
            .get(key)
            .copied()
            .flatten()
    }

    /// Whether `row` is marked: for a new file, a key it will write
    /// (`style.preset` always); for an existing one, a key to
    /// change.
    pub fn marked(&self, row: Row) -> bool {
        match self.target {
            Target::New => row == Row::Style || self.written(row).is_some(),
            Target::Existing(_) => self.written(row) != self.original(row),
        }
    }

    /// Something differs from how the editor opened.
    pub fn changed(&self) -> bool {
        self.state.written != self.start.written
    }

    /// The style options the shape rows draw with (effective values).
    pub fn options(&self) -> crate::style::StyleOptions {
        let e = |r| self.effective(r);
        rows::options(
            e(Row::Style),
            e(Row::Outer),
            e(Row::Joint),
            e(Row::Inner),
            e(Row::Gap),
        )
    }

    /// `s` with `v` picked for `row`: written only when it differs from the
    /// inherited value, so a key equal to it is not written (and one already
    /// written is taken out).
    fn picked(&self, s: State, row: Row, v: u8) -> State {
        let mut n = s;
        let inherited = self.inherited_in(&n, row);
        n.written[row.index()] = (v != inherited).then_some(v);
        if Row::SHAPE.contains(&row) {
            n.shaped = true;
        }
        n
    }

    /// Makes `next` the state, keeping the one before for `u`. A change of
    /// this file's preset takes the part keys this file wrote; icons pick the preset of a new file until a shape row was
    /// changed.
    fn change(&mut self, mut next: State) -> Effect {
        if self.target == Target::New
            && !next.shaped
            && self.chosen_in(&next, Row::Icons) != self.chosen(Row::Icons)
        {
            let p = rows::icons_preset(self.chosen_in(&next, Row::Icons));
            let shaped = next.shaped;
            next = self.picked(next, Row::Style, p);
            next.shaped = shaped;
        }
        let mut note = None;
        // This file's own preset choice, also when a later file covers the
        // preset: the part keys belong to the preset this file picks.
        if self.chosen_in(&next, Row::Style) != self.chosen(Row::Style) {
            for r in PARTS {
                if next.written[r.index()].take().is_some() {
                    note = Some(Note::PartsReset);
                }
            }
        }
        if next.written[Row::Icons.index()] != self.written(Row::Icons) {
            self.icons_changed = true;
        }
        if next == self.state {
            return Effect::None;
        }
        self.undo = Some(self.state);
        self.state = next;
        self.note = note;
        Effect::Draw
    }

    /// Picks the value after (`+1`) or before (`-1`) the chosen one.
    fn step(&mut self, row: Row, by: i8) -> Effect {
        let n = row.values().len() as i16;
        let v = (i16::from(self.chosen(row)) + i16::from(by)).rem_euclid(n) as u8;
        self.pick(row, v)
    }

    /// Picks value `v` (an index of `row.values()`) for `row`.
    pub fn pick(&mut self, row: Row, v: u8) -> Effect {
        if usize::from(v) >= row.values().len() {
            return Effect::None;
        }
        let next = self.picked(self.state, row, v);
        self.change(next)
    }

    /// Backspace: the target stops writing `row`, which then has the
    /// inherited value.
    pub fn remove_override(&mut self, row: Row) -> Effect {
        let mut next = self.state;
        next.written[row.index()] = None;
        if Row::SHAPE.contains(&row) {
            next.shaped = true;
        }
        self.change(next)
    }

    /// `r`: every row back to how the editor opened.
    pub fn restart(&mut self) -> Effect {
        if self.state == self.start {
            return Effect::None;
        }
        self.undo = Some(self.state);
        self.state = self.start;
        self.note = Some(Note::Restarted);
        Effect::Draw
    }

    /// `u`: swaps the state with the one before the last change.
    pub fn undo(&mut self) -> Effect {
        let Some(before) = self.undo else {
            return Effect::None;
        };
        self.undo = Some(self.state);
        self.state = before;
        self.note = Some(Note::Undone);
        Effect::Draw
    }

    fn quit(&mut self, pending: Option<u64>, read: u64) -> Effect {
        if !self.changed() {
            return Effect::Quit;
        }
        // Only a press from a later read confirms: keys of one read may be
        // a paste the key reader could not tell from typing.
        match pending {
            Some(first) if read > first => Effect::Quit,
            _ => {
                self.quit_pending = Some(read);
                self.note = Some(Note::QuitAgain);
                Effect::Draw
            }
        }
    }

    /// One key.
    pub fn handle(&mut self, i: Input) -> Effect {
        let pending = self.quit_pending.take();
        match i.key {
            Key::Ctrl(b'c') => return Effect::Cancel,
            Key::Ctrl(b'z') => {
                self.quit_pending = pending;
                return Effect::Suspend;
            }
            Key::Ctrl(b'l') => {
                self.quit_pending = pending;
                return Effect::Redraw;
            }
            Key::Char(b'q') => return self.quit(pending, i.read),
            _ => {}
        }
        let had_note = self.note.take().is_some();
        // A key that changes nothing still takes the last key's message off
        // the screen (a pending `q` always has one).
        let drawn = |e: Effect| match e {
            Effect::None if had_note => Effect::Draw,
            e => e,
        };
        if self.too_small {
            return drawn(Effect::None);
        }
        let e = match self.screen {
            Screen::Main => self.main_key(i),
            Screen::Keys => match i.key {
                Key::Esc | Key::Char(b'?') => {
                    self.screen = Screen::Main;
                    Effect::Draw
                }
                _ => Effect::None,
            },
            Screen::Save { opened } => match i.key {
                Key::Enter | Key::Char(b'y') if i.read > opened => match self.target {
                    Target::New if self.read_only => Effect::None,
                    Target::New => Effect::Write,
                    Target::Existing(_) => Effect::Report,
                },
                Key::Esc => {
                    self.screen = Screen::Main;
                    Effect::Draw
                }
                _ => Effect::None,
            },
        };
        drawn(e)
    }

    fn main_key(&mut self, i: Input) -> Effect {
        let move_by = |m: &mut Self, by: i8| {
            let n = Row::ALL.len() as i8;
            let at = (m.row.index() as i8 + by).rem_euclid(n);
            m.row = Row::ALL[at as usize];
            Effect::Draw
        };
        match i.key {
            Key::Up | Key::BackTab => move_by(self, -1),
            Key::Down | Key::Tab => move_by(self, 1),
            Key::Left => self.step(self.row, -1),
            Key::Right | Key::Char(b' ') => self.step(self.row, 1),
            Key::Backspace => self.remove_override(self.row),
            Key::Enter => {
                self.screen = Screen::Save { opened: i.read };
                Effect::Draw
            }
            Key::Char(b'u') => self.undo(),
            Key::Char(b'r') => self.restart(),
            Key::Char(b'?') => {
                self.screen = Screen::Keys;
                Effect::Draw
            }
            Key::Char(c @ b'1'..=b'9') => self.pick(self.row, c - b'1'),
            Key::Char(c) => match Row::by_key(c.to_ascii_lowercase()) {
                Some(r) => {
                    self.row = r;
                    self.step(r, if c.is_ascii_uppercase() { -1 } else { 1 })
                }
                None => Effect::None,
            },
            _ => Effect::None,
        }
    }
}
