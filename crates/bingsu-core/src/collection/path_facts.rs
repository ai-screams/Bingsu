//! Bounded raw directory evidence. Component indices refer to the original PWD.
use super::wire::{ProtocolError, Reader, add_budget};
use crate::shorten::{self, Anchor, PathFacts};
use alloc::vec::Vec;

pub const SETS_MAX: usize = 32;
pub const ENCODED_MAX: usize = 32_768;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathQuery {
    pub home_component: Option<u16>,
    pub unique: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiblingSet {
    pub component: u16,
    pub complete: bool,
    /// Raw directory order is permitted; only the component sets are sorted.
    pub names: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathFactInput {
    pub repo_component: Option<u16>,
    pub in_repo: Option<bool>,
    pub readonly: Option<bool>,
    pub siblings: Vec<SiblingSet>,
    pub partial: bool,
}

pub(crate) fn components(cwd: &[u8]) -> impl DoubleEndedIterator<Item = &[u8]> {
    cwd.split(|b| *b == b'/').filter(|c| !c.is_empty())
}
fn component(index: u16, count: usize) -> Result<(), ProtocolError> {
    if usize::from(index) >= count {
        return Err(ProtocolError::Schema);
    }
    Ok(())
}
pub(crate) fn read_component(r: &mut Reader<'_>) -> Result<Option<u16>, ProtocolError> {
    let present = r.boolean()?;
    let index = r.u16()?;
    if !present && index != 0 {
        return Err(ProtocolError::Schema);
    }
    Ok(present.then_some(index))
}
fn put_component(out: &mut Vec<u8>, index: Option<u16>) {
    out.push(u8::from(index.is_some()));
    out.extend_from_slice(&index.unwrap_or(0).to_le_bytes());
}
impl PathQuery {
    /// Component-prefix comparison uses hook bytes only, with no path lookup.
    /// A logical dot component cannot establish a physical home boundary.
    pub fn for_path(cwd: &[u8], home: Option<&[u8]>, unique: bool) -> Self {
        let home_component = home.filter(|h| h.first() == Some(&b'/')).and_then(|home| {
            let mut pwd = components(cwd);
            let mut count = 0usize;
            for h in components(home) {
                if pwd.next() != Some(h) {
                    return None;
                }
                count += 1;
            }
            if components(cwd).any(|c| c == b"." || c == b"..") {
                return None;
            }
            count.checked_sub(1).and_then(|i| u16::try_from(i).ok())
        });
        Self {
            home_component,
            unique,
        }
    }
    pub(crate) fn validate(self, cwd: &[u8]) -> Result<(), ProtocolError> {
        if let Some(index) = self.home_component {
            component(index, components(cwd).count())?;
        }
        Ok(())
    }
    pub(crate) fn put(self, out: &mut Vec<u8>) {
        put_component(out, self.home_component);
        out.push(u8::from(self.unique));
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(Self {
            home_component: read_component(r)?,
            unique: r.boolean()?,
        })
    }
}
impl PathFactInput {
    pub fn validate(&self, cwd: &[u8]) -> Result<(), ProtocolError> {
        self.encoded_len(cwd).map(|_| ())
    }
    pub(crate) fn encoded_len(&self, cwd: &[u8]) -> Result<usize, ProtocolError> {
        let count = components(cwd).count();
        if let Some(index) = self.repo_component {
            component(index, count)?;
            if self.in_repo != Some(true) {
                return Err(ProtocolError::Schema);
            }
        }
        if self.siblings.len() > SETS_MAX {
            return Err(ProtocolError::Budget);
        }
        let mut previous = None;
        let mut total = 0;
        let mut len = 7;
        for set in &self.siblings {
            component(set.component, count)?;
            if previous.is_some_and(|p| p >= set.component) {
                return Err(ProtocolError::Schema);
            }
            previous = Some(set.component);
            if set.names.len() > shorten::MAX_SIBLINGS {
                return Err(ProtocolError::Budget);
            }
            len = add_budget(len, 5, ENCODED_MAX)?;
            let mut step = 0;
            for name in &set.names {
                add_budget(0, name.len(), shorten::SIBLING_NAME_MAX)?;
                step = add_budget(step, name.len(), shorten::SIBLING_STEP_MAX)?;
                total = add_budget(total, name.len(), shorten::SIBLING_PATH_MAX)?;
                len = add_budget(len, 2 + name.len(), ENCODED_MAX)?;
            }
        }
        Ok(len)
    }
    pub fn encode(&self, cwd: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let len = self.encoded_len(cwd)?;
        let mut out = Vec::with_capacity(len);
        self.put(&mut out);
        super::wire::checked_encoding(out, len)
    }
    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        put_component(out, self.repo_component);
        for value in [self.in_repo, self.readonly] {
            out.push(match value {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            });
        }
        out.push(u8::from(self.partial));
        out.push(self.siblings.len() as u8);
        for set in &self.siblings {
            out.extend_from_slice(&set.component.to_le_bytes());
            out.push(u8::from(set.complete));
            out.extend_from_slice(&(set.names.len() as u16).to_le_bytes());
            for name in &set.names {
                out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                out.extend_from_slice(name);
            }
        }
    }
    pub fn decode(bytes: &[u8], cwd: &[u8]) -> Result<Self, ProtocolError> {
        // Validate all counts, bytes and indices before copying even one name.
        Self::parse(bytes, cwd, false)?;
        Self::parse(bytes, cwd, true)
    }
    fn parse(bytes: &[u8], cwd: &[u8], copy: bool) -> Result<Self, ProtocolError> {
        add_budget(0, bytes.len(), ENCODED_MAX)?;
        let mut r = Reader::new(bytes);
        let repo_component = read_component(&mut r)?;
        let mut tag = || match r.u8()? {
            0 => Ok(None),
            1 => Ok(Some(false)),
            2 => Ok(Some(true)),
            _ => Err(ProtocolError::Schema),
        };
        let in_repo = tag()?;
        let readonly = tag()?;
        let partial = r.boolean()?;
        let sets = usize::from(r.u8()?);
        let count = components(cwd).count();
        if let Some(index) = repo_component {
            component(index, count)?;
            if in_repo != Some(true) {
                return Err(ProtocolError::Schema);
            }
        }
        if sets > SETS_MAX {
            return Err(ProtocolError::Budget);
        }
        let mut siblings = Vec::with_capacity(if copy { sets } else { 0 });
        let mut previous = None;
        let mut total = 0;
        for _ in 0..sets {
            let index = r.u16()?;
            component(index, count)?;
            if previous.is_some_and(|p| p >= index) {
                return Err(ProtocolError::Schema);
            }
            previous = Some(index);
            let complete = r.boolean()?;
            let names_count = usize::from(r.u16()?);
            if names_count > shorten::MAX_SIBLINGS {
                return Err(ProtocolError::Budget);
            }
            let mut names = Vec::with_capacity(if copy { names_count } else { 0 });
            let mut step = 0;
            for _ in 0..names_count {
                let len = usize::from(r.u16()?);
                add_budget(0, len, shorten::SIBLING_NAME_MAX)?;
                step = add_budget(step, len, shorten::SIBLING_STEP_MAX)?;
                total = add_budget(total, len, shorten::SIBLING_PATH_MAX)?;
                let raw = r.take(len)?;
                if copy {
                    names.push(raw.to_vec());
                }
            }
            if copy {
                siblings.push(SiblingSet {
                    component: index,
                    complete,
                    names,
                });
            }
        }
        r.end()?;
        Ok(Self {
            repo_component,
            in_repo,
            readonly,
            siblings,
            partial,
        })
    }
    /// Resolve indices before `PathFacts::new` trims to MAX_STEPS. Incomplete
    /// raw lists never become uniqueness evidence, even if a prefix looks unique.
    pub fn to_path_facts(&self, cwd: &[u8], query: PathQuery) -> Result<PathFacts, ProtocolError> {
        self.validate(cwd)?;
        query.validate(cwd)?;
        let skip = query.home_component.map_or(0, |i| usize::from(i) + 1);
        let logical = components(cwd).all(|c| c != b"." && c != b"..");
        let count = components(cwd).count();
        let keep_from = skip.max(count.saturating_sub(shorten::MAX_STEPS));
        let steps: Vec<_> = components(cwd).skip(keep_from).collect();
        let raw: Vec<Vec<&[u8]>> = self
            .siblings
            .iter()
            .map(|s| s.names.iter().map(|name| name.as_slice()).collect())
            .collect();
        let mut siblings = alloc::vec![None; steps.len()];
        if logical && query.unique {
            for (set, names) in self.siblings.iter().zip(&raw) {
                if set.complete {
                    if let Some(index) = usize::from(set.component).checked_sub(keep_from) {
                        siblings[index] = Some(names.as_slice());
                    }
                }
            }
        }
        let repo = self
            .repo_component
            .filter(|_| logical)
            .and_then(|i| usize::from(i).checked_sub(keep_from));
        Ok(PathFacts::new(
            if query.home_component.is_some() {
                Anchor::Home
            } else {
                Anchor::Root
            },
            &steps,
            repo,
            &siblings,
        )
        .with_readonly(self.readonly))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        shorten::{Method, ShortenRequest, Source, run_builtin},
        width::WidthProfile,
    };
    // Removing complete gating would claim the partial prefix is unique.
    #[test]
    fn incomplete_names_and_readonly_survive_wire_without_claiming_unique() {
        let cwd = b"/home/alphabet/leaf";
        let query = PathQuery {
            home_component: Some(0),
            unique: true,
        };
        let mut input = PathFactInput {
            in_repo: Some(true),
            repo_component: Some(1),
            readonly: Some(true),
            partial: true,
            siblings: alloc::vec![SiblingSet {
                component: 1,
                complete: false,
                names: alloc::vec![b"alpine".to_vec()]
            }],
        };
        for readonly in [None, Some(false), Some(true)] {
            input.readonly = readonly;
            let decoded = PathFactInput::decode(&input.encode(cwd).unwrap(), cwd).unwrap();
            let facts = decoded.to_path_facts(cwd, query).unwrap();
            assert_eq!(facts.readonly(), readonly);
            let render = |f: &PathFacts| {
                run_builtin(&ShortenRequest {
                    source: Source::Path(f),
                    method: Method::Unique,
                    budget: u32::MAX,
                    profile: WidthProfile::DEFAULT,
                })
                .unwrap()
                .text()
            };
            let oracle = PathFacts::new(Anchor::Home, &[b"alphabet", b"leaf"], Some(0), &[]);
            assert_eq!(render(&facts), render(&oracle));
            input.siblings[0].complete = true;
            assert_ne!(
                render(&input.to_path_facts(cwd, query).unwrap()),
                render(&oracle)
            );
            input.siblings[0].complete = false;
        }
    }
}
