//! Names-only evidence from C5's held descriptors, before read confinement.
use crate::{meter::Meter, safe_read::Discovery};
use bingsu_core::{
    collection::path_facts::{ENCODED_MAX, PathFactInput, PathQuery, SiblingSet},
    shorten::SIBLING_PATH_MAX,
};

pub fn collect(roots: &Discovery, query: PathQuery, meter: &mut Meter) -> PathFactInput {
    let (components, level, in_repo) = roots.path_binding();
    let logical = roots.logical();
    let mut facts = PathFactInput {
        in_repo,
        repo_component: level.filter(|_| logical).and_then(|level| {
            components
                .checked_sub(level + 1)
                .and_then(|i| u16::try_from(i).ok())
        }),
        readonly: roots.readonly(meter).ok().flatten(),
        ..PathFactInput::default()
    };
    facts.partial = in_repo.is_none() || facts.readonly.is_none() || !logical;
    if !query.unique || !logical {
        return facts;
    }
    let skip = query.home_component.map_or(0, |home| usize::from(home) + 1);
    let count = components.saturating_sub(skip).min(32);
    let held = roots.ancestors();
    let count = count.min(held.len());
    facts.partial |= components.saturating_sub(skip) > count;
    let mut allocation = meter.path_allocation();
    if allocation
        .reserve(count * std::mem::size_of::<SiblingSet>(), meter)
        .is_err()
    {
        facts.partial = true;
        return facts;
    }
    facts.siblings = Vec::with_capacity(count);
    let mut left = SIBLING_PATH_MAX;
    // Original component order also makes the shared 16 KiB cap deterministic.
    for (offset, ancestor) in held[held.len() - count..].iter().enumerate() {
        let component = (components - count + offset) as u16;
        let (names, complete) = match ancestor.siblings(left, meter) {
            Ok(listing) => {
                let bytes = listing.names.iter().map(Vec::len).sum::<usize>();
                left -= bytes;
                // Transfer the live reservation from the temporary listing to
                // facts while the rest of this collection is being gathered.
                if allocation
                    .reserve(
                        bytes + listing.names.len() * std::mem::size_of::<Vec<u8>>(),
                        meter,
                    )
                    .is_err()
                {
                    facts.partial = true;
                    break;
                }
                (listing.names, listing.complete)
            }
            Err(_) => (Vec::new(), false),
        };
        facts.partial |= !complete;
        facts.siblings.push(SiblingSet {
            component,
            complete,
            names,
        });
    }
    bound_encoding(facts)
}

fn bound_encoding(mut facts: PathFactInput) -> PathFactInput {
    let encoded = 7 + facts
        .siblings
        .iter()
        .map(|set| 5 + set.names.iter().map(|name| 2 + name.len()).sum::<usize>())
        .sum::<usize>();
    if encoded > ENCODED_MAX {
        facts.siblings.clear();
        facts.partial = true;
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoded_fact_cap_discards_lists_without_losing_observations() {
        let mut facts = PathFactInput {
            in_repo: Some(true),
            repo_component: Some(0),
            readonly: Some(false),
            ..Default::default()
        };
        for component in 0..32 {
            facts.siblings.push(SiblingSet {
                component,
                complete: false,
                names: vec![b"ab".to_vec(); 256],
            });
        }
        let result = bound_encoding(facts);
        assert!(result.partial);
        assert!(result.siblings.is_empty());
        assert_eq!(result.in_repo, Some(true));
        assert_eq!(result.repo_component, Some(0));
        assert_eq!(result.readonly, Some(false));
    }
}
