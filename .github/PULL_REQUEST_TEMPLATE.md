## What

<!-- What does this pull request change? -->

## Why

<!-- Why is it needed? Link the issue: Closes #000 -->

## How it was verified

<!-- Commands you ran, tests you added, screenshots for visual changes. -->

## Checklist

- [ ] The title follows [Conventional Commits](https://www.conventionalcommits.org/) (`type(scope): summary`); it becomes the squash commit.
- [ ] CI passes locally: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`.
- [ ] New behavior is covered by tests that fail without the change.
- [ ] Visible changes follow the design rules in CONTRIBUTING.md (color tokens, contrast, cell widths, icon fallbacks).
- [ ] No secrets, tokens or personal paths in the diff.
