# Security Policy

bingsu runs on every prompt and reads your working directory, git repository and environment.
Security issues in it matter, so please report them privately.

## Supported versions

bingsu has no release yet. Once it does, only the latest release receives security fixes.

| Version | Supported |
| -- | -- |
| Latest release | Yes |
| Older releases | No, please upgrade |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it through a [private security advisory](https://github.com/ai-screams/Bingsu/security/advisories/new).
Only the maintainers can see it.

Include as much as you can:

1. What the vulnerability is and where it lives (file, segment, shell integration, config key).
2. Steps to reproduce, with the shell, OS and bingsu version.
3. The impact: what an attacker can do and under what conditions.
4. A suggested fix, if you have one.

## What happens next

| Stage | Target time |
| -- | -- |
| Acknowledgment | 3 days |
| Initial assessment | 7 days |
| Fix and release | Depends on severity, critical issues first |

We will keep you updated, credit you in the release notes unless you prefer otherwise, and publish an advisory once a fix is out.

## Scope

In scope, for example:

- Command or code execution triggered by entering a directory, reading a repository or loading a config
- Escape sequences from untrusted data (branch names, file names, environment values) reaching the terminal unfiltered
- Plugins breaking out of their declared permissions
- Path traversal or unintended file reads and writes
- Leaking secrets such as tokens or environment values into the prompt, logs or share links

Out of scope:

- Bugs without a security impact. Please [open a regular issue](https://github.com/ai-screams/Bingsu/issues).
- Problems that need an attacker who already controls your shell config or your user account.
