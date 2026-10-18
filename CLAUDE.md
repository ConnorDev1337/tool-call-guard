# Tool-Call Guard - repo conventions

## Publishing and remotes (read before any git push)
This repository is published and maintained **by hand** by the owner. Automated
agents must not publish it.
- **Do not push to any remote.** Never run `git push` (GitHub, GitLab, or
  anything else), `git push --force`, `gh repo create`, or any command that
  uploads commits. The owner reviews changes locally and pushes them manually.
- **Do not add, change, or remove git remotes**, and do not open pull requests
  or create releases.
- Commit locally only; leave uploading to the owner.
- Canonical public home: https://github.com/ConnorDev1337/tool-call-guard
  (GitHub only). There is no GitLab mirror; do not recreate or reference one.

## Commit hygiene
- Author and committer is `ConnorDev <connordev@protonmail.com>`.
- Never add AI-attribution trailers (no `Co-Authored-By: Claude`, no
  "Generated with ..." lines).
- English only. Do not mention the owner's real name or employer anywhere.
