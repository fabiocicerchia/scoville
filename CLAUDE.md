# CLAUDE.md

Guidance for Claude Code (and other AI agents) working in this repo.

## Project

scoville is a single-file, zero-dependency Python 3.10+ CLI that scores the
risk of a shell command before it runs: a 0–100 score, a blast radius, a
reversibility verdict and every factor that contributed. The tool is
`scoville.py` (entry point `scoville:main`); the rule set is data inside that
module. Tests live in `tests/`.

## Commands

```sh
make help       # Show this help
make setup      # Install the pre-commit hook
make install    # Install the package
make dev        # Editable install with dev dependencies
make lint       # Run ruff
make test       # Run tests
make build      # Build sdist and wheel
make inventory  # Regenerate INVENTORY.md from the rule table
```

## The corpus is the calibration

`tests/corpus.tsv` is the source of truth for what each command should score.
`INVENTORY.md` is **generated** from it (`make inventory`) — never edit it by
hand. A rule change that moves a command between bands has to fail the suite
rather than silently recalibrate the tool, so:

- New coverage starts in `corpus.tsv`: add the command and the band you expect,
  then make it pass.
- Rescoring an existing command means changing the corpus deliberately, in the
  same commit, with the reason in the message.
- Regenerate `INVENTORY.md` whenever the corpus or the rule set changes.

`BEHAVIOUR.md` documents the scoring order, precedence and limits. Keep it in
step with the code — it is the contract, not commentary.

## Tooling

Shared config — the GitHub workflows, `.pre-commit-config.yaml`,
`.editorconfig`, `.hadolint.yaml`, `SECURITY.md`, `CONTRIBUTING.md`,
`CODE_OF_CONDUCT.md` — is the portfolio-wide standard, not this repo's own.
Edit it at the source; a local edit is drift and the next sync overwrites it.

- `make setup` installs the pre-commit hook, and that is the whole of it.
  Don't add a `.githooks/` directory: `core.hooksPath` replaces `.git/hooks/`
  wholesale, so setting it silently stops every pre-commit hook from running.
- Hooks and actions are pinned by commit SHA with the tag in a trailing
  comment. A tag can be moved, a SHA cannot.
- CI runs this same `.pre-commit-config.yaml` through `pre-commit/action`, so
  what passes locally is what gates the pull request.

## Releases

release-please runs in manifest mode (`release-please-config.json` +
`.release-please-manifest.json`) with `"draft": true`. Releases are immutable
here, so assets can only be attached while the release is still a draft — the
`release` workflow uploads to the draft and publishes it last. Don't switch
back to an inline `release-type:`; the action has no `draft` input.

## Conventions

- Match existing style; don't reformat unrelated code.
- Use Conventional Commit messages; don't edit CHANGELOG.md by hand
  (release-please generates it).
- Update `docs/` and `examples/` with behaviour changes.
- Never commit secrets; CI runs gitleaks. Keep `.env` out of git.

## Guardrails

- Stdlib only. scoville has no runtime dependencies and that is a feature — it
  is meant to be droppable into a `PreToolUse` hook or a CI image.
- Nothing is ever executed to score it. `--introspect` reads files and runs
  read-only `docker inspect`; it must never pull, run or evaluate.
- Don't touch generated files (`INVENTORY.md`, `*.egg-info/`, `dist/`) by hand.
- Ask before large refactors or destructive operations.
