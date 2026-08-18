# scoville

Risk posture for shell commands, before you run them: a score, a blast radius,
a reversibility verdict, and every factor that contributed.

- [Getting Started](getting-started.md) — install, first run, day-to-day use.
- [Scoring](scoring.md) — bands, the two facets, the pepper scale, calibration.
- [Rules](rules.md) — what the rule set covers and how the long tail is handled.
- [Architecture](architecture.md) — how a command becomes a score.
- [Known limits](limits.md) — where the tool stops, and what it is not.

Two references sit in the repository root because they are generated and
executed by the test suite:

- [BEHAVIOUR.md](https://github.com/fabiocicerchia/scoville/blob/main/BEHAVIOUR.md)
  — the scoring order, precedence, carrier weights, introspection, and the full
  limitations section.
- [INVENTORY.md](https://github.com/fabiocicerchia/scoville/blob/main/INVENTORY.md)
  — every command scoville is calibrated against, with the band, scope and
  reversibility each one gets.
