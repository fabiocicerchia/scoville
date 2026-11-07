@domain:risk-scoring @area:unknown-commands @from:scoville/scoring
Feature: Scoring commands no rule recognises
  Tells an operator when a command is unreviewed, and lets strict mode refuse to treat unknown as harmless.

  Background:
    Given no rule recognises `frobnicate` or `frobctl`

  @id:risk-scoring.unknown-commands.001 @rule:risk.unknown.strict-is-medium @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_unknown_command_is_low_unless_strict
  Scenario Outline: An unknown command is safe by default and medium under strict mode
    When the operator scores `frobnicate --all` <mode>
    Then the level is <level>
    And the finding is marked as not known

    Examples:
      | mode             | level  |
      | without --strict | safe   |
      | with --strict    | medium |

  @id:risk-scoring.unknown-commands.002 @rule:risk.unknown.destructive-verb-floor @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_an_unknown_cli_with_a_destructive_verb_is_never_safe
  Scenario: An unknown CLI with a destructive verb is never safe
    When the operator scores `frobctl delete cluster prod`
    Then the level is high
    And the finding is marked as not known
    And `frobctl list` is still safe
