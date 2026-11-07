@domain:repo-policy @area:rule-overrides @from:scoville/overrides
Feature: Re-rating commands for a repository
  Lets a team tell scoville, in a reviewed .scovillerc file, that a command is routine, forbidden or differently risky in their repository, so the gate stays switched on instead of being turned off the first time it blocks legitimate work.

  Background:
    Given a repository whose .scovillerc is in force for the analysed commands

  @id:repo-policy.rule-overrides.001 @rule:policy.overrides.allow-keeps-score-but-opens-gate @verified @source:scoville/overrides.py#apply_overrides @test:tests/test_scoville.py#test_allow_keeps_the_real_score_but_does_not_trip_the_gate @test:tests/test_scoville.py#test_an_unallowed_command_still_trips_the_gate
  Scenario Outline: An allowed command keeps its real score but does not trip the gate
    Given the .scovillerc allows "kubectl delete ns ci-*" because "routine CI teardown"
    When the operator scores "<command>" with --fail-on high
    Then the command is reported at level "<level>" with score <score>
    And only the command the allow matches has a factor trace ending with "allowed by .scovillerc: routine CI teardown (scored high, does not trip --fail-on)"
    And scoville exits with status <exit>

    Examples:
      | command                   | level | score | exit |
      | kubectl delete ns ci-1234 | high  | 80    | 0    |
      | kubectl delete ns prod    | critical | 95 | 1    |

  @id:repo-policy.rule-overrides.002 @rule:policy.overrides.deny-forces-critical @verified @source:scoville/overrides.py#apply_overrides @test:tests/test_scoville.py#test_deny_forces_critical_whatever_the_command_scores
  Scenario: A denied command is critical whatever it would otherwise score
    Given the .scovillerc denies "*--context prod*" because "prod goes through the pipeline"
    When the operator scores "kubectl get pods --context prod-eu"
    Then the command is reported at level "critical" with score 100
    And the factor trace ends with "denied by .scovillerc: prod goes through the pipeline"

  @id:repo-policy.rule-overrides.003 @rule:policy.overrides.rescore-pins-band @verified @source:scoville/overrides.py#apply_overrides @test:tests/test_scoville.py#test_rescore_pins_the_band_and_says_what_moved
  Scenario: A re-scored command is pinned to the named band and says what moved
    Given the .scovillerc re-scores "terraform apply*" to "critical" because "shared state"
    When the operator scores "terraform apply"
    Then the command is reported at level "critical" with score 85
    And the factor trace ends with "re-scored medium → critical by .scovillerc: shared state"

  @id:repo-policy.rule-overrides.004 @rule:policy.overrides.deny-beats-allow @verified @source:scoville/overrides.py#load_config @test:tests/test_scoville.py#test_deny_beats_allow_when_both_match
  Scenario Outline: A deny holds even when an allow also matches the command
    Given the .scovillerc allows "rm *" because "we delete a lot"
    And the .scovillerc denies "rm -rf /*" because "no"
    When the operator scores "<command>"
    Then the override applied to the command is "<action>"

    Examples:
      | command      | action |
      | rm -rf /var  | deny   |
      | rm notes.txt | allow  |

  @id:repo-policy.rule-overrides.005 @rule:policy.overrides.allow-survives-strict @verified @source:scoville/overrides.py#gated @test:tests/test_scoville.py#test_strict_does_not_defeat_an_allow
  Scenario: An allowed unknown command still passes the gate under strict mode
    Given the .scovillerc allows "frobnicate *" because "ours"
    When the operator scores "frobnicate the-thing" with --strict and --fail-on medium
    Then scoville exits with status 0
    And without the .scovillerc the same run exits with status 1

  @id:repo-policy.rule-overrides.006 @rule:policy.overrides.reason-required @verified @source:scoville/overrides.py#_parse_entry @test:tests/test_scoville.py#test_every_override_must_state_a_reason
  Scenario: Every override must state why it exists
    Given the .scovillerc allows "rm *" without giving a reason
    When the operator scores any command
    Then scoville refuses the config with "needs a `why` — an unexplained override is one nobody can safely remove later"
    And scoville exits with status 64

  @id:repo-policy.rule-overrides.007 @rule:policy.overrides.malformed-config-refused @verified @source:scoville/overrides.py#load_config @test:tests/test_scoville.py#test_a_malformed_config_is_refused_not_guessed_at
  Scenario Outline: A config that cannot be read as written is refused, not guessed at
    Given the .scovillerc contains <content>
    When the operator scores any command
    Then scoville refuses the config with a message containing "<message>"
    And no command is scored
    And scoville exits with status 64

    Examples:
      | content                           | message            |
      | a rescore entry with level "nope" | must be one of     |
      | an unknown top-level key "oops"   | unknown key        |
      | an allow entry with no match glob | needs a `match`    |
      | a list instead of an object       | expected an object |
      | text that is not JSON             | not valid JSON     |

  @id:repo-policy.rule-overrides.008 @rule:policy.overrides.visible-in-json @verified @source:scoville/overrides.py#apply_overrides @test:tests/test_scoville.py#test_an_override_is_visible_in_json
  Scenario: An overridden command says which override applied in JSON output
    Given the .scovillerc re-scores "terraform apply*" to "critical" because "shared state"
    When the operator scores "terraform apply" with --format json
    Then the command's "override" object has action "rescore", match "terraform apply*", level "critical" and why "shared state"
    And the override object does not name the config file it came from
