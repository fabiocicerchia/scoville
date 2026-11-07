@domain:risk-scoring @area:score-and-bands @from:scoville/scoring
Feature: Scoring a command
  Gives an operator or a hook one capped score and band per command, so the decision rests on the worst thing the input does.

  @id:risk-scoring.score-and-bands.004 @rule:risk.score.capped-at-100 @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_scores_are_clamped
  Scenario: A score never exceeds 100 however many factors stack up
    Given a command whose factors add up to more than 100 points
    When the operator scores `sudo rm -rf --no-preserve-root / /etc /home`
    Then the score is 100
    And the level is critical

  @id:risk-scoring.score-and-bands.005 @rule:risk.score.specific-rule-beats-generic @verified @source:scoville/scoring.py#pick_rule @test:tests/test_scoville.py#test_specific_rules_beat_generic_verbs_even_when_lower
  Scenario Outline: A rule for the exact subcommand wins over a generic verb rule, even when it scores lower
    Given the CLI has a rule for its exact subcommand and a generic rule for its verb
    When the operator scores `<command>`
    Then the level is <level>
    And `virsh destroy vm1` scores below `virsh undefine vm1`

    Examples:
      | command           | level  |
      | virsh destroy vm1 | medium |

  @id:risk-scoring.score-and-bands.006 @rule:risk.score.flag-counted-once @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_a_rule_does_not_also_collect_the_amp_it_exists_for @test:tests/test_scoville.py#test_a_rule_that_prices_its_own_yes_does_not_double_count
  Scenario: A flag a rule already prices is not counted a second time
    Given the fsck repair rule exists because of its auto-confirm flag
    When the operator scores `fsck -y /dev/sdb1`
    Then the report has no generic auto-confirms factor
    And the generic force factor still applies to `frobctl delete cluster` with a force flag, which has no rule of its own

  @id:risk-scoring.score-and-bands.007 @rule:risk.score.fork-bomb-critical @verified @source:scoville/scoring.py#analyze @test:tests/test_scoville.py#test_fork_bomb @questionable
  Scenario: A fork bomb anywhere in the input is critical
    Given the input contains a fork bomb
    When the operator scores `:(){ :|:& };:`
    Then one finding is reported, scored 100 and critical
    And its scope is host
    And its advice says there is no legitimate reason for this on a machine you care about

  @id:risk-scoring.score-and-bands.008 @rule:risk.score.substitutions-scored-separately @verified @source:scoville/scoring.py#analyze @test:tests/test_scoville.py#test_command_substitution_is_analyzed
  Scenario: A command substitution is scored as a command of its own
    Given a command line embeds `$( … )`
    When the operator scores `echo $(rm -rf /)`
    Then the report has a separate finding for `rm -rf /` marked as a substitution
    And that finding is critical
