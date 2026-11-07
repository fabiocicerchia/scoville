@domain:risk-scoring @area:score-and-bands @from:scoville/scales
Feature: Naming how risky, how far-reaching and how undoable a command is
  Operators and CI gates act on the band, scope and reversibility scoville reports, so the thresholds and orderings behind them must stay fixed.

  Background:
    Given scoville scores a command by summing its factors and clamping the total to 0–100

  @id:risk-scoring.score-and-bands.001 @rule:risk.bands.score-maps-to-fixed-band @verified @source:scoville/scales.py#band @test:tests/test_scoville.py#test_bands
  Scenario Outline: A score falls into a fixed band from safe to critical
    Given a command whose factors add up to <score>
    When the operator scores the command
    Then the reported score is <score>
    And the reported level is <band>

    Examples:
      | score | band     |
      | 0     | safe     |
      | 14    | safe     |
      | 15    | low      |
      | 34    | low      |
      | 35    | medium   |
      | 59    | medium   |
      | 60    | high     |
      | 84    | high     |
      | 85    | critical |
      | 100   | critical |

  @id:risk-scoring.score-and-bands.002 @rule:risk.scope.widest-factor-wins @inferred @source:scoville/scales.py#widest
  Scenario: A command's blast radius is the widest any of its factors reaches
    Given a command where one factor reaches a single file and another reaches the whole host
    When the operator scores the command
    Then the reported scope is host
    And scopes rank none, file, directory, container, host, network, cluster, account

  @id:risk-scoring.score-and-bands.003 @rule:risk.reversibility.hardest-factor-wins @inferred @source:scoville/scales.py#harder
  Scenario: A command is as hard to undo as its least reversible factor
    Given a command where one factor is irreversible and another is reversible
    When the operator scores the command
    Then the reported reversibility is irreversible
    And reversibility ranks reversible, recoverable, irreversible
