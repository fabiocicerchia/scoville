@domain:risk-catalogue @area:catalogue-integrity @from:scoville/catalog
Feature: Refusing malformed catalogue entries
  Protects maintainers and anyone extending scoville's rule set from shipping a rule or amplifier whose scope, reversibility or pattern the scorer cannot read, by refusing it when the catalogue is loaded.

  @id:risk-catalogue.catalogue-integrity.001 @rule:catalogue.entries.scope-must-be-defined @verified @source:scoville/catalog.py#_check @test:tests/test_scoville.py#test_tables_reject_a_bad_scope
  Scenario Outline: A catalogue entry naming an undefined blast radius is refused
    Given the defined blast radii are none, file, directory, container, host, network, cluster and account
    When the maintainer defines a <entry> "<id>" with blast radius "<scope>"
    Then the entry is refused with an error
    And the error reads "<id>: unknown scope '<scope>'"

    Examples:
      | entry     | id | scope                           |
      | rule      | X  | not-a-scope                     |
      | amplifier | Y  | some advice that is not a scope |

  @id:risk-catalogue.catalogue-integrity.002 @rule:catalogue.entries.reversibility-must-be-defined @inferred @source:scoville/catalog.py#_check
  Scenario: A catalogue entry naming an undefined reversibility is refused
    Given the defined reversibility levels are reversible, recoverable and irreversible
    When the maintainer defines a rule "X" with blast radius "file" and reversibility "undoable"
    Then the rule is refused with an error
    And the error reads "X: unknown reversibility 'undoable'"

  @id:risk-catalogue.catalogue-integrity.003 @rule:catalogue.rules.scope-and-reversibility-required @inferred @source:scoville/catalog.py#R @questionable
  Scenario Outline: A rule must name both its blast radius and its reversibility
    When the maintainer defines a rule "X" that leaves its <missing> unset
    Then the rule is refused with an error
    And the error reads "X: unknown <word> None"

    Examples:
      | missing       | word          |
      | blast radius  | scope         |
      | reversibility | reversibility |

  @id:risk-catalogue.catalogue-integrity.004 @rule:catalogue.amplifiers.scope-and-reversibility-optional @inferred @source:scoville/catalog.py#A
  Scenario: An amplifier may leave blast radius and reversibility unset
    When the maintainer defines an amplifier "Y" with no blast radius and no reversibility
    Then the amplifier is accepted
    And the amplifier leaves the command's blast radius and reversibility unchanged

  @id:risk-catalogue.catalogue-integrity.005 @rule:catalogue.entries.pattern-must-compile @inferred @source:scoville/catalog.py#A @questionable
  Scenario: A catalogue entry with a malformed pattern is refused
    When the maintainer defines an amplifier "Y" whose pattern is "(--force"
    Then the amplifier is refused with a pattern error
    And the error does not name "Y"
