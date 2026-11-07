@domain:risk-catalogue @area:resource-clis @from:scoville/rules
Feature: Choosing the rule that describes a command
  Operators rely on a command being rated by the rule written for that exact subcommand, not by a coarse verb classifier, so a harmless-sounding verb is not over- or under-rated.

  @id:risk-catalogue.resource-clis.001 @rule:catalogue.precedence.specific-rule-beats-generic-verb @verified @source:scoville/rules.py#RULES @test:tests/test_scoville.py#test_specific_rules_beat_generic_verbs_even_when_lower @questionable
  Scenario: A rule for the exact subcommand wins over the generic verb classification, even when it scores lower
    Given a resource CLI subcommand that has its own rule and also contains a destructive verb
    When the operator scores "virsh destroy vm1"
    Then the command is rated medium
    And it scores lower than "virsh undefine vm1"
