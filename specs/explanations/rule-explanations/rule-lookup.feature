@domain:explanations @area:rule-explanations @from:scoville/cli
Feature: Looking up why a rule fired
  Lets an operator who sees a finding read what the rule guards against, or browse every rule, without opening the code.

  @id:explanations.rule-explanations.001 @rule:explanations.rule-explanations.why-prints-long-form @verified @source:scoville/cli.py#_why @test:tests/test_scoville.py#test_why_accepts_an_amplifier_id_in_the_spelling_list_rules_prints
  Scenario Outline: Asking about a rule or amplifier prints its explanation and scores nothing
    When the operator asks scoville to explain "<id>"
    Then stdout shows that rule's long-form explanation
    And no command is read or scored
    And the exit status is 0

    Examples:
      | id            |
      | K8S-DELETE-NS |
      | FORCE         |
      | +FORCE        |
      | force         |

  @id:explanations.rule-explanations.002 @rule:explanations.id-suggestions.unknown-id-suggests @verified @source:scoville/cli.py#_why @test:tests/test_scoville.py#test_an_unknown_id_exits_64_and_suggests_a_near_miss @test:tests/test_scoville.py#test_an_id_with_no_near_miss_points_at_list_rules
  Scenario Outline: An unknown rule id is refused with the closest ids, or a pointer to the full list
    When the operator asks scoville to explain "<id>"
    Then stderr says there is no rule or amplifier called that id
    And stderr then shows <hint>
    And the exit status is 64

    Examples:
      | id                   | hint                                     |
      | K8S-DELETE-NAMESPACE | a did-you-mean line naming K8S-DELETE-NS |
      | zzzzzzzz             | a pointer to --list-rules                |

  @id:explanations.rule-explanations.003 @rule:explanations.rule-listing.list-every-rule @verified @source:scoville/cli.py#_list_rules @test:tests/test_scoville.py#test_list_rules @questionable
  Scenario: Listing rules prints every rule and amplifier with its points and the commands it matches
    When the operator lists the rules
    Then each rule shows its id, base score, up to six matched commands and its reason
    And each amplifier shows its id with a plus sign, its signed points, up to four matched commands or any, and its reason
    And the exit status is 0
