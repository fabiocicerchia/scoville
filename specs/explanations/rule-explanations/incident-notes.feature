@domain:explanations @area:rule-explanations @from:scoville/incidents
Feature: Explaining the incident a rule prevents
  Lets an operator who hit a finding read, with `scoville --why`, the kind of real-world incident the rule or amplifier exists to prevent, or a plain admission when that note has not been written yet.

  Background:
    Given scoville is installed on the operator's machine

  @id:explanations.rule-explanations.004 @rule:explanations.incidents.note-printed-for-rule-or-amplifier @verified @source:scoville/incidents.py#INCIDENTS @test:tests/test_scoville.py#test_every_id_has_a_why_body
  Scenario Outline: Asking why a rule or amplifier matters prints the incident it prevents
    Given the rule catalogue has an incident note for <id>
    When the operator runs `scoville --why <id>`
    Then the output has an "INCIDENT CLASS" section
    And that section opens with "<opening>"

    Examples:
      | id            | opening                                             |
      | FS-RM         | The command everyone has already run wrong once.    |
      | GIT-PUSH-F    | A force push replaces the remote branch.            |
      | K8S-DELETE-NS | Deleting a namespace deletes every object inside it |
      | FORCE         | `--force` exists to get past a check.               |

  @id:explanations.rule-explanations.005 @rule:explanations.incidents.missing-note-admitted @verified @source:scoville/why.py#_why_incident @test:tests/test_scoville.py#test_a_rule_with_no_incident_note_says_so_rather_than_padding
  Scenario: A rule with no incident note says so and still gives its one-line reason
    Given the rule catalogue has no incident note for a rule
    When the operator runs `scoville --why` for that rule
    Then the "INCIDENT CLASS" section says "Not written yet. The one-line reason is:" followed by the rule's one-line reason
    And the section says the missing note "is a gap, not a judgement that the rule is uninteresting"

  @id:explanations.rule-explanations.006 @rule:explanations.incidents.coverage-shown @inferred @source:scoville/why.py#why_text
  Scenario: Every explanation reports how many ids have an incident note
    Given the catalogue has incident notes for some of its rule and amplifier ids
    When the operator runs `scoville --why FS-RM`
    Then the last line reads "scoville --list-rules   ·   <noted> of <total> ids have an incident note", where <noted> is the number of ids with a note and <total> is every rule and amplifier id
