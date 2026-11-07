@domain:explanations @area:rule-explanations @from:scoville/why
Feature: Explaining why a rule scores what it does
  Lets an operator who disagrees with a score, or wants to learn from one, read the long form for any rule or amplifier: what it matches, the incident it prevents, why its band, the safer alternative and its neighbours.

  Background:
    Given scoville ships with its built-in rule and amplifier catalogue

  @id:explanations.rule-explanations.007 @rule:explanations.rule-explanations.headline-matches-the-score @verified @source:scoville/why.py#why_text @test:tests/test_scoville.py#test_the_derived_view_cannot_disagree_with_the_score @test:tests/test_scoville.py#test_every_id_has_a_why_body @test:tests/test_scoville.py#test_a_rule_scoring_at_all_explains_its_band_and_its_alternative
  Scenario: A rule's explanation states the same base, band, blast radius and reversibility the scorer uses
    Given the rule K8S-DELETE-NS has base 80, blast radius cluster and is irreversible
    When the operator asks scoville why K8S-DELETE-NS
    Then the first line reads "K8S-DELETE-NS  ·  base 80 (high)  ·  scope: cluster  ·  irreversible"
    And the explanation has the sections MATCHES, INCIDENT CLASS, WHY THIS BAND and SAFER
    And the MATCHES section lists kubectl and oc and the argument pattern the rule matches on

  @id:explanations.rule-explanations.008 @rule:explanations.rule-explanations.amplifier-ids-resolve-in-any-spelling @verified @source:scoville/why.py#entry_by_id @test:tests/test_scoville.py#test_why_accepts_an_amplifier_id_in_the_spelling_list_rules_prints
  Scenario Outline: An amplifier can be asked about with or without its leading plus and in any case
    Given FORCE is an amplifier worth +12 and INTERACTIVE is a softener worth -12
    When the operator asks scoville why <spelling>
    Then the same explanation is printed for every spelling
    And its first line starts with "+<id>" and its signed weight, labelled <kind>
    And it has a MATCHES and an INCIDENT CLASS section but no WHY THIS BAND or SAFER section

    Examples:
      | spelling     | id          | kind      |
      | +FORCE       | FORCE       | amplifier |
      | FORCE        | FORCE       | amplifier |
      | force        | FORCE       | amplifier |
      | +interactive | INTERACTIVE | softener  |

  @id:explanations.rule-explanations.009 @rule:explanations.rule-explanations.missing-incident-note-is-admitted @verified @source:scoville/why.py#_why_incident @test:tests/test_scoville.py#test_a_rule_with_no_incident_note_says_so_rather_than_padding
  Scenario: A rule with no incident write-up says so and still gives its one-line reason
    Given a rule has no incident note written for it
    When the operator asks scoville why that rule
    Then the INCIDENT CLASS section starts "Not written yet. The one-line reason is:" followed by the rule's reason
    And it states that the missing note is a gap, not a judgement that the rule is uninteresting

  @id:explanations.rule-explanations.010 @rule:explanations.rule-explanations.band-shows-reachable-worst-case @inferred @source:scoville/why.py#_why_band
  Scenario: The band explanation shows how far the rule's own amplifiers can push it, capped at 100
    Given a rule has amplifiers registered for its binaries
    When the operator asks scoville why that rule
    Then WHY THIS BAND names the largest of those amplifiers and the score and band the rule reaches where it applies, never above 100
    And up to eight of those amplifiers are listed with their signed weights, largest first
    And up to six softeners for the same binaries are listed under "Asking for it carefully scores below asking for it carelessly"
    And it notes that generic signals such as --force, -y and a production target apply on top of any command

  @id:explanations.rule-explanations.011 @rule:explanations.rule-explanations.safer-alternative-or-admitted-gap @inferred @source:scoville/why.py#_why_safer
  Scenario Outline: The explanation gives the safer alternative, or says plainly when a risky rule has none recorded
    Given a rule with base <base> and <advice>
    When the operator asks scoville why that rule
    Then the SAFER section reads <safer>

    Examples:
      | base       | advice                                  | safer                                                                                                            |
      | 80         | the advice "export the namespace first" | the recorded advice                                                                                              |
      | 35 or more | no advice recorded                      | "No alternative recorded. For a rule at this level that is a gap in the rule, not a statement that none exists." |
      | below 35   | no advice recorded                      | "Nothing to avoid — this is not a destructive rule."                                                             |

  @id:explanations.rule-explanations.012 @rule:explanations.rule-explanations.specific-rule-beats-verb-classifier @inferred @source:scoville/why.py#_why_related
  Scenario Outline: A specific rule's explanation names the generic verb classifier it overrides
    Given K8S-DELETE is the generic kubectl delete classifier at base 55
    And K8S-DELETE-NS is a specific rule on the same binaries
    When the operator asks scoville why <id>
    Then <shows>

    Examples:
      | id            | shows                                                                                                          |
      | K8S-DELETE-NS | RELATED lists "beats K8S-DELETE (55), the verb classifier" and MATCHES says specificity wins before score does |
      | K8S-DELETE    | MATCHES says it is a verb classifier and any specific rule beats it, including one that scores lower           |
