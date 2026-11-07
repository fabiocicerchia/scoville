@domain:risk-catalogue @area:resource-clis @from:scoville/rules-clis
Feature: Classifying resource CLIs by their verbs
  Gives operators a risk score for any cloud, SaaS, storage or virtualisation CLI from day one, even one nobody wrote a rule for, by reading its verb.

  Background:
    Given scoville recognises the resource CLIs it knows about, among them hcloud, scw, vultr-cli, linode-cli, wrangler, pscale, doctl, gh, openstack, vault and velero

  @id:risk-catalogue.resource-clis.002 @rule:catalogue.resource-clis.verb-sets-the-floor @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_verb_classification_still_carries_the_clis_nobody_promoted @test:tests/test_scoville.py#test_read_verbs_stay_free @test:tests/test_scoville.py#test_write_verbs_sit_between @test:tests/test_scoville.py#test_destructive_verbs_across_cloud_clis @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: A resource CLI's verb sets its risk when no rule names the subcommand
    Given no rule names the "<command>" subcommand
    When the operator scores "<command>"
    Then the level is <level>
    And the blast radius is <blast>
    And the reversibility is <reversibility>

    Examples:
      | command                       | level | blast   | reversibility |
      | hcloud server list            | safe  | none    | reversible    |
      | hcloud server create web-1    | low   | account | recoverable   |
      | hcloud server delete my-db    | high  | account | irreversible  |
      | vultr-cli server delete web-1 | high  | account | irreversible  |

  @id:risk-catalogue.resource-clis.003 @rule:catalogue.resource-clis.first-verb-wins @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_a_resource_named_delete_does_not_make_a_read_destructive
  Scenario: A resource named after a destructive verb does not make a read destructive
    When the operator scores "hcloud server describe delete-me"
    Then the level is safe

  @id:risk-catalogue.resource-clis.004 @rule:catalogue.resource-clis.specific-rule-beats-verb @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_specific_rules_beat_generic_verbs_even_when_lower @test:tests/test_scoville.py#test_doctl_verbs_that_lie @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: A rule written for a subcommand overrides the verb's rating, even when it rates lower
    Given a rule describes what "<command>" actually does
    When the operator scores "<command>"
    Then the level is <level>, not the high a destroy verb would give

    Examples:
      | command                                | level  |
      | virsh destroy vm1                      | medium |
      | doctl projects delete 4e5f6a7b         | low    |
      | vault kv delete kv/app/db              | medium |
      | velero restore delete r1               | medium |
      | argocd cluster rm https://k8s.internal | medium |

  @id:risk-catalogue.resource-clis.005 @rule:catalogue.resource-clis.unlisted-subcommand-falls-back @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_an_unenumerated_subcommand_of_a_promoted_cli_falls_back_to_the_verb @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: A subcommand of a promoted CLI that no rule names is still rated by its verb
    Given the CLI has rules for some of its subcommands, but none for "<command>"
    When the operator scores "<command>"
    Then the level is high

    Examples:
      | command                          |
      | gh label delete wontfix          |
      | openstack flavor delete m1.small |
      | vault namespace delete acme      |
      | velero plugin remove acme/plugin |
