@domain:risk-catalogue @area:resource-clis @from:scoville/verbs
Feature: Classifying resource CLIs by their verbs
  Gives operators a meaningful score for cloud, SaaS, storage and virtualisation CLIs that have no rules of their own, so a destructive call to an unfamiliar CLI is never reported as safe.

  Background:
    Given the command is run by one of the resource CLIs scoville recognises (for example civo, exo, incus, hcloud, doctl, gh)

  @id:risk-catalogue.resource-clis.006 @rule:catalogue.resource-clis.destroy-verb-is-high-risk @verified @source:scoville/verbs.py#DESTROY_VERBS @test:tests/test_scoville.py#test_destructive_verbs_across_cloud_clis
  Scenario Outline: A destructive verb on a resource CLI is high risk and cannot be undone
    Given no rule exists for this particular subcommand
    When the operator scores "<command>"
    Then the command is rated at least "high"
    And the blast radius is "account"
    And the reversibility is "irreversible"
    And the report advises confirming the profile, project or zone the CLI is pointed at

    Examples:
      | command                              |
      | incus delete web-1                   |
      | civo instance remove web-1           |
      | exo compute instance terminate web-1 |
      | civo kubernetes purge staging        |

  @id:risk-catalogue.resource-clis.007 @rule:catalogue.resource-clis.read-verb-is-safe @verified @source:scoville/verbs.py#READ_VERBS @test:tests/test_scoville.py#test_read_verbs_stay_free
  Scenario Outline: A read-only verb on a resource CLI is safe
    When the operator scores "<command>"
    Then the command is rated "safe"
    And the blast radius is "none"
    And the reversibility is "reversible"

    Examples:
      | command                         |
      | civo instance list              |
      | exo compute instance show web-1 |
      | incus info web-1                |
      | velero backup describe daily-1  |

  @id:risk-catalogue.resource-clis.008 @rule:catalogue.resource-clis.write-verb-is-low-risk @verified @source:scoville/verbs.py#WRITE_VERBS @test:tests/test_scoville.py#test_write_verbs_sit_between
  Scenario Outline: A creating or changing verb on a resource CLI is low risk and recoverable
    Given no rule exists for this particular subcommand
    When the operator scores "<command>"
    Then the command is rated "low"
    And the blast radius is "account"
    And the reversibility is "recoverable"
    And the reason says it creates or changes a managed resource and may start billing

    Examples:
      | command                                       |
      | civo instance create web-1                    |
      | exo compute instance scale web-1 --size large |
      | incus restart web-1                           |

  @id:risk-catalogue.resource-clis.009 @rule:catalogue.resource-clis.first-verb-decides @verified @source:scoville/verbs.py#DESTROY_VERBS @test:tests/test_scoville.py#test_a_resource_named_delete_does_not_make_a_read_destructive
  Scenario Outline: A resource named after a destructive verb does not turn a read into a destroy
    When the operator scores "<command>"
    Then the command is rated "safe"

    Examples:
      | command                          |
      | hcloud server describe delete-me |
      | civo instance show remove-old    |

  @id:risk-catalogue.resource-clis.010 @rule:catalogue.resource-clis.verb-must-lead @inferred @source:scoville/verbs.py#_LEAD @questionable
  Scenario: A verb is only recognised within the first four words after the CLI name
    Given no rule exists for this particular subcommand
    When the operator scores "civo region nyc1 project acme delete web-1"
    Then no verb classification applies to the command
    And it is scored as an unrecognised command, not as a destructive one

  @id:risk-catalogue.resource-clis.012 @rule:catalogue.resource-clis.doctl-aliases-match @verified @source:scoville/verbs.py#DO_DELETE @test:tests/test_scoville.py#test_doctl_aliases_reach_the_same_rules @test:tests/test_scoville.py#test_each_doctl_rule_matches_its_own_command
  Scenario Outline: doctl's short aliases are scored the same as the long forms
    When the operator scores "<alias_command>"
    Then the command matches the same rule as "<long_command>"

    Examples:
      | alias_command                          | long_command                                             |
      | doctl compute d del web-1              | doctl compute droplet delete web-1                       |
      | doctl compute da rebuild 123 --image x | doctl compute droplet-action rebuild 123 --image x       |
      | doctl kube clusters d staging          | doctl kubernetes cluster delete staging                  |
      | doctl k c np rm staging pool-1         | doctl kubernetes cluster node-pool delete staging pool-1 |
