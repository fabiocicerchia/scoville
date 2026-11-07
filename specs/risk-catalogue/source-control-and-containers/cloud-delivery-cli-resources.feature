@domain:risk-catalogue @area:source-control-and-containers @from:scoville/rules-clis
Feature: Rating cloud and delivery CLI commands by the resource they touch
  Lets operators of OpenStack, DigitalOcean, Fly, Argo CD and GitHub see a rating that follows the resource a command touches, not just its verb.

  @id:risk-catalogue.source-control-and-containers.001 @rule:catalogue.promoted-clis.resource-decides-score @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_the_resource_moves_the_score_within_one_cli @test:tests/test_scoville.py#test_doctl_scores_the_resource_not_the_verb @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Within one CLI, the resource a command acts on decides how risky it is
    When the operator scores "<command>"
    Then the level is <level>

    Examples:
      | command                                     | level    |
      | openstack server stop web-1                 | low      |
      | openstack server delete web-1               | high     |
      | openstack stack delete platform             | critical |
      | openstack project purge --project acme      | critical |
      | flyctl machine destroy 4d891de2             | medium   |
      | flyctl apps destroy api                     | high     |
      | flyctl volumes destroy vol_2n0l3vlnklpr8qy7 | critical |
      | doctl compute tag delete web                | medium   |
      | doctl compute droplet delete web-1          | high     |
      | doctl databases delete db-1                 | critical |
      | gh repo archive acme/api                    | low      |
      | gh repo delete acme/api                     | high     |

  @id:risk-catalogue.source-control-and-containers.002 @rule:catalogue.promoted-clis.misleading-verbs-explained @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_openstack_project_delete_leaves_the_resources_running @test:tests/test_scoville.py#test_doctl_verbs_that_lie @test:tests/test_scoville.py#test_argocd_cluster_rm_does_not_touch_the_cluster @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: A command whose verb misleads is rated and explained by what it really does
    When the operator scores "<command>"
    Then the level is <level>
    And the explanation says <explanation>

    Examples:
      | command                                                           | level  | explanation                                                             |
      | openstack project delete acme                                     | high   | the servers and volumes keep running and keep billing                   |
      | doctl compute droplet-action rebuild 123 --image ubuntu-24-04-x64 | high   | the droplet keeps its ID and IP and loses everything on its disk        |
      | argocd cluster rm https://k8s.internal                            | medium | it de-registers the cluster from Argo CD and does not touch the cluster |

  @id:risk-catalogue.source-control-and-containers.003 @rule:catalogue.doctl.aliases-match-long-forms @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_doctl_aliases_reach_the_same_rules @test:tests/test_scoville.py#test_each_doctl_rule_matches_its_own_command @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: doctl's short aliases are rated the same as the long commands they stand for
    When the operator scores "<command>"
    Then the level is <level>

    Examples:
      | command                                               | level  |
      | doctl compute d del web-1                             | high   |
      | doctl compute da rebuild 123 --image ubuntu-24-04-x64 | high   |
      | doctl kube clusters d staging                         | high   |
      | doctl k c np rm staging pool-1                        | medium |

  @id:risk-catalogue.source-control-and-containers.004 @rule:catalogue.gh.api-rated-by-method @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_gh_api_is_scored_on_the_method_not_the_subcommand @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: A raw GitHub API call is rated by its HTTP method
    When the operator scores "<command>"
    Then the level is <level>

    Examples:
      | command                          | level  |
      | gh api /repos/acme/api           | safe   |
      | gh api -X PATCH /repos/acme/api  | medium |
      | gh api -X DELETE /repos/acme/api | high   |

  @id:risk-catalogue.source-control-and-containers.005 @rule:catalogue.promoted-clis.firewall-opening-rated-low @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Opening a port to a named private range is rated low
    When the operator scores "<command>"
    Then the level is low
    And the advice says to name a CIDR you control, because 0.0.0.0/0 is the entire internet

    Examples:
      | command                                                                                        |
      | openstack security group rule create --remote-ip 10.0.0.0/8 --dst-port 22 web                  |
      | doctl compute firewall add-rules fw-1 --inbound-rules protocol:tcp,ports:22,address:10.0.0.0/8 |

  @id:risk-catalogue.source-control-and-containers.006 @rule:catalogue.config-management.fleet-runs-are-medium @inferred @source:scoville/rules_clis.py#CLI_RULES
  Scenario Outline: A configuration-management run is rated at least medium because it reaches every matched host
    When the operator scores "<command>"
    Then the level is at least medium
    And the blast radius is cluster

    Examples:
      | command                   |
      | ansible-playbook site.yml |
      | salt '*' state.apply      |
