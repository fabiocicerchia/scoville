@domain:live-context @area:kubernetes-context @from:scoville/kube
Feature: Weighing a kubectl command against what the current context may do
  Operators who score kubectl commands with --introspect get a score that reflects whether the current kube context could actually run them, without the tool ever under-reporting risk on a missing or unclear answer.

  Background:
    Given the operator scores a kubectl command line

  @id:live-context.kubernetes-context.001 @rule:live-context.kubernetes.refused-command-scored-down-not-to-zero @verified @source:scoville/scoring.py#kube_rbac_factors @test:tests/test_scoville.py#test_a_command_the_context_cannot_run_is_dampened_and_says_so @test:tests/test_scoville.py#test_a_refusal_scores_down_but_never_to_nothing
  Scenario: A command the current context is refused scores lower, but never to nothing
    Given the current kube context is "prod-readonly"
    And the cluster answers "no" to whether that context may delete namespaces in prod
    When the operator scores "kubectl delete ns prod -n prod" with --introspect
    Then the score is 30 points lower than without --introspect
    And the score stays above 0
    And a factor names context "prod-readonly", says it cannot delete namespaces in prod and that `kubectl auth can-i` says no

  @id:live-context.kubernetes-context.002 @rule:live-context.kubernetes.no-answer-never-dampens @verified @source:scoville/kube.py#kube_can_i @test:tests/test_scoville.py#test_no_answer_never_dampens @test:tests/test_scoville.py#test_an_unanswered_check_is_still_recorded_in_the_trace
  Scenario Outline: A missing or unclear answer from the cluster never lowers the score
    Given <situation>
    When the operator scores "kubectl delete ns prod" with --introspect
    Then the score is no lower than without --introspect
    And <trace>

    Examples:
      | situation                                                                           | trace                                                                                                                |
      | there is no current kube context                                                    | no RBAC factor is shown                                                                                              |
      | context "prod-readonly" exists but the permission check never answers               | a zero-point factor says there was no answer from `kubectl auth can-i delete namespaces` for context "prod-readonly" |
      | context "prod-readonly" exists and the check answers with nothing                   | a zero-point factor says there was no answer for context "prod-readonly"                                             |
      | context "prod-readonly" exists and the check answers "error: You must be logged in" | a zero-point factor says there was no answer for context "prod-readonly"                                             |
      | context "prod-readonly" exists and the check answers "maybe"                        | a zero-point factor says there was no answer for context "prod-readonly"                                             |

  @id:live-context.kubernetes-context.003 @rule:live-context.kubernetes.cluster-admin-amplifies @verified @source:scoville/scoring.py#kube_rbac_factors @test:tests/test_scoville.py#test_cluster_admin_is_an_amplifier_on_a_destructive_verb @questionable
  Scenario: A cluster-admin context raises the score and widens the blast radius to the cluster
    Given the current kube context is "kind-kind"
    And the cluster answers "yes" to deleting namespaces and "yes" to doing anything on anything
    When the operator scores "kubectl delete ns prod" with --introspect
    Then a 10-point cluster-admin factor raises the score above the score without --introspect, capped at 100
    And the blast radius is "cluster"
    And a factor says context "kind-kind" is cluster-admin and no RBAC boundary is left to catch a mistake

  @id:live-context.kubernetes-context.004 @rule:live-context.kubernetes.permitted-leaves-score-unchanged @verified @source:scoville/scoring.py#kube_rbac_factors @test:tests/test_scoville.py#test_permitted_but_not_admin_changes_nothing_and_says_why
  Scenario: A permitted command from an ordinary context keeps its score and says why
    Given the current kube context is "team-ns"
    And the cluster answers "yes" to deleting namespaces and "no" to doing anything on anything
    When the operator scores "kubectl delete ns prod" with --introspect
    Then the score equals the score without --introspect
    And a zero-point factor says context "team-ns" may delete namespaces and `kubectl auth can-i` says yes

  @id:live-context.kubernetes-context.005 @rule:live-context.kubernetes.asks-about-the-rbac-verb-and-resource @verified @source:scoville/kube.py#kube_target @test:tests/test_scoville.py#test_kubectl_verbs_are_mapped_to_the_rbac_verbs_they_need @test:tests/test_scoville.py#test_a_short_resource_name_is_expanded_before_it_is_asked_about @test:tests/test_scoville.py#test_an_unknown_resource_is_passed_through_verbatim @test:tests/test_scoville.py#test_the_verb_and_resource_come_from_the_positionals @test:tests/test_scoville.py#test_a_flag_value_is_not_mistaken_for_the_resource
  Scenario Outline: The cluster is asked about the permission the command really needs
    Given the current kube context is "c"
    When the operator scores "<command>" with --introspect
    Then the cluster is asked whether the context may "<question>"
    And the RBAC factor names "<question>"

    Examples:
      | command                                  | question                          |
      | kubectl apply deploy web                 | patch deployments                 |
      | kubectl delete ns prod                   | delete namespaces                 |
      | kubectl delete pod/foo                   | delete pod                        |
      | kubectl -n kube-system delete deploy x   | delete deployments in kube-system |
      | kubectl delete deploy x --namespace=prod | delete deployments in prod        |
      | kubectl delete -l app=x pods             | delete pods                       |
      | kubectl delete widgets.example.com w1    | delete widgets.example.com        |

  @id:live-context.kubernetes-context.006 @rule:live-context.kubernetes.name-taken-as-resource @verified @source:scoville/kube.py#kube_target @test:tests/test_scoville.py#test_the_verb_and_resource_come_from_the_positionals @questionable
  Scenario Outline: For commands that name an object rather than a kind, the object name is asked about as if it were a resource
    Given the current kube context is "c"
    And the cluster answers "no" for a resource type it does not know
    When the operator scores "<command>" with --introspect
    Then the cluster is asked whether the context may "<question>"
    And a 30-point refusal factor lowers the score below the score without --introspect

    Examples:
      | command                                    | question             |
      | kubectl exec -n prod mypod -- rm -rf /data | create mypod in prod |
      | kubectl drain node-1                       | patch node-1         |
      | kubectl rollout restart deploy/web         | patch restart        |

  @id:live-context.kubernetes-context.007 @rule:live-context.kubernetes.check-timeout-bounded @verified @source:scoville/kube.py#_kubectl @test:tests/test_scoville.py#test_the_timeout_is_bounded_and_configurable
  Scenario: Each permission check is bounded by a timeout the operator can set
    Given the current kube context is "prod-readonly"
    When the operator scores "kubectl delete ns prod" with --introspect and --kube-timeout 0.25
    Then each question to the cluster is abandoned after 0.25 seconds
    And without --kube-timeout the bound is 3 seconds
    And a check that runs out of time scores as if it had not been asked
