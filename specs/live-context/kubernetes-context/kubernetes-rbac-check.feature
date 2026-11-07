@domain:live-context @area:kubernetes-context @from:scoville/scoring
Feature: Checking a kubectl command against the cluster's own permissions
  Tells an operator whether the current Kubernetes context could actually run a command, without ever under-reporting when the cluster gives no answer.

  Background:
    Given a kubectl command that deletes a namespace

  @id:live-context.kubernetes-context.008 @rule:kube.rbac.only-under-introspect @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_the_default_path_never_talks_to_a_cluster @test:tests/test_scoville.py#test_only_kubectl_lines_are_checked
  Scenario Outline: The cluster is consulted only for kubectl lines under introspection
    When the operator scores <command> <mode>
    Then no question is sent to the cluster

    Examples:
      | command                | mode                 |
      | kubectl delete ns prod | without --introspect |
      | rm -rf /etc            | with --introspect    |
      | docker rm -f web       | with --introspect    |

  @id:live-context.kubernetes-context.009 @rule:kube.rbac.refusal-discounts-not-erases @verified @source:scoville/scoring.py#kube_rbac_factors @test:tests/test_scoville.py#test_a_command_the_context_cannot_run_is_dampened_and_says_so @test:tests/test_scoville.py#test_a_refusal_scores_down_but_never_to_nothing
  Scenario: A command the current context may not run is scored down, but never to zero
    Given the current context is `prod-readonly`
    And `kubectl auth can-i` says no
    When the operator scores `kubectl delete ns prod -n prod` with --introspect
    Then it scores lower than without --introspect
    And its score is above zero
    And a factor names context `prod-readonly` and `kubectl auth can-i`

  @id:live-context.kubernetes-context.010 @rule:kube.rbac.cluster-admin-amplifies @verified @source:scoville/scoring.py#kube_rbac_factors @test:tests/test_scoville.py#test_cluster_admin_is_an_amplifier_on_a_destructive_verb
  Scenario: A cluster-admin context raises the score and widens it to the cluster
    Given the current context may do anything (`can-i '*' '*'` says yes)
    When the operator scores `kubectl delete ns prod` with --introspect
    Then it scores higher than without --introspect
    And its scope is cluster
    And a factor says the context is cluster-admin

  @id:live-context.kubernetes-context.011 @rule:kube.rbac.permitted-unchanged @verified @source:scoville/scoring.py#kube_rbac_factors @test:tests/test_scoville.py#test_permitted_but_not_admin_changes_nothing_and_says_why
  Scenario: A permitted, non-admin context leaves the score unchanged and says so
    Given `kubectl auth can-i` says yes for the command and no for everything
    When the operator scores `kubectl delete ns prod` with --introspect
    Then the score equals the score without --introspect
    And a factor says `kubectl auth can-i` says yes

  @id:live-context.kubernetes-context.012 @rule:kube.rbac.no-answer-never-lowers @verified @source:scoville/scoring.py#kube_rbac_factors @test:tests/test_scoville.py#test_no_answer_never_dampens @test:tests/test_scoville.py#test_an_unanswered_check_is_still_recorded_in_the_trace
  Scenario Outline: When the cluster gives no clear answer the score is never lowered
    Given the cluster check returns <answer>
    When the operator scores `kubectl delete ns prod` with --introspect
    Then it scores at least as high as without --introspect
    And when a context is known, a factor says there was no answer and names the context

    Examples:
      | answer                       |
      | no context at all            |
      | no reply at all              |
      | an empty reply               |
      | error: You must be logged in |
      | maybe                        |
