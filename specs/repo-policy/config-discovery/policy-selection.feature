@domain:repo-policy @area:config-discovery @from:scoville/cli
Feature: Picking the repository policy for a run
  Makes sure a run applies the .scovillerc policy the operator expects: the repository's own, an explicitly named one, or none at all.

  Background:
    Given a .scovillerc at the repository root allows "kubectl delete ns ci-*" because it is "routine CI teardown"

  @id:repo-policy.config-discovery.001 @rule:repo-policy.config-discovery.nearest-rc-from-analysed-location @verified @source:scoville/cli.py#main @test:tests/test_scoville.py#test_no_config_ignores_a_discovered_file
  Scenario Outline: The policy is found from the script's directory, or from the working directory for typed commands
    Given a fail threshold of "high"
    And <location>
    When the operator scores <input>
    Then the repository policy applies and the exit status is 0

    Examples:
      | location                                       | input                                                                           |
      | the operator is working in the repository root | the command "kubectl delete ns ci-1"                                            |
      | the operator is working outside the repository | a script in a subdirectory of the repository that runs "kubectl delete ns ci-1" |

  @id:repo-policy.config-discovery.002 @rule:repo-policy.config-discovery.no-config-ignores-discovered @verified @source:scoville/cli.py#_load_entries @test:tests/test_scoville.py#test_no_config_ignores_a_discovered_file
  Scenario: Turning policy off ignores a discovered .scovillerc
    Given the operator is working in the repository root
    And a fail threshold of "high"
    When the operator scores "kubectl delete ns ci-1" with policy turned off
    Then the allow is not applied
    And the exit status is 1

  @id:repo-policy.config-discovery.003 @rule:repo-policy.config-discovery.named-config-must-exist @verified @source:scoville/cli.py#_load_entries @test:tests/test_scoville.py#test_a_named_config_that_is_missing_is_an_error
  Scenario: A named policy file that does not exist is refused, not skipped
    Given the operator names the policy file nope.json, which does not exist
    When the operator scores "ls"
    Then stderr shows "scoville: nope.json: no such file"
    And nothing is scored
    And the exit status is 64
