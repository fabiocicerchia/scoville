@domain:repo-policy @area:config-discovery @from:scoville/overrides
Feature: Finding the repository's override file
  Makes sure the policy a repository has written down applies wherever in the repository scoville runs, and that an operator who names or disables a config gets exactly what they asked for.

  @id:repo-policy.config-discovery.004 @rule:policy.config.nearest-above-applies @verified @source:scoville/overrides.py#find_config @test:tests/test_scoville.py#test_config_is_discovered_from_the_directory_upwards
  Scenario Outline: The nearest override file at or above the analysed location applies
    Given a repository whose root holds a <file>
    And the operator is working in the subdirectory "a/b" of that repository
    When the operator scores a command
    Then the overrides in the repository root's <file> are in force

    Examples:
      | file             |
      | .scovillerc      |
      | .scovillerc.json |

  @id:repo-policy.config-discovery.005 @rule:policy.config.no-config-ignores-discovered @verified @source:scoville/cli.py#_load_entries @test:tests/test_scoville.py#test_no_config_ignores_a_discovered_file
  Scenario Outline: Disabling config ignores a discovered override file
    Given the working directory holds a .scovillerc that allows "kubectl delete ns ci-*"
    When the operator scores "kubectl delete ns ci-1" with --fail-on high <flag>
    Then scoville exits with status <exit>

    Examples:
      | flag                | exit |
      | and no other option | 0    |
      | and --no-config     | 1    |

  @id:repo-policy.config-discovery.006 @rule:policy.config.named-config-must-exist @verified @source:scoville/cli.py#_load_entries @test:tests/test_scoville.py#test_a_named_config_that_is_missing_is_an_error
  Scenario: A named override file that does not exist is an error
    Given no file exists at "nope.json"
    When the operator scores "ls" with --config nope.json
    Then scoville reports "nope.json: no such file"
    And scoville exits with status 64
