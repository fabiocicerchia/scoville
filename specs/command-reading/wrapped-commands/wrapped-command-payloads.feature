@domain:command-reading @area:wrapped-commands @from:scoville/carriers
Feature: Scoring the command a wrapper carries
  Operators and hooks that gate container exec, pod exec, ssh, shell -c, ansible ad-hoc runs and find's per-match actions need the score to reflect the command that actually runs, weighted by where it lands, and not the harmless-looking wrapper.

  Background:
    Given scoville scores a command without executing it

  @id:command-reading.wrapped-commands.001 @rule:wrapped-commands.container.payload-scored-in-container @verified @source:scoville/carriers.py#carried_command @test:tests/test_scoville.py#test_docker_exec_scored_on_its_payload @test:tests/test_scoville.py#test_container_payload_scores_below_the_same_command_on_the_host
  Scenario Outline: A command run inside a container is scored on that command, slightly below the same command on the host
    Given the operator has a container named web
    When the operator scores <wrapped command> run in web through <wrapper>
    Then the command is reported at level <level>
    And the wrapped command is listed as carried, with a factor naming the payload and saying it runs inside the container
    And the payload's share of the score is no higher than the same payload scored directly on the host

    Examples:
      | wrapper     | wrapped command                                  | level    |
      | docker exec | ls /app                                          | low      |
      | docker exec | a forced recursive removal of the root directory | critical |
      | podman exec | a forced recursive removal of the root directory | critical |

  @id:command-reading.wrapped-commands.002 @rule:wrapped-commands.container.flag-values-are-not-the-target @verified @source:scoville/carriers.py#_skip_flags @test:tests/test_scoville.py#test_docker_exec_payload_is_reported_as_a_child
  Scenario: Option values given to the container wrapper are not mistaken for the container or the command
    Given the operator has a container named web
    When the operator scores docker exec -u root web followed by a forced recursive removal of a system directory
    Then the carried command is the removal, matched by rule FS-RM, and root is not taken as the container
    And a factor names the payload as the risk

  @id:command-reading.wrapped-commands.003 @rule:wrapped-commands.remote.payload-scored-on-target @verified @source:scoville/carriers.py#carried_command @test:tests/test_scoville.py#test_kubectl_exec_and_ssh_carry_payloads @test:tests/test_scoville.py#test_container_payload_scores_below_the_same_command_on_the_host
  Scenario Outline: A command sent to a pod or a remote host is scored on what it runs there
    When the operator scores <wrapped command> sent through <wrapper>
    Then the command is reported at level <level>
    And a factor names the payload and where it runs

    Examples:
      | wrapper                   | wrapped command                                  | level    |
      | kubectl exec -it pod-1 -- | a forced recursive removal of the data directory | critical |
      | ssh web-1                 | systemctl stop nginx                             | medium   |
      | ssh prod-1                | systemctl stop nginx                             | high     |

  @id:command-reading.wrapped-commands.004 @rule:wrapped-commands.shell.dash-c-unwrapped @verified @source:scoville/carriers.py#carried_command @test:tests/test_scoville.py#test_sh_c_payload_is_unwrapped
  Scenario Outline: A command string handed to a shell with -c is scored as the command it contains
    When the operator scores <shell> -c with a quoted forced recursive removal of <path>
    Then the command is reported at level critical

    Examples:
      | shell     | path                               |
      | sh        | the root directory                 |
      | sudo bash | the system configuration directory |

  @id:command-reading.wrapped-commands.005 @rule:wrapped-commands.fleet.ansible-ad-hoc-amplified @verified @source:scoville/carriers.py#carried_command @test:tests/test_scoville.py#test_ansible_fans_out_across_the_fleet
  Scenario: An ad-hoc command run across an inventory scores above the same command on one host and reaches the cluster
    When the operator scores an ansible ad-hoc shell run against all hosts that recursively removes the log directory
    Then the score is higher than the same removal scored on its own
    And the blast radius is cluster
    And a factor says it runs on every host matched by the inventory pattern, in parallel

  @id:command-reading.wrapped-commands.006 @rule:wrapped-commands.per-file.find-actions-fan-out @verified @source:scoville/carriers.py#carried_command @test:tests/test_scoville.py#test_find_exec_and_delete @test:tests/test_scoville.py#test_find_fans_out_over_the_match_set
  Scenario: An action run on every match of a file walk scores above the same action on one named file
    When the operator scores a file walk that runs a destructive command on each match
    Then the score is higher than the same command scored against one named file
    And a factor says the action applies to every path the walk matches, not to one argument you can read
    And the blast radius is at least a directory

  @id:command-reading.wrapped-commands.007 @rule:wrapped-commands.container.hidden-entrypoint-flagged @verified @source:scoville/carriers.py#carried_command @test:tests/test_scoville.py#test_docker_run_without_a_command_flags_the_hidden_entrypoint @test:tests/test_scoville.py#test_introspection_is_opt_in
  Scenario: Starting a container without naming a command is flagged as running a hidden entrypoint
    Given live introspection is not requested
    When the operator scores "docker run acme/importer:1.2"
    Then the command is reported at level medium
    And a factor says what runs is the image ENTRYPOINT/CMD, not this line, and suggests re-running with --introspect

  @id:command-reading.wrapped-commands.008 @rule:wrapped-commands.misread-wrapper-misses-payload @inferred @source:scoville/carriers.py#_skip_flags @questionable
  Scenario Outline: A wrapper written in a form the reader does not recognise is not scored on its real command
    When the operator scores "<command>"
    Then systemctl stop nginx is not scored as the carried command
    And the result instead shows <instead>

    Examples:
      | command                                               | instead                                                           |
      | docker run --hostname box alpine systemctl stop nginx | box taken as the image and alpine scored as an unknown command    |
      | kubectl exec pod-1 systemctl stop nginx               | a hidden ENTRYPOINT/CMD factor, though the command is on the line |
