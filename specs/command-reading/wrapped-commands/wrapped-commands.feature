@domain:command-reading @area:wrapped-commands @from:scoville/scoring
Feature: Scoring what a wrapper actually runs
  Shows an operator the risk of the command a wrapper carries or hides, rather than the harmless-looking wrapper itself.

  @id:command-reading.wrapped-commands.014 @rule:wrapped.carriers.payload-is-scored @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_docker_exec_scored_on_its_payload @test:tests/test_scoville.py#test_docker_exec_payload_is_reported_as_a_child @test:tests/test_scoville.py#test_kubectl_exec_and_ssh_carry_payloads @test:tests/test_scoville.py#test_sh_c_payload_is_unwrapped @test:tests/test_scoville.py#test_find_exec_and_delete
  Scenario Outline: A command carried by a wrapper is scored as that command
    When the operator scores `<command>`
    Then the level is <level>
    And the carried command is reported beneath it

    Examples:
      | command                                | level    |
      | docker exec web ls /app                | low      |
      | docker exec web rm -rf /               | critical |
      | kubectl exec -it pod-1 -- rm -rf /data | critical |
      | sh -c 'rm -rf /'                       | critical |
      | ssh web-1 systemctl stop nginx         | medium   |
      | find /var -exec rm -rf {} ;            | critical |

  @id:command-reading.wrapped-commands.015 @rule:wrapped.carriers.weighted-by-reach @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_container_payload_scores_below_the_same_command_on_the_host @test:tests/test_scoville.py#test_ansible_fans_out_across_the_fleet
  Scenario: A payload in a container scores no higher than on the host, and across a fleet scores higher
    When the operator scores the same destructive command on a container, the host and an ansible inventory
    Then `docker exec web rm -rf /` scores no higher than `rm -rf /`
    And `ansible all -m shell -a "rm -rf /var/log"` scores higher than `rm -rf /var/log`
    And the ansible finding has scope cluster

  @id:command-reading.wrapped-commands.016 @rule:wrapped.hidden.opaque-until-read @verified @source:scoville/scoring.py#hidden_payload @test:tests/test_scoville.py#test_a_wrapper_is_opaque_until_it_is_read @test:tests/test_scoville.py#test_docker_run_without_a_command_flags_the_hidden_entrypoint @test:tests/test_scoville.py#test_source_is_a_readable_wrapper_not_an_eval
  Scenario Outline: A wrapper whose commands are not on the line is flagged as opaque
    Given introspection is off
    When the operator scores `<command>`
    Then the level is <level>
    And a factor says <where> and suggests re-running with --introspect

    Examples:
      | command                      | level  | where                                 |
      | ./deploy.sh                  | low    | the commands are inside the script    |
      | docker run acme/importer:1.2 | medium | what runs is the image ENTRYPOINT/CMD |

  @id:command-reading.wrapped-commands.017 @rule:wrapped.introspect.reads-and-names-the-line @verified @source:scoville/scoring.py#resolve_payload @test:tests/test_scoville.py#test_introspect_reads_the_wrapper_and_names_the_line @test:tests/test_scoville.py#test_make_target_and_npm_script_are_resolved
  Scenario Outline: With introspection a script, Makefile target or npm script is scored by its worst line
    Given the project has `<wrapper>` whose body runs `<dangerous command>`
    When the operator scores `<command>` with --introspect
    Then the level is critical
    And for a script, a factor names the line and the command that drove the score

    Examples:
      | command          | wrapper                        | dangerous command               |
      | ./foo.sh         | foo.sh                         | rm -rf "$BUILD_DIR"/            |
      | make deploy      | a Makefile deploy target       | terraform destroy -auto-approve |
      | npm run reset-db | a package.json reset-db script | psql -c 'DROP DATABASE app'     |

  @id:command-reading.wrapped-commands.018 @rule:wrapped.introspect.harmless-wrapper-scores-lower @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_reading_a_harmless_wrapper_lowers_the_score
  Scenario: Reading a harmless wrapper lowers its score
    Given the project has `safe.sh` that only lists files and echoes
    When the operator scores `./safe.sh` with --introspect
    Then the level is safe
    And it scores lower than without --introspect

  @id:command-reading.wrapped-commands.019 @rule:wrapped.introspect.unreadable-says-so @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_make_target_and_npm_script_are_resolved
  Scenario: A wrapper that cannot be read under introspection stays flagged and says why
    Given the Makefile has no `nope` target
    When the operator scores `make nope` with --introspect
    Then a factor says the recipe could not be read from here
