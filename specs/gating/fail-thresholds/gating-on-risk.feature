@domain:gating @area:fail-thresholds @from:scoville/cli
Feature: Gating a pipeline or hook on a command's risk
  Lets CI jobs and pre-run hooks block a command or script automatically once it reaches a chosen risk level, without blocking commands the repository has explicitly allowed.

  @id:gating.fail-thresholds.001 @rule:gating.fail-thresholds.worst-command-trips-gate @verified @source:scoville/cli.py#main @test:tests/test_scoville.py#test_json_output_and_exit_codes @test:tests/test_scoville.py#test_file_input_reports_line_numbers @test:tests/test_scoville.py#test_fail_on_still_works_with_peppers
  Scenario Outline: The run fails when any command reaches the chosen level
    Given a fail threshold of "<threshold>"
    When the operator scores <input>
    Then the exit status is <exit>
    And the full report is still printed

    Examples:
      | input                                                     | threshold | exit |
      | the command "rm -rf /"                                    | high      | 1    |
      | the command "ls -la"                                      | high      | 0    |
      | a script deploy.sh whose fourth line is "rm -rf /opt/app" | medium    | 1    |
      | the command "rm -rf /" on the pepper scale                | high      | 1    |

  @id:gating.fail-thresholds.002 @rule:gating.fail-thresholds.no-threshold-never-fails @verified @source:scoville/cli.py#main @test:tests/test_scoville.py#test_scale_only_changes_the_label
  Scenario: Without a threshold even a critical command exits cleanly
    Given no fail threshold is set
    When the operator scores the command "rm -rf /"
    Then the report shows the command at 100/100
    And the exit status is 0

  @id:gating.fail-thresholds.003 @rule:gating.fail-thresholds.allowed-commands-do-not-trip-gate @verified @source:scoville/cli.py#main @test:tests/test_scoville.py#test_allow_keeps_the_real_score_but_does_not_trip_the_gate @test:tests/test_scoville.py#test_an_unallowed_command_still_trips_the_gate @test:tests/test_scoville.py#test_strict_does_not_defeat_an_allow
  Scenario Outline: A command the repository allows keeps its real score but does not fail the run
    Given the repository policy allows "kubectl delete ns ci-*" because it is "routine CI teardown"
    And a fail threshold of "high"
    When the operator scores "<command>"
    Then the report shows the command at its real level "<level>"
    And the exit status is <exit>

    Examples:
      | command                   | level | exit |
      | kubectl delete ns ci-1234 | high  | 0    |
      | kubectl delete ns prod    | high  | 1    |
