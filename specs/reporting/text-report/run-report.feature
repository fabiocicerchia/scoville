@domain:reporting @area:text-report @from:scoville/cli
Feature: Reading the result of a run
  Gives people a readable verdict and gives tooling a stable machine format for the same analysis, in whatever form the caller asked for.

  @id:reporting.text-report.001 @rule:reporting.text-report.summary-line @verified @source:scoville/cli.py#_report @test:tests/test_scoville.py#test_scale_only_changes_the_label
  Scenario Outline: The text report ends with one line naming the worst command
    Given the level scale "<scale>"
    When the operator scores the command "rm -rf /"
    Then the last line starts "scoville: 1 command, worst <label>"
    And it then gives 100/100, the widest scope and the least reversible outcome
    And with the pepper scale the label carries its heat marker in brackets

    Examples:
      | scale   | label                               |
      | bands   | CRITICAL                            |
      | peppers | CAROLINA REAPER (with chilli marks) |

  @id:reporting.text-report.002 @rule:reporting.text-report.quiet-one-line-per-command @verified @source:scoville/cli.py#_report @test:tests/test_scoville.py#test_quiet_uses_ascii_slugs
  Scenario: Quiet mode prints one greppable line per command
    Given the level scale "peppers"
    When the operator scores "aws s3 ls" and "rm -rf /" in quiet mode
    Then each command gets one line: level slug, score, command
    And the slugs are "bell-pepper" and "carolina-reaper"
    And no summary line is printed

  @id:reporting.text-report.003 @rule:reporting.colour.only-on-interactive-terminals @inferred @source:scoville/cli.py#_report
  Scenario Outline: Levels are coloured only on an interactive terminal that has not opted out
    Given the report goes to <destination>
    When the operator scores "rm -rf /"
    Then the levels are <coloured>

    Examples:
      | destination                  | coloured |
      | a terminal                   | coloured |
      | a terminal with NO_COLOR set | plain    |
      | a terminal with --no-color   | plain    |
      | a pipe or file               | plain    |

  @id:reporting.text-report.004 @rule:reporting.json-output.overall-and-commands @verified @source:scoville/cli.py#_report @test:tests/test_scoville.py#test_json_is_unaffected_by_the_scale @test:tests/test_scoville.py#test_json_output_and_exit_codes @test:tests/test_scoville.py#test_an_override_is_visible_in_json
  Scenario: JSON output carries an overall verdict and every command, always in band names
    Given the level scale "peppers"
    When the operator scores "rm -rf /" as JSON
    Then the output is one JSON object with "overall" and "commands"
    And overall.level is "critical"
    And a command matched by a policy entry carries that entry under "override"
