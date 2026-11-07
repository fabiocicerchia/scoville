@domain:gating @area:exit-codes @from:scoville/cli
Feature: Refusing runs that cannot be scored
  Tells the operator or the calling automation, through the message and the exit status, that nothing was scored, so a missing input or a broken policy is never read as a pass.

  @id:gating.exit-codes.001 @rule:gating.exit-codes.unscorable-input-refused @inferred @source:scoville/cli.py#_read_input
  Scenario Outline: A run with nothing scorable is refused as a usage error
    Given <situation>
    When the operator runs scoville
    Then stderr shows "<message>"
    And no report is printed
    And the exit status is 64

    Examples:
      | situation                                                 | message                                                    |
      | no command, no file, and an interactive terminal on stdin | usage: scoville [-h] ...                                   |
      | the command given is only whitespace                      | scoville: nothing to analyze                               |
      | the file deploy.sh does not exist                         | scoville: [Errno 2] No such file or directory: 'deploy.sh' |
      | the discovered .scovillerc is not valid JSON              | scoville: (path): not valid JSON                           |

  @id:gating.exit-codes.002 @rule:gating.exit-codes.bad-arguments-exit-2 @inferred @source:scoville/cli.py#main @questionable
  Scenario Outline: An unrecognised option or invalid choice exits with status 2
    When the operator runs scoville with "<arguments>"
    Then stderr shows the usage line and the argument error
    And the exit status is 2, not the documented 64

    Examples:
      | arguments            |
      | ls --fail-on extreme |
      | ls --format yaml     |
      | ls --bogus           |

  @id:gating.exit-codes.003 @rule:gating.exit-codes.truncated-output-is-quiet @inferred @source:scoville/cli.py#main @questionable
  Scenario: Cutting the report short with a pager or head is only quiet when run as a module
    Given the report is piped into a reader that closes early, such as head -1
    When the operator runs the installed scoville command on a long script
    Then the quiet exit 0 on a closed pipe only applies under python -m scoville.cli
    And the installed command can print a broken-pipe traceback instead

  @id:gating.exit-codes.004 @rule:gating.version-reporting.prints-version @inferred @source:scoville/cli.py#main
  Scenario: The operator can ask which scoville version is installed
    When the operator asks scoville for its version
    Then stdout shows "scoville <version>"
    And the exit status is 0
