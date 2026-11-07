@domain:command-reading @area:input-sources @from:scoville/cli
Feature: Choosing what to score
  Lets operators and hooks hand scoville commands as arguments, through stdin or as a script file, and get every command in it scored.

  @id:command-reading.input-sources.001 @rule:command-reading.input-sources.arguments-stdin-or-file @verified @source:scoville/cli.py#_read_input @test:tests/test_scoville.py#test_quiet_uses_ascii_slugs @test:tests/test_scoville.py#test_file_input_reports_line_numbers
  Scenario Outline: Commands are read from a file, the arguments or stdin, in that order
    Given <input>
    When the operator runs scoville
    Then the report scores <scored>

    Examples:
      | input                                                    | scored                                                  |
      | the arguments "aws s3 ls" and "rm -rf /"                 | both commands, one per argument                         |
      | the argument "-" with "rm -rf /tmp/build" piped on stdin | the piped command                                       |
      | no arguments with "rm -rf /tmp/build" piped on stdin     | the piped command                                       |
      | --file deploy.sh                                         | each command in deploy.sh, located as deploy.sh:<line>  |
      | --file deploy.sh and the argument "ls"                   | only the commands in deploy.sh; the argument is ignored |

  @id:command-reading.input-sources.002 @rule:command-reading.input-sources.undecodable-bytes-replaced @verified @source:scoville/cli.py#_read_input @test:tests/test_scoville.py#test_file_input_survives_undecodable_bytes
  Scenario: A script with bytes that are not UTF-8 is still scored
    Given a script deploy.sh with an invalid UTF-8 byte in a comment on line 2 and "rm -rf /opt/app" on line 3
    When the operator scores the file with a fail threshold of "medium"
    Then the report shows a finding at deploy.sh:3
    And the exit status is 1
