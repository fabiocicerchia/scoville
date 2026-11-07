@domain:command-reading @area:command-splitting @from:scoville/parsing
Feature: Splitting a command line into the commands it runs
  Operators gating commands or scripts need every command on a line scored on its own, so a dangerous step can't hide behind a harmless one, a quote or a substitution.

  Background:
    Given scoville scores commands without executing them

  @id:command-reading.command-splitting.001 @rule:command-reading.splitting.every-command-scored @verified @source:scoville/parsing.py#split_commands @test:tests/test_scoville.py#test_sequences_split_and_worst_wins
  Scenario Outline: Every command joined by a shell separator is scored on its own
    Given a command line in which a destructive rm follows a harmless command
    When the operator scores "<line>"
    Then "rm -rf /var" is reported as its own command
    And its level is critical
    And the overall level for the line is critical

    Examples:
      | line                           |
      | cd /tmp && ls -la; rm -rf /var |
      | ls \|\| rm -rf /var            |
      | ls \| rm -rf /var              |
      | ls \|& rm -rf /var             |
      | ls & rm -rf /var               |
      | ls\nrm -rf /var                |
      | (cd /tmp && rm -rf /var)       |
      | { ls; rm -rf /var; }           |

  @id:command-reading.command-splitting.002 @rule:command-reading.splitting.quoted-separators-stay-literal @verified @source:scoville/parsing.py#split_commands @test:tests/test_scoville.py#test_quotes_are_not_split_on
  Scenario Outline: Separators inside quotes or after a backslash do not split a command
    Given a command line whose quoted or escaped text contains a separator character
    When the operator scores "<line>"
    Then exactly <count> commands are reported

    Examples:
      | line                                      | count |
      | echo 'a; b' && echo c                     | 2     |
      | echo "a \| b" && echo c                   | 2     |
      | find . -name '*.log' -exec rm {} \; && ls | 2     |

  @id:command-reading.command-splitting.003 @rule:command-reading.splitting.comments-ignored @verified @source:scoville/parsing.py#split_commands @test:tests/test_scoville.py#test_comments_and_shebangs_are_ignored
  Scenario: Comments and shebang lines are never scored
    Given a script whose comment line mentions "rm -rf /"
    When the operator scores the script "#!/bin/bash\n# rm -rf / would be bad\nls\n"
    Then no command from the comment lines is reported
    And every reported command is safe

  @id:command-reading.command-splitting.004 @rule:command-reading.splitting.substitutions-scored @verified @source:scoville/parsing.py#subshell_commands @test:tests/test_scoville.py#test_command_substitution_is_analyzed
  Scenario Outline: A command substitution is scored as a command of its own
    Given a harmless command whose argument is a substitution running "rm -rf /"
    When the operator scores "<line>"
    Then "rm -rf /" is reported as a substitution
    And its level is critical

    Examples:
      | line             |
      | echo $(rm -rf /) |
      | echo `rm -rf /`  |

  @id:command-reading.command-splitting.005 @rule:command-reading.splitting.broken-quoting-still-scored @inferred @source:scoville/parsing.py#tokenize
  Scenario: A command with an unclosed quote is still scored rather than dropped
    Given a command whose quote is never closed
    When the operator scores 'rm -rf "/opt'
    Then one command is reported, scored as rm
    And the rest of the text after the open quote belongs to that same command

  @id:command-reading.command-splitting.006 @rule:command-reading.splitting.ampersand-redirections-split @inferred @source:scoville/parsing.py#split_commands @questionable
  Scenario: An ampersand inside a redirection is read as a command separator
    Given a command that redirects stderr with "2>&1"
    When the operator scores "make build 2>&1 | tee build.log" in strict mode
    Then "1" is reported as a command of its own
    And it is scored as an unknown command, which strict mode rates medium
