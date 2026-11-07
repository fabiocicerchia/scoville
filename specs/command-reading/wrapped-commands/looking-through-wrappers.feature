@domain:command-reading @area:wrapped-commands @from:scoville/parsing
Feature: Looking through sudo, env and other wrappers
  Operators need the command a wrapper launches to be scored, along with the fact that it runs as root, so prefixing a command with sudo or nice can never hide it.

  Background:
    Given scoville scores commands without executing them

  @id:command-reading.wrapped-commands.009 @rule:command-reading.wrappers.wrapped-command-scored @verified @source:scoville/parsing.py#strip_prefix @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: A wrapped command is scored as the command the wrapper runs
    Given a destructive rm prefixed by a wrapper or environment assignment
    When the operator scores "<line>"
    Then the command is scored by the rm rule
    And its level is critical

    Examples:
      | line                            |
      | sudo rm -rf /                   |
      | /usr/bin/sudo -u root rm -rf /  |
      | FOO=bar rm -rf /                |
      | env FOO=1 rm -rf /              |
      | nohup rm -rf /                  |
      | timeout 30 rm -rf /             |
      | nice -n 10 rm -rf /             |
      | flock /tmp/deploy.lock rm -rf / |

  @id:command-reading.wrapped-commands.010 @rule:command-reading.wrappers.privilege-raises-score @verified @source:scoville/parsing.py#strip_prefix @test:tests/test_scoville.py#test_sudo_raises_and_is_transparent
  Scenario Outline: Running under sudo, doas or su raises the score and widens the reach to the host
    Given a command that runs through "<wrapper>"
    When the operator scores "<wrapper> rm -rf /var/lib/data"
    Then the score is higher than for "rm -rf /var/lib/data"
    And a factor reads "`<wrapper>`: runs as root — file permissions do not apply"
    And the blast radius is host

    Examples:
      | wrapper |
      | sudo    |
      | doas    |

  @id:command-reading.wrapped-commands.011 @rule:command-reading.wrappers.bare-prefix-not-reported @inferred @source:scoville/scoring.py#score_command
  Scenario Outline: A line that is only a wrapper or an assignment produces no result
    Given a line with nothing after the wrapper or the assignment
    When the operator scores "<line>"
    Then no command is reported for that line

    Examples:
      | line    |
      | sudo    |
      | FOO=bar |

  @id:command-reading.wrapped-commands.012 @rule:command-reading.wrappers.su-payload-visible @inferred @source:scoville/parsing.py#_is_wrapper_operand @questionable
  Scenario Outline: The command su runs with -c is lost from the report
    Given a destructive command passed to su with -c
    When the operator scores "<line>"
    Then no command is reported for the line
    And nothing about rm or root access appears

    Examples:
      | line                       |
      | su -c 'rm -rf /var' root   |
      | su - root -c 'rm -rf /var' |

  @id:command-reading.wrapped-commands.013 @rule:command-reading.wrappers.flag-values-match-the-wrapper @inferred @source:scoville/parsing.py#_skip_wrapper_args @questionable
  Scenario Outline: A sudo flag that takes no value swallows the command it wraps
    Given a destructive rm run through sudo with a flag that takes no value
    When the operator scores "sudo <flag> rm -rf /var"
    Then the command is not scored by the rm rule
    And it is reported as an unknown command

    Examples:
      | flag |
      | -i   |
      | -s   |
      | -n   |
