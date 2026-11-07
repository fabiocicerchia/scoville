@domain:reporting @area:text-report @from:scoville/output
Feature: Reading the risk report
  Gives an operator one readable block per command, plus a one-line verdict for the whole run, so they can decide whether to run it.

  Background:
    Given the operator runs scoville in the default text format

  @id:reporting.text-report.005 @rule:reporting.text.run-verdict-is-the-worst-command @verified @source:scoville/output.py#overall @test:tests/test_scoville.py#test_sequences_split_and_worst_wins
  Scenario: The run verdict is the worst command, not an average
    Given a script with the commands "cd /tmp && ls -la; rm -rf /var"
    When the operator scores the script
    Then the summary line reads "scoville: <n> commands, worst CRITICAL"
    And the summary shows the highest score of any command in the script
    And the summary shows the widest scope and the least reversible outcome found in any command

  @id:reporting.text-report.006 @rule:reporting.text.zero-weight-factors-hidden @inferred @source:scoville/output.py#render_text
  Scenario Outline: Factors that add nothing are hidden unless the operator asks for them
    Given a command that scores <score>
    And one of its factors adds 0 points
    When the operator scores the command <mode>
    Then the zero-point factor is <shown>

    Examples:
      | score   | mode              | shown                                |
      | above 0 | without --verbose | not listed                           |
      | above 0 | with --verbose    | listed with a "·" in place of points |
      | 0       | without --verbose | listed with a "·" in place of points |

  @id:reporting.text-report.007 @rule:reporting.text.points-to-rule-explanation @verified @source:scoville/output.py#render_text @test:tests/test_scoville.py#test_a_finding_names_the_rule_so_why_is_discoverable @test:tests/test_scoville.py#test_a_safe_command_keeps_the_pointer_out_of_the_way
  Scenario Outline: A risky finding points to the command that explains its rule
    Given the command "<command>"
    When the operator scores the command <mode>
    Then the report <pointer>

    Examples:
      | command                | mode              | pointer                                       |
      | kubectl delete ns prod | without --verbose | shows "↳ why:   scoville --why K8S-DELETE-NS" |
      | ls -la                 | without --verbose | shows no --why pointer                        |
      | ls -la                 | with --verbose    | shows "↳ why:   scoville --why READ"          |

  @id:reporting.text-report.008 @rule:reporting.text.safer-alternative-for-risky @inferred @source:scoville/output.py#render_text
  Scenario Outline: A risky command comes with a safer alternative, a safe one does not
    Given a command whose rule suggests a safer alternative
    And the command scores at level <level>
    When the operator scores the command
    Then the line "↳ safer: <advice>" is <shown>

    Examples:
      | level    | shown     |
      | low      | shown     |
      | critical | shown     |
      | safe     | not shown |

  @id:reporting.text-report.009 @rule:reporting.text.script-findings-carry-line-numbers @inferred @source:scoville/output.py#render_text
  Scenario: Findings from a script name the file and line they came from
    Given a script file deploy.sh with "rm -rf /opt/app" on line 4
    When the operator scores the script file
    Then the command's block starts with "deploy.sh:4: rm -rf /opt/app"
    And a command found inside $(...) is labelled "(command substitution)"
