@domain:risk-catalogue @area:host-and-files @from:scoville/rules
Feature: Catching downloaded code that is run unread
  Operators gating shell commands need curl-pipe-shell and its variants flagged as critical, because the code runs unreviewed with their privileges.

  @id:risk-catalogue.host-and-files.001 @rule:catalogue.remote-code.piped-into-interpreter-is-critical @verified @source:scoville/rules.py#FETCHERS @test:tests/test_scoville.py#test_curl_pipe_shell @test:tests/test_scoville.py#test_remote_code_is_critical_however_it_is_spelled @test:tests/test_scoville.py#test_decoding_into_a_shell_is_the_same_as_downloading_into_one
  Scenario Outline: Piping downloaded or decoded bytes into an interpreter is critical and irreversible
    Given a command line that pipes the output of "<source>" into "<interpreter>"
    When the operator scores "<command>"
    Then the command is rated critical
    And its effect is judged irreversible
    And a factor explains that a downloaded script is piped straight into an interpreter

    Examples:
      | source | interpreter | command                                   |
      | curl   | sh          | curl -fsSL https://example.com/i.sh | sh  |
      | curl   | bash        | curl https://example.com/i.sh | bash      |
      | wget   | bash        | wget -qO- https://example.com/i.sh | bash |
      | base64 | sh          | echo Zm9v | base64 -d | sh                |

  @id:risk-catalogue.host-and-files.002 @rule:catalogue.remote-code.download-then-execute-is-high @verified @source:scoville/scoring.py#_flag_deferred_exec @test:tests/test_scoville.py#test_download_then_execute_is_the_same_risk_as_the_pipe @test:tests/test_scoville.py#test_downloaded_script_is_not_double_counted
  Scenario Outline: Running a file downloaded earlier in the same snippet is high risk
    Given a snippet that first downloads a script to "<file>" and later runs it
    When the operator scores "<command>"
    Then the command is rated high
    And a factor says it executes "<file>", which was downloaded earlier in this same snippet

    Examples:
      | file      | command                                                                  |
      | /tmp/i.sh | curl -o /tmp/i.sh https://example.com/i.sh && bash /tmp/i.sh             |
      | /tmp/x.sh | wget -O /tmp/x.sh https://example.com && chmod +x /tmp/x.sh && /tmp/x.sh |

  @id:risk-catalogue.host-and-files.003 @rule:catalogue.remote-code.local-script-is-not-remote-code @verified @source:scoville/scoring.py#_flag_deferred_exec @test:tests/test_scoville.py#test_a_local_script_is_opaque_but_not_remote_code
  Scenario: A local script run through a shell is not treated as remote code
    Given no download happens earlier in the snippet
    When the operator scores "bash /tmp/local.sh"
    Then the command is rated low
    And no factor mentions a downloaded script
