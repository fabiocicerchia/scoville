@domain:risk-scoring @area:softeners @from:scoville/amplifiers
Feature: Lowering the score for the careful way of asking
  A gate is only usable if the careful form of a command (prompting, backups, dry runs, narrowing) scores below the careless one, so operators are rewarded for leaving themselves a way out.

  Background:
    Given the operator scores commands with scoville without running them

  @id:risk-scoring.softeners.001 @rule:risk.softeners.careful-form-scores-lower @verified @source:scoville/amplifiers.py#SOFTENERS @test:tests/test_scoville.py#test_softeners_lower_the_careful_form @test:tests/test_scoville.py#test_the_cli_s_own_flags_amplify_and_soften
  Scenario Outline: The careful form of a command scores below the careless form
    Given no repository policy applies
    When the operator scores "<careful>"
    Then it scores lower than "<careless>"

    Examples:
      | careful                                               | careless                                |
      | rm -ri /tmp/cache                                     | rm -rf /tmp/cache                       |
      | sed -i.bak 's/a/b/' app.conf                          | sed -i 's/a/b/' app.conf                |
      | ansible all -m shell -a 'rm -rf /tmp/x' --limit web-1 | ansible all -m shell -a 'rm -rf /tmp/x' |
      | gh pr merge 42 --auto                                 | gh pr merge 42                          |

  @id:risk-scoring.softeners.002 @rule:risk.softeners.dry-run-caps-the-score @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_dry_run_caps_the_score @test:tests/test_scoville.py#test_vault_output_curl_string_sends_nothing @test:tests/test_scoville.py#test_assume_no_is_the_mirror
  Scenario Outline: A dry run is never rated above safe, however destructive the command
    Given no repository policy applies
    When the operator scores "<command>"
    Then the command is rated safe
    And its reversibility is reversible
    And the report lists the factor "<note>"

    Examples:
      | command                                    | note                                                              |
      | aws s3 rm s3://b --recursive --dryrun      | --dry-run: reports what it would do and changes nothing           |
      | kubectl delete ns prod --dry-run=client    | --dry-run: reports what it would do and changes nothing           |
      | vault delete -output-curl-string secret/db | -output-curl-string: prints the request as curl and sends nothing |
      | fsck -n /dev/sdb1                          | -n: dry run, nothing is written                                   |

  @id:risk-scoring.softeners.003 @rule:risk.softeners.server-dry-run-is-not-a-dry-run @verified @source:scoville/amplifiers.py#DAMPENERS @test:tests/test_scoville.py#test_dry_run_server_is_not_a_dampener
  Scenario: A server-side dry run gets no dry-run discount
    Given no repository policy applies
    When the operator scores "kubectl delete ns prod --dry-run=server"
    Then the command is rated critical

  @id:risk-scoring.softeners.004 @rule:risk.softeners.short-n-is-dry-run-only-on-known-tools @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_assume_no_is_the_mirror @questionable
  Scenario Outline: A bare -n counts as a dry run only for tools where it means one
    Given no repository policy applies
    When the operator scores "<command>"
    Then the report <outcome> the factor "-n: dry run, nothing is written"

    Examples:
      | command                      | outcome       |
      | rsync -a -n src/ dst/        | lists         |
      | fsck -n /dev/sdb1            | lists         |
      | cp -n app.conf /etc/app.conf | lists         |
      | git commit -n -m wip         | lists         |
      | kill -n 9 1234               | does not list |

  @id:risk-scoring.softeners.005 @rule:risk.softeners.check-flag-is-a-dry-run-everywhere @inferred @source:scoville/amplifiers.py#DAMPENERS @questionable
  Scenario: A --check argument caps the score on any tool
    Given no repository policy applies
    When the operator scores "rm -rf /var --check"
    Then the command is rated safe
    And the report lists the factor "--dry-run: reports what it would do and changes nothing"
