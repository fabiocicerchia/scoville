@domain:risk-scoring @area:softeners @from:scoville/scoring
Feature: Lowering the score for dry runs and regenerable targets
  Keeps a gate usable by scoring the careful form of a command below the careless one.

  @id:risk-scoring.softeners.006 @rule:risk.softeners.dry-run-caps-at-safe @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_dry_run_caps_the_score
  Scenario Outline: A dry run is safe and reversible whatever it would otherwise score
    When the operator scores `<command>`
    Then the level is safe
    And the reversibility is reversible

    Examples:
      | command                                 |
      | aws s3 rm s3://b --recursive --dryrun   |
      | kubectl delete ns prod --dry-run=client |

  @id:risk-scoring.softeners.007 @rule:risk.softeners.server-dry-run-not-softened @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_dry_run_server_is_not_a_dampener
  Scenario: A server-side dry run is not treated as a dry run
    When the operator scores `kubectl delete ns prod --dry-run=server`
    Then the level is critical

  @id:risk-scoring.softeners.008 @rule:risk.softeners.regenerable-directory @verified @source:scoville/scoring.py#_dir_factor @test:tests/test_scoville.py#test_system_dirs_escalate_but_build_dirs_dampen
  Scenario: Deleting a regenerable build directory scores below deleting real data
    When the operator scores `rm -rf node_modules`
    Then it scores lower than `rm -rf /srv/data`
    And a factor calls `node_modules` a regenerable build/dependency directory
