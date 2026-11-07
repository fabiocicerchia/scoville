@domain:risk-scoring @area:amplifiers @from:scoville/amplifiers
Feature: Raising the score for the dangerous way of asking
  Operators and CI gates rely on the score rising when a command is asked for in a way that makes it worse, so the reckless form of a command never scores like the careful one.

  Background:
    Given the operator scores commands with scoville without running them

  @id:risk-scoring.amplifiers.001 @rule:risk.amplifiers.flags-and-target-escalate-a-delete @verified @source:scoville/amplifiers.py#AMPS @test:tests/test_scoville.py#test_rm_escalates_with_flags_then_target @test:tests/test_scoville.py#test_no_preserve_root_is_worse_than_root_alone
  Scenario Outline: A delete scores higher with forcing and recursive flags, and highest at the filesystem root
    Given no repository policy applies
    When the operator scores "<command>"
    Then the command is rated <level>
    And its reversibility is <reversibility>
    And each step of the escalation scores above the one before it

    Examples:
      | command                     | level            | reversibility |
      | rm notes.txt                | medium           | reversible    |
      | rm -rf ./build-output       | medium or higher | reversible    |
      | rm -rf /                    | critical         | irreversible  |
      | rm -rf --no-preserve-root / | critical         | irreversible  |

  @id:risk-scoring.amplifiers.002 @rule:risk.amplifiers.generic-arguments-on-any-binary @verified @source:scoville/amplifiers.py#AMPS @test:tests/test_scoville.py#test_secret_on_the_command_line @test:tests/test_scoville.py#test_verification_disabled_is_generic @test:tests/test_scoville.py#test_production_target_escalates @test:tests/test_scoville.py#test_assume_yes_is_the_same_signal_on_every_binary
  Scenario Outline: Dangerous arguments raise the score whichever tool they are passed to
    Given no repository policy applies
    When the operator scores "<command>"
    Then it scores higher than "<plain>"
    And the report lists the factor "<factor>"

    Examples:
      | command                                        | plain                            | factor                                                                         |
      | curl --token=abc123 https://api.example.com    | curl https://api.example.com     | a credential on the command line is visible to every user on the host via `ps` |
      | helm upgrade api ./c --skip-tls-verify         | helm upgrade api ./c             | certificate verification disabled                                              |
      | apt-get install -y --allow-unauthenticated foo | apt-get install -y foo           | package or image signature verification disabled                               |
      | kubectl delete deploy api -n prod              | kubectl delete deploy api -n dev | the target names a production environment                                      |
      | frobctl delete cluster -y                      | frobctl delete cluster           | auto-confirms every prompt                                                     |

  @id:risk-scoring.amplifiers.003 @rule:risk.amplifiers.no-double-counting @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_a_rule_does_not_also_collect_the_amp_it_exists_for @test:tests/test_scoville.py#test_a_rule_that_prices_its_own_yes_does_not_double_count @test:tests/test_scoville.py#test_verification_disabled_is_generic
  Scenario Outline: A flag the matching rule already prices is not counted a second time
    Given a rule exists because of the flag on the command
    When the operator scores "<command>"
    Then <outcome>

    Examples:
      | command                     | outcome                                                          |
      | fsck -y /dev/sdb1           | the report does not list the factor "auto-confirms every prompt" |
      | curl -k https://example.com | it scores the same as "curl --insecure https://example.com"      |

  @id:risk-scoring.amplifiers.004 @rule:risk.amplifiers.system-directory-targets @verified @source:scoville/scoring.py#_dir_factor @test:tests/test_scoville.py#test_system_dirs_escalate_but_build_dirs_dampen @test:tests/test_scoville.py#test_paths_under_a_system_dir_score_below_the_dir_itself
  Scenario Outline: Targeting a system directory raises the score more than targeting a path beneath it
    Given no repository policy applies
    When the operator scores "<command>"
    Then it ranks <ordering>

    Examples:
      | command               | ordering                                   |
      | rm -rf /etc           | critical, irreversible, host-wide          |
      | rm -rf /var/lib/mysql | above rm -rf ./build and below rm -rf /var |
      | rm -rf node_modules   | below rm -rf /srv/data                     |

  @id:risk-scoring.amplifiers.005 @rule:risk.amplifiers.device-node-target @inferred @source:scoville/scoring.py#_dir_factor
  Scenario Outline: Pointing an ordinary file tool at a device node is flagged, but disk tools are not
    Given no repository policy applies
    When the operator scores "<command>"
    Then the report <outcome> the factor "target is a device node"

    Examples:
      | command              | outcome       |
      | cp disk.img /dev/sdb | lists         |
      | wipefs /dev/sdb      | does not list |

  @id:risk-scoring.amplifiers.006 @rule:risk.amplifiers.widen-scope-and-reversibility @verified @source:scoville/amplifiers.py#AMPS @test:tests/test_scoville.py#test_privileged_and_host_mount_widen_the_scope @test:tests/test_scoville.py#test_open_to_the_world_is_generic
  Scenario Outline: An amplifier can widen how far the damage reaches
    Given no repository policy applies
    When the operator scores "<command>"
    Then its blast radius is <scope>

    Examples:
      | command                                      | scope   |
      | docker run --privileged -v /:/host alpine sh | host    |
      | frobctl allow --cidr ::/0                    | network |

  @id:risk-scoring.amplifiers.007 @rule:risk.amplifiers.negated-purge-is-not-a-purge @verified @source:scoville/amplifiers.py#AMPS @test:tests/test_scoville.py#test_a_negated_cascade_is_not_a_purge
  Scenario: A purge flag set to false does not count as asking for the thorough variant
    Given no repository policy applies
    When the operator scores "argocd app delete api --cascade=false"
    Then it scores lower than "argocd app delete api"
    And the report does not list the factor "asks for the thorough variant"
