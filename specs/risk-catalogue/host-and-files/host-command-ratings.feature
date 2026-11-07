@domain:risk-catalogue @area:host-and-files @from:scoville/rules-host
Feature: Rating commands that change the local machine
  Gives operators and hook authors a calibrated rating for everyday host commands (files, devices, services, networking, packages, eval), so that a harmless inspection passes and a lockout or wipe is stopped before it runs.

  Background:
    Given scoville scores commands without running them

  @id:risk-catalogue.host-and-files.004 @rule:host.reads.inspection-is-safe @verified @source:scoville/rules_host.py#HOST_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued @test:tests/test_scoville.py#test_ifup_is_fine_ifdown_is_not
  Scenario Outline: Commands that only inspect the host, or only bring an interface up, are rated safe
    When the operator scores "<command>"
    Then the command is rated "safe"

    Examples:
      | command                 |
      | ls -la /etc             |
      | sed 's/a/b/' config.ini |
      | find . -name '*.py'     |
      | ip addr show            |
      | systemctl status nginx  |
      | dpkg -l                 |
      | rpm -qa                 |
      | apt list --installed    |
      | ifup eth0               |

  @id:risk-catalogue.host-and-files.005 @rule:host.system.subcommand-decides-rating @verified @source:scoville/rules_host.py#HOST_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued @test:tests/test_scoville.py#test_crontab_r
  Scenario Outline: The subcommand or option decides the rating, so undoing or querying scores below the destructive form of the same binary
    When the operator scores "<command>"
    Then the command is rated "<level>"

    Examples:
      | command                 | level  |
      | shutdown -c             | safe   |
      | shutdown -h now         | high   |
      | crontab -l              | safe   |
      | crontab -r              | high   |
      | mount /dev/sdb1 /mnt    | low    |
      | mount -o remount,ro /   | high   |
      | systemctl status ssh    | safe   |
      | systemctl restart nginx | low    |
      | systemctl stop nginx    | medium |
      | systemctl mask ssh      | high   |

  @id:risk-catalogue.host-and-files.006 @rule:host.devices.format-is-critical @verified @source:scoville/rules_host.py#HOST_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Formatting or repartitioning a device is critical and cannot be undone
    When the operator scores "<command>"
    Then the command is rated "critical"
    And its reversibility is "irreversible"

    Examples:
      | command             |
      | mkfs.ext4 /dev/sda1 |
      | wipefs -a /dev/sdb  |

  @id:risk-catalogue.host-and-files.007 @rule:host.network.lockout-risk-flagged @verified @source:scoville/rules_host.py#HOST_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued @test:tests/test_scoville.py#test_ifup_is_fine_ifdown_is_not
  Scenario Outline: Taking down an interface or firewall rules is flagged as a network-wide lockout risk
    When the operator scores "<command>"
    Then the command is rated "<level>"
    And its blast radius is "network"

    Examples:
      | command                    | level  |
      | ifdown eth0                | medium |
      | ip link set eth0 down      | medium |
      | ip route del default       | medium |
      | nmcli connection down eth0 | medium |
      | ufw disable                | medium |
      | iptables -F                | high   |
      | iptables -P INPUT DROP     | high   |

  @id:risk-catalogue.host-and-files.008 @rule:host.exec.eval-is-high @verified @source:scoville/rules_host.py#HOST_RULES @test:tests/test_scoville.py#test_eval_is_high_because_nothing_can_read_it @test:tests/test_scoville.py#test_source_is_a_readable_wrapper_not_an_eval @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Any eval is rated high because what it runs cannot be read from the line, while source scores lower
    When the operator scores "<command>"
    Then the command is rated "<level>"

    Examples:
      | command               | level  |
      | eval "echo hello"     | high   |
      | eval "$PAYLOAD"       | high   |
      | source scripts/env.sh | medium |

  @id:risk-catalogue.host-and-files.009 @rule:host.packages.install-and-remove-are-not-reads @verified @source:scoville/rules_host.py#HOST_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Installing, removing or publishing packages is rated as a change to the host, not a read
    When the operator scores "<command>"
    Then the command is rated "<level>"

    Examples:
      | command                      | level  |
      | apt install nginx            | medium |
      | pip install requests         | medium |
      | apt-get remove --purge nginx | medium |
      | pacman -Rns base-devel       | medium |
      | dpkg -P nginx                | medium |
      | apt full-upgrade             | medium |
      | nix-collect-garbage -d       | medium |
      | rpm -e glibc                 | high   |
      | npm publish                  | high   |

  @id:risk-catalogue.host-and-files.010 @rule:host.packages.metadata-refresh-rated-as-install @inferred @source:scoville/rules_host.py#HOST_RULES @questionable
  Scenario Outline: Refreshing package metadata is rated like an install
    When the operator scores "<command>"
    Then the command is rated "medium"
    And the contributing rule is the package install rule, not the metadata query rule

    Examples:
      | command     |
      | apt update  |
      | brew update |
