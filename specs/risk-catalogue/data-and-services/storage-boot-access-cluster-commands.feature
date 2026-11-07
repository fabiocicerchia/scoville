@domain:risk-catalogue @area:data-and-services @from:scoville/rules-services
Feature: Scoring storage, boot, access and cluster commands
  Operators need the commands that erase disks, break the boot path, widen access, destroy audit evidence or pull nodes out of clusters ranked by how badly they can hurt, so a gate can stop them.

  Background:
    Given scoville is scoring a command without running it

  @id:risk-catalogue.data-and-services.012 @rule:data.storage.device-erasure-is-critical-or-high @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Erasing or truncating disks, volumes and pools lands in the high or critical band
    Given the command is <command>
    When the operator scores the command
    Then the command is reported at level <level>

    Examples:
      | command                                   | level    |
      | blkdiscard /dev/nvme0n1                   | critical |
      | cryptsetup luksFormat /dev/sdb1           | critical |
      | badblocks -w /dev/sdc                     | critical |
      | zpool destroy tank                        | critical |
      | mdadm --zero-superblock /dev/sdb1         | high     |
      | resize2fs /dev/vg0/data 10G               | high     |
      | diskutil eraseDisk JHFS+ Empty /dev/disk2 | critical |

  @id:risk-catalogue.data-and-services.013 @rule:data.storage.fsck-auto-repair-is-medium-check-only-is-safe @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Auto-repairing a filesystem is medium risk while a check-only run is safe
    Given the command is <command>
    When the operator scores the command
    Then the command is reported at level <level>

    Examples:
      | command           | level  |
      | fsck -y /dev/sdb1 | medium |
      | fsck -n /dev/sdb1 | safe   |

  @id:risk-catalogue.data-and-services.014 @rule:data.boot.boot-path-changes-are-flagged @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Changing the boot path, kernel or clock is flagged before the next reboot finds out
    Given the command is <command>
    When the operator scores the command
    Then the command is reported at level <level>

    Examples:
      | command                         | level  |
      | grub-install /dev/sda           | high   |
      | update-grub                     | high   |
      | tune2fs -U random /dev/sda1     | high   |
      | kexec -e                        | high   |
      | modprobe -r e1000e              | medium |
      | timedatectl set-time 2020-01-01 | medium |

  @id:risk-catalogue.data-and-services.015 @rule:data.boot.module-load-scored-as-unload @inferred @source:scoville/rules_services.py#SERVICE_RULES @questionable
  Scenario: Loading a kernel module is scored the same as unloading one
    Given the command loads a kernel module with modprobe and no removal flag
    When the operator scores the command
    Then the command is attributed to the kernel-module rule
    And the reason given is that unloading the module can remove the host's storage or network driver

  @id:risk-catalogue.data-and-services.016 @rule:data.exposure.widening-access-is-flagged @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Making data public or minting broad credentials is flagged
    Given the command is <command>
    When the operator scores the command
    Then the command is reported at level <level>

    Examples:
      | command                                                                                    | level  |
      | aws s3api put-bucket-acl --bucket assets --acl public-read                                 | high   |
      | gcloud storage buckets add-iam-policy-binding gs://b --member=allUsers --role=roles/viewer | high   |
      | aws iam create-access-key --user-name deploy                                               | medium |
      | setenforce 0                                                                               | medium |

  @id:risk-catalogue.data-and-services.017 @rule:data.audit.erasing-evidence-is-flagged @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Deleting audit rules or vacuuming the journal is flagged, while reading the journal is safe
    Given the command is <command>
    When the operator scores the command
    Then the command is reported at level <level>

    Examples:
      | command                     | level  |
      | auditctl -D                 | high   |
      | journalctl --vacuum-time=1s | medium |
      | journalctl -u nginx         | safe   |

  @id:risk-catalogue.data-and-services.018 @rule:data.clusters.keys-certs-and-membership-changes-are-flagged @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Revoking certificates, deleting keys and removing nodes from clusters or networks are flagged
    Given the command is <command>
    When the operator scores the command
    Then the command is reported at level <level>

    Examples:
      | command                              | level    |
      | certbot revoke --cert-name api       | high     |
      | gpg --delete-secret-keys ABCD1234    | high     |
      | kubeadm reset                        | critical |
      | docker swarm leave --force           | high     |
      | etcdctl snapshot restore snapshot.db | high     |
      | conntrack -F                         | medium   |
      | ip netns delete blue                 | medium   |
      | ovs-vsctl del-br br0                 | medium   |
