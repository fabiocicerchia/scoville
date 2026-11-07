@domain:risk-catalogue @area:data-and-services @from:scoville/rules-clis
Feature: Rating secret-store, backup and storage commands
  Shows operators which vault, velero and storage or backup commands lose data, secrets or the last restorable copy, and which only look as if they do.

  @id:risk-catalogue.data-and-services.001 @rule:catalogue.vault.rated-per-operation @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Each Vault operation is rated by what it permanently removes
    When the operator scores "<command>"
    Then the level is <level>

    Examples:
      | command                                          | level    |
      | vault kv list kv/                                | safe     |
      | vault kv delete kv/app/db                        | medium   |
      | vault kv destroy -versions=1 kv/app/db           | high     |
      | vault secrets disable kv                         | high     |
      | vault auth disable approle                       | high     |
      | vault audit disable file                         | high     |
      | vault token revoke hvs.CAESIA                    | medium   |
      | vault policy delete deploy                       | medium   |
      | vault operator seal                              | high     |
      | vault operator raft remove-peer node-2           | high     |
      | vault operator raft snapshot restore backup.snap | critical |

  @id:risk-catalogue.data-and-services.002 @rule:catalogue.vault.soft-delete-is-recoverable @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_vault_kv_delete_is_soft_and_kv_destroy_is_not
  Scenario Outline: A Vault soft delete is recoverable, while destroying versions is not
    When the operator scores "<command>"
    Then the reversibility is <reversibility>

    Examples:
      | command                            | reversibility |
      | vault kv delete kv/app/db          | recoverable   |
      | vault kv destroy kv/app/db         | irreversible  |
      | vault kv metadata delete kv/app/db | irreversible  |

  @id:risk-catalogue.data-and-services.003 @rule:catalogue.secrets.printing-a-secret-is-not-safe @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: A command that prints a secret or token to the terminal is never rated safe
    When the operator scores "<command>"
    Then the level is <level>
    And the report warns that the value lands in scrollback and CI logs

    Examples:
      | command                | level  |
      | vault read kv/data/app | low    |
      | gh auth token          | medium |

  @id:risk-catalogue.data-and-services.004 @rule:catalogue.backups.losing-a-restore-point-is-high @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_backup_tools_are_scored_on_the_copy_of_last_resort @test:tests/test_scoville.py#test_velero_restore_delete_removes_the_record_not_the_restore @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Removing a backup or its schedule rates higher than taking or tidying one
    When the operator scores "<command>"
    Then the level is <level>

    Examples:
      | command                                               | level  |
      | velero backup create daily-1 --include-namespaces app | safe   |
      | velero restore delete r1                              | medium |
      | velero restore create --from-backup daily-1           | medium |
      | velero schedule delete nightly                        | medium |
      | velero backup delete daily-1                          | high   |
      | velero backup-location delete default                 | high   |
      | velero uninstall                                      | high   |
      | restic forget --prune --keep-last 1                   | high   |

  @id:risk-catalogue.data-and-services.005 @rule:catalogue.storage.data-removing-verbs @verified @source:scoville/rules_clis.py#CLI_RULES @test:tests/test_scoville.py#test_rclone_sync_deletes_at_the_destination @test:tests/test_scoville.py#test_etcd_prefix_delete_is_cluster_state @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Storage commands that delete data at the destination are rated by how much they take
    When the operator scores "<command>"
    Then the level is <level>

    Examples:
      | command                             | level    |
      | rclone sync /srv/data remote:bucket | medium   |
      | rclone purge remote:bucket          | high     |
      | s3cmd rb s3://assets                | high     |
      | virsh undefine vm1                  | high     |
      | snap remove docker                  | medium   |
      | etcdctl del --prefix ''             | critical |

  @id:risk-catalogue.data-and-services.006 @rule:catalogue.backups.keyword-anywhere-triggers-forget @inferred @source:scoville/rules_clis.py#CLI_RULES @questionable
  Scenario Outline: A backup-tool command is rated as dropping snapshots when forget, prune or delete appears anywhere in it
    When the operator scores "<command>"
    Then the level is high
    And the explanation says it drops snapshots from the backup repository

    Examples:
      | command                       |
      | restic backup /srv/prune-logs |
      | borg list ::delete-me         |
