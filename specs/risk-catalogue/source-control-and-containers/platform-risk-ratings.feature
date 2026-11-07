@domain:risk-catalogue @area:source-control-and-containers @from:scoville/rules-platform
Feature: Rating source control, container, cluster and cloud commands
  Operators and CI gates rely on scoville to rate git, docker, Kubernetes, Terraform/Helm and cloud CLI commands by how much they can destroy, so that history loss, data-volume loss and account-wide teardown are stopped before they run.

  Background:
    Given scoville scores commands without running them

  @id:risk-catalogue.source-control-and-containers.007 @rule:platform.read-only.queries-are-safe @verified @source:scoville/rules_platform.py#PLATFORM_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued @test:tests/test_scoville.py#test_aws_read_is_free_write_is_not @test:tests/test_scoville.py#test_terraform_plan_is_free_destroy_is_not
  Scenario Outline: Read-only platform queries are rated safe
    Given a command that only reads state from git, a container engine, a cluster, Terraform, Helm or a cloud account
    When the operator scores "<command>"
    Then the command is rated "safe"

    Examples:
      | command                          |
      | git status                       |
      | git log --oneline -20            |
      | docker ps -a                     |
      | kubectl get pods -A              |
      | kubectl auth can-i delete pods   |
      | helm list -A                     |
      | terraform plan                   |
      | terraform validate               |
      | aws s3api list-buckets           |
      | aws iam get-role --role-name app |
      | gcloud projects describe acme    |
      | az vm list                       |

  @id:risk-catalogue.source-control-and-containers.008 @rule:platform.git.history-loss-is-rated-by-recoverability @verified @source:scoville/rules_platform.py#PLATFORM_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued @test:tests/test_scoville.py#test_git_force_push_and_clean
  Scenario Outline: Git commands are rated by how much history or work they can lose
    Given a git working copy with a remote
    When the operator scores a git command that performs <operation>
    Then the command is rated "<level>"

    Examples:
      | operation                                     | level  |
      | a plain push                                  | low    |
      | a lease-guarded force-push to main            | low    |
      | a force-push to a feature branch              | medium |
      | a force-push to main                          | high   |
      | a remote branch delete                        | medium |
      | a mirror push                                 | high   |
      | an immediate reflog expiry of all refs        | high   |
      | a hard reset three commits back               | medium |
      | a forced clean of untracked and ignored files | medium |
      | a checkout of the whole tree over local edits | medium |
      | clearing the stash                            | medium |
      | a force-delete of a local branch              | low    |
      | an interactive rebase                         | medium |

  @id:risk-catalogue.source-control-and-containers.009 @rule:platform.containers.data-volume-loss-is-high @verified @source:scoville/rules_platform.py#PLATFORM_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Removing container volumes is rated above removing containers
    Given a host running containers with named volumes
    When the operator scores "<command>"
    Then the command is rated "<level>"

    Examples:
      | command                 | level  |
      | docker stop web         | low    |
      | docker rmi acme/api:old | low    |
      | docker image prune      | medium |
      | docker system prune -a  | medium |
      | docker volume rm pgdata | high   |
      | docker-compose down -v  | high   |

  @id:risk-catalogue.source-control-and-containers.010 @rule:platform.kubernetes.cascading-deletes-outrank-restarts @verified @source:scoville/rules_platform.py#PLATFORM_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Cluster deletions are rated by what they cascade to, and a named pod delete counts as a restart
    Given a Kubernetes cluster
    When the operator scores "<command>"
    Then the command is rated "<level>"

    Examples:
      | command                               | level    |
      | kubectl apply -f deploy.yaml          | low      |
      | kubectl cordon node-1                 | low      |
      | kubectl delete pod api-1              | low      |
      | kubectl delete deploy api             | medium   |
      | kubectl drain node-1                  | medium   |
      | kubectl scale deploy api --replicas=0 | medium   |
      | kubectl delete pvc data-0             | high     |
      | kubectl delete pods --all -A          | high     |
      | kubectl delete ns prod                | critical |
      | kubectl delete crd widgets.acme.io    | critical |

  @id:risk-catalogue.source-control-and-containers.011 @rule:platform.iac.destroy-outranks-apply @verified @source:scoville/rules_platform.py#PLATFORM_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued @test:tests/test_scoville.py#test_terraform_plan_is_free_destroy_is_not
  Scenario Outline: Infrastructure teardown is rated above applying changes
    Given a Terraform workspace or a Helm release in a cluster
    When the operator scores "<command>"
    Then the command is rated "<level>"

    Examples:
      | command                                 | level  |
      | terraform apply                         | medium |
      | terraform taint aws_instance.web        | medium |
      | terraform state rm aws_db_instance.main | high   |
      | terraform destroy                       | high   |
      | helm upgrade --install api ./chart      | medium |
      | helm uninstall api                      | high   |

  @id:risk-catalogue.source-control-and-containers.012 @rule:platform.cloud.account-wide-destruction-is-critical @verified @source:scoville/rules_platform.py#PLATFORM_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued @test:tests/test_scoville.py#test_aws_read_is_free_write_is_not
  Scenario Outline: Cloud commands are rated by what they destroy, and losing data, keys or whole accounts is rated highest
    Given a cloud CLI logged in to an account
    When the operator scores "<command>"
    Then the command is rated "<level>"

    Examples:
      | command                                                                        | level    |
      | aws ec2 create-tags --resources i-1 --tags Key=a,Value=b                       | low      |
      | aws s3 rb s3://assets                                                          | high     |
      | aws ec2 terminate-instances --instance-ids i-123                               | high     |
      | aws iam delete-user --user-name deploy                                         | high     |
      | aws s3 rm s3://assets --recursive                                              | critical |
      | aws rds delete-db-instance --db-instance-identifier prod --skip-final-snapshot | critical |
      | aws cloudformation delete-stack --stack-name prod                              | critical |
      | aws kms schedule-key-deletion --key-id abc                                     | critical |
      | aws organizations remove-account-from-organization --account-id 111            | critical |
      | gcloud compute instances delete web-1                                          | high     |
      | gcloud projects delete acme                                                    | critical |
      | az vm delete --name web-1                                                      | high     |
      | az group delete --name prod --yes                                              | critical |

  @id:risk-catalogue.source-control-and-containers.013 @rule:platform.kubernetes.namespace-flag-read-as-namespace-delete @inferred @source:scoville/rules_platform.py#PLATFORM_RULES @questionable
  Scenario: Deleting a resource with a namespace flag is rated as deleting the namespace
    Given a Kubernetes cluster with a namespace "staging"
    When the operator scores "kubectl delete deploy api --namespace staging"
    Then the command is attributed to the namespace-deletion rule
    And the reason shown says deleting a namespace cascades to everything inside it

  @id:risk-catalogue.source-control-and-containers.014 @rule:platform.git.branch-name-read-as-force-checkout @inferred @source:scoville/rules_platform.py#PLATFORM_RULES @questionable
  Scenario: Switching to a branch whose name contains a dash-f is rated as a forced checkout
    Given a git working copy
    When the operator scores "git switch -c bug-fix"
    Then the command is attributed to the forced-checkout rule
    And the reason shown says it overwrites local modifications
