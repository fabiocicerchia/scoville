@domain:risk-catalogue @area:data-and-services @from:scoville/rules-services
Feature: Scoring database and data-service commands
  Operators and the hooks they put in front of agents need statements that wipe tables, keyspaces, queues or schemas flagged high or critical before they run, while a plain read-only query stays low.

  Background:
    Given scoville is scoring a command without running it

  @id:risk-catalogue.data-and-services.007 @rule:data.databases.destructive-statements-are-high-or-critical @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued @test:tests/test_scoville.py#test_sql_without_where_clause
  Scenario Outline: Destructive database statements land in the high or critical band
    Given a database client command carries the statement <command>
    When the operator scores the command
    Then the command is reported at level <level>

    Examples:
      | command                                       | level    |
      | psql -c 'DROP TABLE users'                    | high     |
      | psql -c 'DROP DATABASE app'                   | critical |
      | mysql -e 'DELETE FROM orders'                 | high     |
      | mysql -e 'TRUNCATE TABLE sessions'            | high     |
      | psql -c 'ALTER TABLE users DROP COLUMN email' | high     |
      | psql -c 'GRANT ALL ON DATABASE app TO deploy' | medium   |
      | redis-cli FLUSHALL                            | critical |
      | mongosh --eval 'db.dropDatabase()'            | critical |
      | pg_restore --clean -d app dump.sql            | high     |

  @id:risk-catalogue.data-and-services.008 @rule:data.databases.unbounded-delete-outranks-filtered @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_scoville.py#test_sql_without_where_clause
  Scenario: A DELETE without a WHERE clause scores higher than one with a WHERE clause
    Given one command deletes from a table with no WHERE clause
    And another command deletes from the same table with a WHERE clause
    When the operator scores both commands
    Then the delete with no WHERE clause has the higher score
    And the delete with no WHERE clause is reported at level high

  @id:risk-catalogue.data-and-services.009 @rule:data.databases.client-session-is-low @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_scoville.py#test_sql_without_where_clause @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario: A read-only database query is reported as low risk
    Given a database client command runs only a SELECT
    When the operator scores the command
    Then the command is reported at level low

  @id:risk-catalogue.data-and-services.010 @rule:data.services.wiping-brokers-and-schemas-is-high-or-critical @verified @source:scoville/rules_services.py#SERVICE_RULES @test:tests/test_corpus.py#test_corpus_command_scores_as_catalogued
  Scenario Outline: Resetting brokers, write-ahead logs or migration schemas lands in the high or critical band
    Given the command is <command>
    When the operator scores the command
    Then the command is reported at level <level>

    Examples:
      | command                                         | level    |
      | rabbitmqctl reset                               | high     |
      | kafka-topics --delete --topic events            | high     |
      | pg_resetwal /var/lib/pgsql/data                 | critical |
      | pg_ctl stop -m immediate -D /var/lib/pgsql/data | medium   |
      | mysqladmin shutdown                             | high     |
      | flyway clean                                    | critical |
      | liquibase dropAll                               | critical |
      | rails db:drop                                   | critical |
      | python manage.py flush                          | high     |
      | npx prisma migrate reset                        | high     |
      | alembic downgrade base                          | high     |

  @id:risk-catalogue.data-and-services.011 @rule:data.migrations.any-python-flush-is-scored-as-database-flush @inferred @source:scoville/rules_services.py#SERVICE_RULES @questionable
  Scenario: Any python command that mentions flush is scored as a Django database flush
    Given a python command runs inline code that calls sys.stdout.flush()
    When the operator scores the command
    Then the command is attributed to the Django flush rule
    And the reason given is that flush deletes every row in every table
