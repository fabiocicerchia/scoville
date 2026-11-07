@domain:live-context @area:container-introspection @from:scoville/introspection
Feature: Resolving what a container image actually runs
  Lets an operator see the real risk of docker run, exec and start lines whose payload is hidden in an image ENTRYPOINT/CMD, by asking the local docker only to inspect, never to pull or run.

  Background:
    Given a command that starts a container without giving it an explicit command

  @id:live-context.container-introspection.001 @rule:live-context.container-introspection.opt-in-only @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_introspection_is_opt_in
  Scenario: Docker is never consulted unless introspection is asked for
    Given the image acme/cleaner:1.0 is available locally
    When the operator scores 'docker run acme/cleaner:1.0' without --introspect
    Then docker is not queried
    And the command is rated medium
    And a factor says 'no explicit command: what runs is the image ENTRYPOINT/CMD, not this line; re-run with --introspect to resolve it'

  @id:live-context.container-introspection.002 @rule:live-context.container-introspection.resolved-entrypoint-scored @verified @source:scoville/introspection.py#introspect_target @test:tests/test_scoville.py#test_introspect_resolves_a_dangerous_entrypoint
  Scenario: A resolved image entrypoint is scored as the command that really runs
    Given the local image acme/cleaner:1.0 has the entrypoint /bin/sh -c 'rm -rf /data'
    When the operator scores 'docker run acme/cleaner:1.0' with --introspect
    Then the command is rated critical
    And a factor names the resolved entrypoint and its level
    And the report says it runs in a fresh container from this image

  @id:live-context.container-introspection.003 @rule:live-context.container-introspection.root-image-flagged @verified @source:scoville/introspection.py#introspect_target @test:tests/test_scoville.py#test_introspect_resolves_a_dangerous_entrypoint @questionable
  Scenario Outline: An image that runs as root, or names no user, is flagged as running as root
    Given the local image acme/cleaner:1.0 sets the user '<user>'
    When the operator scores 'docker run acme/cleaner:1.0' with --introspect
    Then the report <outcome> the factor 'the image runs as root'

    Examples:
      | user   | outcome          |
      | (none) | includes         |
      | root   | includes         |
      | 0      | includes         |
      | app    | does not include |

  @id:live-context.container-introspection.004 @rule:live-context.container-introspection.never-pulls-unresolved @verified @source:scoville/introspection.py#introspect_target @test:tests/test_scoville.py#test_introspect_reports_when_it_cannot_resolve
  Scenario Outline: An image or container that cannot be inspected locally is reported unresolved, never pulled
    Given docker is installed but '<target>' is not present locally
    When the operator scores '<command>' with --introspect
    Then nothing is pulled or started
    And a factor says '<note>'
    And the command keeps its unresolved rating

    Examples:
      | command                     | target           | note                                                                                                             |
      | docker run acme/cleaner:1.0 | acme/cleaner:1.0 | cannot inspect image 'acme/cleaner:1.0' — not pulled here, or no docker daemon; scoville never pulls to find out |
      | docker start web            | web              | cannot inspect container 'web' — not running here, or no docker daemon                                           |

  @id:live-context.container-introspection.005 @rule:live-context.container-introspection.no-docker-reported @verified @source:scoville/introspection.py#introspect_target @test:tests/test_scoville.py#test_introspect_without_docker_says_so
  Scenario: Without a docker CLI the report says the entrypoint could not be resolved
    Given no docker CLI is installed on this machine
    When the operator scores 'docker run acme/cleaner:1.0' with --introspect
    Then a factor says 'no docker CLI here to resolve it with'
