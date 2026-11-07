@domain:developer-tooling @area:container-image @from:scoville/dockerfile
Feature: Running scoville from its container image
  Lets operators drop scoville into a CI job or hook as a container, passing commands straight to the CLI without installing Python packages.

  Background:
    Given the operator has built the scoville container image

  @id:developer-tooling.container-image.001 @rule:tooling.container-image.runs-cli-with-arguments @inferred @source:Dockerfile#ENTRYPOINT
  Scenario Outline: Arguments given to the container go straight to scoville
    When the operator runs the image with the arguments <args>
    Then scoville runs with <args> as its command-line arguments
    And the container's output and exit code are scoville's

    Examples:
      | args                        |
      | "ls -la"                    |
      | --version                   |
      | --json "chmod 777 build.sh" |

  @id:developer-tooling.container-image.002 @rule:tooling.container-image.runs-unprivileged @inferred @source:Dockerfile#USER
  Scenario: The container runs scoville as an unprivileged user, not root
    When the operator runs the image without overriding the user
    Then scoville runs as the user "app" with uid 10001
    And scoville does not run as root inside the container
