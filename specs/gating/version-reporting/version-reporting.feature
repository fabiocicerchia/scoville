@domain:gating @area:version-reporting @from:scoville/version
Feature: Reporting the installed version
  Lets operators and CI pipelines confirm which scoville release, and so which rule calibration, is scoring their commands.

  @id:gating.version-reporting.001 @rule:gating.version.reports-installed-release @inferred @source:scoville/version.py#__version__
  Scenario: The operator can ask scoville which release is installed
    Given scoville release 0.4.2 is installed
    When the operator runs `scoville --version`
    Then the output is `scoville 0.4.2`
    And no command is scored
    And the exit code is 0
