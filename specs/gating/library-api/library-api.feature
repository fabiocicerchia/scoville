@domain:gating @area:library-api @from:scoville/scoville
Feature: Scoring commands from Python
  Lets hook and CI authors import scoville and score commands in-process, getting the same verdicts the CLI prints without running a subprocess.

  Background:
    Given the scoville package is installed

  @id:gating.library-api.001 @rule:gating.library-api.analyze-importable @verified @source:scoville/__init__.py#analyze @test:tests/test_scoville.py#test_rm_escalates_with_flags_then_target
  Scenario Outline: The scoring engine can be imported and returns one verdict per command
    Given an integrator's Python code imports analyze from the scoville package
    When the integrator analyzes the text "<command>"
    Then one result per command comes back, each with a score, a level and a reversibility
    And the highest-scoring result has level "<level>"
    And the highest-scoring result has reversibility "<reversibility>"

    Examples:
      | command      | level    | reversibility |
      | rm notes.txt | medium   | -             |
      | rm -rf /     | critical | irreversible  |
