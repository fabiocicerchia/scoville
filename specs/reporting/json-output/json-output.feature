@domain:reporting @area:json-output @from:scoville/output
Feature: Consuming results as JSON
  Gives hooks and CI a stable machine-readable verdict: an overall summary plus every scored command with its factors.

  Background:
    Given the operator requests JSON output

  @id:reporting.json-output.001 @rule:reporting.json.overall-and-commands @verified @source:scoville/output.py#public @test:tests/test_scoville.py#test_json_output_and_exit_codes @test:tests/test_scoville.py#test_json_carries_the_rule_id_on_every_factor_that_has_one
  Scenario: JSON output carries an overall verdict and every command scored
    Given a script with the commands "ls; rm -rf /etc"
    When the operator scores the script
    Then the document has an "overall" object with score, level, scope, reversibility, commands and worst
    And "overall.worst" is "rm -rf /etc"
    And the document has a "commands" list with one entry per command, each listing its factors
    And commands found inside another command appear under that command's "carries" in the same shape
