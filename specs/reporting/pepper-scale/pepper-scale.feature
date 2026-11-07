@domain:reporting @area:pepper-scale @from:scoville/output
Feature: Naming risk on the pepper scale
  Lets an operator read risk levels as chilli peppers instead of bands, without changing the analysis or what machines consume.

  Background:
    Given the operator chooses the pepper scale

  @id:reporting.pepper-scale.001 @rule:reporting.peppers.level-names @verified @source:scoville/output.py#label @test:tests/test_scoville.py#test_scale_only_changes_the_label @test:tests/test_scoville.py#test_quiet_uses_ascii_slugs @test:tests/test_scoville.py#test_pepper_labels_cover_every_band @test:tests/test_scoville.py#test_pepper_heat_rises_with_the_band
  Scenario Outline: Each risk level is named after a pepper with its heat
    Given a command that scores at level <level>
    When the operator scores the command
    Then the text report labels it "<label>"
    And the summary line adds "(<shu>)"
    And quiet output labels it "<slug>"

    Examples:
      | level    | label                | shu          | slug            |
      | safe     | BELL PEPPER          | 0 SHU        | bell-pepper     |
      | low      | 🌶 JALAPEÑO           | 2.5-8k SHU   | jalapeno        |
      | medium   | 🌶🌶 CAYENNE           | 30-50k SHU   | cayenne         |
      | high     | 🌶🌶🌶 HABANERO         | 100-350k SHU | habanero        |
      | critical | 🌶🌶🌶🌶 CAROLINA REAPER | 1.6-2.2M SHU | carolina-reaper |

  @id:reporting.pepper-scale.002 @rule:reporting.peppers.only-the-label-changes @verified @source:scoville/output.py#label @test:tests/test_scoville.py#test_scale_only_changes_the_label @test:tests/test_scoville.py#test_json_is_unaffected_by_the_scale
  Scenario Outline: The pepper scale changes the names, not the score or the machine output
    Given the command "rm -rf /"
    When the operator scores the command <format>
    Then <outcome>

    Examples:
      | format  | outcome                                                                                                |
      | as text | the report shows CAROLINA REAPER, not CRITICAL, still with 100/100 and "target is the filesystem root" |
      | as JSON | the overall level is "critical"                                                                        |
