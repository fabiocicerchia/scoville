@domain:command-reading @area:functions-and-aliases @from:scoville/scoring
Feature: Resolving functions and aliases defined in the input
  Lets an operator see what a script's own helpers and aliases really run, scored the same on every machine.

  Background:
    Given the script defines `alias k=kubectl` and a `deploy` function that deletes a namespace

  @id:command-reading.functions-and-aliases.007 @rule:functions.resolve.opt-in-under-introspect @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_resolution_is_opt_in @test:tests/test_scoville.py#test_a_function_call_is_scored_as_its_body @test:tests/test_scoville.py#test_an_alias_shadowing_a_binary_is_expanded
  Scenario Outline: Functions and aliases are resolved only under introspection
    When the operator scores the script <mode>
    Then `deploy prod` is <deploy level>
    And `k delete ns prod` is <alias level>

    Examples:
      | mode                 | deploy level | alias level |
      | without --introspect | low          | high        |
      | with --introspect    | high         | critical    |

  @id:command-reading.functions-and-aliases.008 @rule:functions.resolve.call-scored-as-body @verified @source:scoville/scoring.py#_score_local_definition @test:tests/test_scoville.py#test_a_function_call_is_scored_as_its_body @test:tests/test_scoville.py#test_an_alias_shadowing_a_binary_is_expanded
  Scenario: A function call is scored as its body and an alias as its expansion
    Given introspection is on
    When the operator scores the script
    Then `deploy prod` is high, scope cluster, irreversible, with a factor naming the line the function is defined on
    And `k delete ns prod` is critical, with a factor saying alias `k` is `kubectl` and it was scored as `kubectl delete ns prod`

  @id:command-reading.functions-and-aliases.009 @rule:functions.resolve.only-definitions-in-scope @verified @source:scoville/scoring.py#score_command @test:tests/test_scoville.py#test_a_function_defined_after_the_call_is_not_applied @test:tests/test_scoville.py#test_the_last_definition_before_the_call_wins @test:tests/test_scoville.py#test_a_name_is_resolved_at_the_call_site_not_the_definition
  Scenario Outline: Only a definition in scope at the call is used, and the latest one wins
    Given introspection is on
    When the operator scores `<script>`
    Then the call is <outcome>

    Examples:
      | script                                                          | outcome                     |
      | cleanup prod, then cleanup() { rm -rf /var/lib/data; }          | an unknown command, low     |
      | sync() { echo safe; }, then sync() { rm -rf /; }, then sync now | critical, defined on line 2 |
      | a() { b; }, then b() { rm -rf /etc; }, then a                   | critical                    |

  @id:command-reading.functions-and-aliases.010 @rule:functions.resolve.recursion-stops @verified @source:scoville/scoring.py#_score_local_definition @test:tests/test_scoville.py#test_direct_recursion_terminates_and_still_scores_the_body @test:tests/test_scoville.py#test_mutual_recursion_terminates @test:tests/test_scoville.py#test_calling_the_same_helper_twice_scores_both_calls
  Scenario Outline: A recursive helper terminates while every separate call is still scored
    Given introspection is on
    When the operator scores `<script>`
    Then analysis finishes
    And <outcome>

    Examples:
      | script                                            | outcome                                     |
      | loop() { loop; rm -rf /tmp/x; }, then loop        | the call's factors still name rm -rf /tmp/x |
      | a() { b; }, b() { a; rm -rf /etc; }, then a       | the call is critical                        |
      | wipe() { rm -rf /var/lib/data; }, then wipe twice | both calls score the same, above zero       |

  @id:command-reading.functions-and-aliases.011 @rule:functions.resolve.input-only @verified @source:scoville/scoring.py#analyze @test:tests/test_scoville.py#test_nothing_outside_the_analysed_text_is_read
  Scenario: Definitions outside the scored input are never used
    Given the operator's ~/.bashrc defines `alias deploy='rm -rf /'`
    And introspection is on
    When the operator scores `deploy prod`
    Then it is an unknown command
    And the level is low
