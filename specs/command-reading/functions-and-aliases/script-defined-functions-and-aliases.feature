@domain:command-reading @area:functions-and-aliases @from:scoville/definitions
Feature: Scoring calls to functions and aliases defined in the script
  Operators scoring a deploy script with --introspect need a call to a helper function or alias defined in that script to be scored as what it really runs, not as an opaque unknown command.

  Background:
    Given the operator scores a script with --introspect

  @id:command-reading.functions-and-aliases.001 @rule:command-reading.functions-and-aliases.function-call-scored-as-body @verified @source:scoville/definitions.py#collect_definitions @test:tests/test_scoville.py#test_a_function_call_is_scored_as_its_body
  Scenario: A call to a function defined in the script is scored as its body
    Given the script defines `deploy() { kubectl delete ns "$1"; kubectl apply -f manifests/; }` on line 2
    And the script later calls `deploy prod`
    When the operator scores the script
    Then the `deploy prod` command is rated high
    And its blast radius is cluster and it is irreversible
    And its factors say `deploy` is a function defined on line 2 of this input
    And its factors name `kubectl delete ns` as the command the function runs

  @id:command-reading.functions-and-aliases.002 @rule:command-reading.functions-and-aliases.alias-expanded-before-scoring @verified @source:scoville/definitions.py#collect_definitions @test:tests/test_scoville.py#test_an_alias_shadowing_a_binary_is_expanded
  Scenario: An alias defined in the script is scored as the command it expands to
    Given the script defines `alias k=kubectl`
    And the script later runs `k delete ns prod`
    When the operator scores the script
    Then the `k delete ns prod` command is rated critical
    And its first factor says resolved alias `k` is `kubectl` and that it was scored as `kubectl delete ns prod`

  @id:command-reading.functions-and-aliases.003 @rule:command-reading.functions-and-aliases.resolution-requires-introspect @verified @source:scoville/definitions.py#definition_at @test:tests/test_scoville.py#test_resolution_is_opt_in
  Scenario: Functions and aliases are only resolved when introspection is asked for
    Given the script defines `alias k=kubectl` and a `deploy` function that deletes a namespace
    And the script calls `deploy prod` and `k delete ns prod`
    And the operator does not pass --introspect
    When the operator scores the script
    Then `deploy prod` is rated low, as an unknown command
    And `k delete ns prod` is rated high, as an unknown CLI with a destructive verb

  @id:command-reading.functions-and-aliases.004 @rule:command-reading.functions-and-aliases.definition-in-scope-at-call @verified @source:scoville/definitions.py#definition_at @test:tests/test_scoville.py#test_a_function_defined_after_the_call_is_not_applied @test:tests/test_scoville.py#test_the_last_definition_before_the_call_wins @test:tests/test_scoville.py#test_a_name_is_resolved_at_the_call_site_not_the_definition
  Scenario Outline: Only the latest definition before a call applies to it
    Given the script contains <layout>
    When the operator scores the script
    Then the call is <outcome>

    Examples:
      | layout                                                                               | outcome                                                     |
      | `cleanup prod` on line 1, then `cleanup() { rm -rf /var/lib/data; }` on line 2       | scored as an unknown command and rated low                  |
      | `sync() { echo safe; }` on line 1, `sync() { rm -rf /; }` on line 2, then `sync now` | attributed to the definition on line 2 and rated critical   |
      | `a() { b; }`, then `b() { rm -rf /etc; }`, then `a`                                  | rated critical, because `b` is defined by the time `a` runs |

  @id:command-reading.functions-and-aliases.005 @rule:command-reading.functions-and-aliases.only-the-scored-text-is-read @verified @source:scoville/definitions.py#collect_definitions @test:tests/test_scoville.py#test_nothing_outside_the_analysed_text_is_read
  Scenario: Definitions outside the scored text are never used
    Given the operator's ~/.bashrc defines `alias deploy='rm -rf /'`
    And the script only contains `deploy prod`
    When the operator scores the script
    Then `deploy prod` is scored as an unknown command
    And it is rated low

  @id:command-reading.functions-and-aliases.006 @rule:command-reading.functions-and-aliases.function-body-read-whole @verified @source:scoville/definitions.py#_balanced_body @test:tests/test_scoville.py#test_an_unterminated_function_body_is_skipped_not_half_scored @test:tests/test_scoville.py#test_a_function_body_containing_braces_is_read_whole
  Scenario Outline: A function body is used only when it is read whole
    Given the script contains <definition> followed by a call
    When the operator scores the script
    Then the call is <outcome>

    Examples:
      | definition                                                      | outcome                                               |
      | `broken() { rm -rf /` with no closing brace, then `deploy prod` | scored as an unknown command                          |
      | `go() { rm -rf "${TARGET}"/data; }`, then `go`                  | scored above zero, with `rm -rf` named in its factors |
