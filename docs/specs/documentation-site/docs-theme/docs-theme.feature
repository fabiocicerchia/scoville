@domain:documentation-site @area:docs-theme @from:stylesheets/extra
Feature: Presenting the documentation in one self-contained brand theme
  Readers of the scoville docs and splash page get one consistent, branded look that loads without contacting any third-party server.

  Background:
    Given the scoville documentation site is published with its theme stylesheet

  @id:docs.documentation-site.docs-theme.001 @rule:docs.theme.no-network-assets @inferred @source:docs/stylesheets/extra.css#:root
  Scenario: The docs render without fetching fonts or assets from the network
    Given the reader's browser can reach only the docs host
    When the reader opens a documentation page
    Then body text is set in the operating system's sans-serif font
    And code is set in the operating system's monospace font
    And no font, stylesheet or script is requested from a CDN or third-party host

  @id:docs.documentation-site.docs-theme.002 @rule:docs.theme.shared-accent-palette @inferred @source:docs/stylesheets/extra.css#:root @questionable
  Scenario Outline: The splash page and the rendered docs share one accent palette
    Given the brand accent pair is orange #fb923c and red #ef4444
    When the reader views <surface>
    Then <element> uses the brand accent colours

    Examples:
      | surface                      | element                               |
      | the splash page              | the install label and plain links     |
      | the docs home hero           | the gradient title and primary button |
      | the docs in the light scheme | the links                             |

  @id:docs.documentation-site.docs-theme.003 @rule:docs.theme.dark-scheme-legibility @inferred @source:docs/stylesheets/extra.css#[data-md-color-scheme="slate"]
  Scenario: In the dark scheme links use the lighter accent on a deep navy ground
    Given the reader has chosen the dark colour scheme
    When the reader opens a documentation page
    Then the page, header and tabs background is deep navy #0b0f1a
    And links are shown in the orange accent #fb923c

  @id:docs.documentation-site.docs-theme.004 @rule:docs.theme.no-placeholder-logo @inferred @source:docs/stylesheets/extra.css#.md-header__button.md-logo
  Scenario: The docs header shows no stand-in logo while the project has none
    Given the project has not configured a logo
    When the reader opens a documentation page
    Then the header and navigation show no logo icon
    And the header shows the site title
