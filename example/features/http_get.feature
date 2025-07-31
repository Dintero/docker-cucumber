Feature: HTTP GET
    Example illustrating use of docker-cucumber

Scenario: fetch urls
    Given a "<url>"
    When I request "GET"
    Then response status should be "<status>"

    Examples:
    | url                   | status      |
    | http://httpstatus/200 | OK          |
    | http://httpstatus/400 | BAD_REQUEST |
